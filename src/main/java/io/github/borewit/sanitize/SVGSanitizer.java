package io.github.borewit.sanitize;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventFactory;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.Namespace;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

/**
 * Utility class for sanitizing SVG content to remove potentially unsafe elements and attributes
 * that may lead to XSS vulnerabilities.
 *
 * <p>This class provides methods to sanitize SVG content from various inputs such as a {@code
 * String} or an {@code InputStream} and output the sanitized version. It utilizes the StAX
 * (Streaming API for XML) for efficient processing.
 *
 * <p>The sanitizer filters out unsafe XML event types, elements (e.g., {@code script}, {@code
 * foreignObject}, {@code iframe}, {@code embed}, {@code object}, {@code style}), and attributes
 * (e.g., {@code onclick}, {@code onload}, etc.) that could be used to inject malicious code.
 */
public class SVGSanitizer {

  private static final Set<Integer> UNSAFE_EVENT_TYPES =
      Set.of(XMLStreamConstants.DTD, XMLStreamConstants.ENTITY_REFERENCE);

  private static final Set<String> UNSAFE_ELEMENTS =
      Set.of("script", "foreignObject", "iframe", "embed", "object");

  private static final Set<String> UNSAFE_ATTRIBUTES =
      Set.of("onload", "onclick", "onmouseover", "onerror", "onfocus", "onblur", "onkeydown");

  /**
   * Sanitizes the given SVG content string by removing unsafe elements and attributes.
   *
   * @param svgContent the SVG content as a {@code String}
   * @return a sanitized version of the SVG content
   * @throws Exception if an error occurs during the sanitization process
   */
  public static String sanitize(String svgContent) throws Exception {
    try (final ByteArrayInputStream inputStream =
            new ByteArrayInputStream(svgContent.getBytes(StandardCharsets.UTF_8));
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
      sanitize(inputStream, outputStream);
      return outputStream.toString(StandardCharsets.UTF_8);
    }
  }

  /**
   * Sanitizes the SVG content provided by the given {@code InputStream} and returns an {@code
   * InputStream} with the sanitized output.
   *
   * <p><strong>Note:</strong> This implementation uses piped streams to achieve streaming behavior.
   *
   * @param is the input {@code InputStream} containing the SVG content
   * @return an {@code InputStream} from which the sanitized SVG content can be read
   * @throws Exception if an error occurs during the sanitization process
   */
  public static InputStream sanitize(InputStream is) throws Exception {
    final PipedOutputStream pos = new PipedOutputStream();
    final PipedInputStream pis = new PipedInputStream(pos);

    new Thread(
            () -> {
              try {
                sanitize(is, pos);
              } catch (Exception e) {
                throw new RuntimeException(e);
              } finally {
                try {
                  pos.close();
                } catch (IOException e) {
                  // Ignore
                }
              }
            })
        .start();

    // Return a wrapper stream that ensures that when the caller closes it,
    // the given input stream is closed (even if the background thread hasn't finished).
    return new FilterInputStream(pis) {
      @Override
      public void close() throws IOException {
        super.close(); // closes the underlying PipedInputStream
        try {
          is.close();
        } catch (IOException ex) {
          // Ignore
        }
      }
    };
  }

  /**
   * Sanitizes SVG content by reading from the provided {@code InputStream} and writing the
   * sanitized output to the provided {@code OutputStream}.
   *
   * <p>This method filters out unsafe XML event types, elements, and attributes to help prevent XSS
   * vulnerabilities.
   *
   * @param is the input {@code InputStream} containing the SVG content
   * @param os the output {@code OutputStream} to which the sanitized SVG content will be written
   * @throws Exception if an error occurs during XML processing or sanitization
   */
  public static void sanitize(InputStream is, OutputStream os) throws Exception {
    final XMLInputFactory factory = XMLInputFactory.newInstance();
    // Disable DTDs entirely for the factory
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    // Ignore unknown entities
    factory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false);

    final XMLOutputFactory outFactory = XMLOutputFactory.newInstance();
    final XMLEventFactory eventFactory = XMLEventFactory.newInstance();

    final XMLEventReader eventReader = factory.createXMLEventReader(is);
    try {
      final XMLEventWriter eventWriter = outFactory.createXMLEventWriter(os);
      try {
        while (eventReader.hasNext()) {
          final XMLEvent event = eventReader.nextEvent();
          if (UNSAFE_EVENT_TYPES.contains(event.getEventType())) {
            continue;
          }
          if (!event.isStartElement()) {
            // Write non-start elements as-is
            eventWriter.add(event);
          } else {
            // Handle start elements
            final StartElement startElement = event.asStartElement();
            final String localElementName = startElement.getName().getLocalPart().toLowerCase();
            if (UNSAFE_ELEMENTS.contains(localElementName)) {
              skipElementAndChildren(eventReader);
            } else if ("style".equals(localElementName)) {
              filterStyle(eventWriter, startElement, eventReader);
            } else {
              eventWriter.add(getElementWithSanitizedAttributes(startElement, eventFactory));
            }
          }
        }
      } finally {
        eventWriter.close();
      }
    } finally {
      eventReader.close();
    }
  }

  public static void filterStyle(
      XMLEventWriter eventWriter, StartElement startElement, XMLEventReader eventReader)
      throws XMLStreamException {
    final XMLEventFactory eventFactory = XMLEventFactory.newInstance();

    // Sanitize attributes and preserve namespace
    QName elementName = startElement.getName();
    Iterator<Attribute> sanitizedAttributes = sanitizeAttributes(startElement.getAttributes());
    Iterator<Namespace> namespaces = startElement.getNamespaces();

    // Write <style> start tag
    eventWriter.add(
        eventFactory.createStartElement(
            elementName.getPrefix(),
            elementName.getNamespaceURI(),
            elementName.getLocalPart(),
            sanitizedAttributes,
            namespaces));

    // Accumulate text inside <style> block
    StringBuilder styleContent = new StringBuilder();
    while (eventReader.hasNext()) {
      XMLEvent event = eventReader.nextEvent();
      if (event.isEndElement()
          && "style".equalsIgnoreCase(event.asEndElement().getName().getLocalPart())) {
        break;
      } else if (event.isCharacters()) {
        styleContent.append(event.asCharacters().getData());
      }
    }

    // Sanitize the CSS and write it
    String cleanedStyle = sanitizeCss(styleContent.toString());
    eventWriter.add(eventFactory.createCharacters(cleanedStyle));

    // Close </style> tag
    eventWriter.add(
        eventFactory.createEndElement(
            elementName.getPrefix(), elementName.getNamespaceURI(), elementName.getLocalPart()));
  }

  private static Iterator<Attribute> sanitizeAttributes(Iterator<Attribute> attributes) {
    List<Attribute> safeAttributes = new ArrayList<>();
    while (attributes.hasNext()) {
      Attribute attr = attributes.next();
      String name = attr.getName().getLocalPart().toLowerCase();
      if (!name.startsWith("on") && !"style".equals(name)) {
        safeAttributes.add(attr);
      }
    }
    return safeAttributes.iterator();
  }

  private static String sanitizeCss(String css) {
    // Decode encoded HTML entities like &lt;iframe&gt;
    String decoded = decodeHtmlEntities(css);

    // Now apply filtering to the decoded version
    // remove any remaining angle brackets

    return decoded
        .replaceAll("(?i)expression\\s*\\(", "")
        .replaceAll("(?i)javascript\\s*:", "")
        .replaceAll("(?i)url\\s*\\(\\s*['\"]?javascript:[^)]*\\)", "")
        .replaceAll("(?i)@import\\s+url\\([^)]*\\)", "")
        .replaceAll("(?i)srcdoc\\s*=", "")
        .replaceAll("(?i)<\\s*(script|iframe|textarea)[^>]*>", "")
        .replaceAll("<", "") // remove any remaining angle brackets
        .replaceAll(">", "");
  }

  /**
   * Decodes HTML entities like &lt;, &gt;, &amp;, &quot; into their respective characters.
   *
   * @param encoded The encoded string.
   * @return Decoded string.
   */
  public static String decodeHtmlEntities(String encoded) {
    return encoded
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#39;", "'")
        .replace("&#x2F;", "/");
  }

  /**
   * Skips the current element and all its child elements in the XML event stream.
   *
   * <p>This method is used to bypass unsafe elements and their contents.
   *
   * @param eventReader the {@code XMLEventReader} from which events are being read
   * @throws XMLStreamException if an error occurs while reading the XML events
   */
  private static void skipElementAndChildren(XMLEventReader eventReader) throws XMLStreamException {
    // Skip this element and all its children by tracking depth
    int depth = 1;
    while (eventReader.hasNext() && depth > 0) {
      final XMLEvent ignoredEvent = eventReader.nextEvent();
      if (ignoredEvent.isStartElement()) {
        depth++;
      } else if (ignoredEvent.isEndElement()) {
        depth--;
      }
    }
  }

  /**
   * Returns a sanitized version of the given start element by filtering out unsafe attributes.
   *
   * <p>Unsafe attributes include those that may contain event handlers (e.g., {@code onclick}) or
   * potentially dangerous values (e.g., JavaScript URLs). If any unsafe attribute is found, the
   * method creates a new start element without those attributes.
   *
   * @param startElement the original {@code StartElement} to sanitize
   * @param eventFactory the {@code XMLEventFactory} used to create new XML events
   * @return a {@code StartElement} with only safe attributes, or the original element if no unsafe
   *     attributes were found
   */
  private static StartElement getElementWithSanitizedAttributes(
      StartElement startElement, XMLEventFactory eventFactory) {
    final Iterator<Attribute> attributes = startElement.getAttributes();
    final List<Attribute> sanitizedAttributes = new ArrayList<>();
    boolean foundOffendingAttributes = false;
    while (attributes.hasNext()) {
      final Attribute attr = attributes.next();
      final String attrName = attr.getName().getLocalPart();
      final String attrValue = attr.getValue().toLowerCase();
      if (UNSAFE_ATTRIBUTES.contains(attrName)
          || attrValue.startsWith("javascript:")
          || ("href".equals(attrName)
              && !attrValue.startsWith("data:")
              && !attrValue.startsWith("#"))) {
        foundOffendingAttributes = true;
      } else {
        sanitizedAttributes.add(attr);
      }
    }
    return foundOffendingAttributes
        // Create a new StartElement without the unwanted attributes
        ? eventFactory.createStartElement(
            startElement.getName(), sanitizedAttributes.iterator(), startElement.getNamespaces())
        // Element was fine, return original
        : startElement;
  }
}
