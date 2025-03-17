package io.github.borewit.sanitize.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class CheckSvg {

  private static final Pattern JAVASCRIPT_URI_PATTERN = Pattern.compile("(?i)^\\s*javascript:.*");

  /**
   * Detects whether an SVG string contains potential JavaScript execution risks.
   *
   * @param svgContent The SVG content to scan.
   * @return true if JavaScript is found, false otherwise.
   * @throws XMLStreamException if an error occurs while parsing.
   */
  public static boolean containsJavaScript(String svgContent)
      throws XMLStreamException, IOException {
    XMLInputFactory factory = XMLInputFactory.newFactory();
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false); // Prevent DTD processing
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);

    try (ByteArrayInputStream inputStream =
        new ByteArrayInputStream(svgContent.getBytes(StandardCharsets.UTF_8))) {
      XMLEventReader reader = factory.createXMLEventReader(inputStream);

      while (reader.hasNext()) {
        XMLEvent event = reader.nextEvent();

        if (event.getEventType() == XMLStreamConstants.START_ELEMENT) {
          StartElement startElement = event.asStartElement();
          String elementName = startElement.getName().getLocalPart().toLowerCase();

          // Detect <script> tag in any namespace (e.g., <xhtml:script>)
          if ("script".equals(elementName)) {
            return true;
          }

          // Check for "on*" event handlers (onclick, onload, etc.)
          Iterator<Attribute> attributes = startElement.getAttributes();
          while (attributes.hasNext()) {
            Attribute attr = attributes.next();
            String attrName = attr.getName().getLocalPart().toLowerCase();
            String attrValue = attr.getValue().trim().toLowerCase();

            if (attrName.startsWith("on")) {
              return true; // Found an event handler like onload, onclick
            }

            // Detect javascript: URIs
            if (JAVASCRIPT_URI_PATTERN.matcher(attrValue).matches()) {
              return true;
            }
          }

          // Detect JavaScript inside <foreignObject>
          if ("foreignObject".equals(elementName) && containsJavaScriptInForeignObject(reader)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  /**
   * Detects JavaScript execution risks inside <style> elements, including CDATA content.
   *
   * @param svgContent The SVG content to scan.
   * @return true if JavaScript-like content is found inside <style>, false otherwise.
   * @throws XMLStreamException if an error occurs while parsing.
   */
  public static boolean containsJavaScriptInStyle(String svgContent)
      throws XMLStreamException, IOException {
    XMLInputFactory factory = XMLInputFactory.newFactory();
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);

    try (ByteArrayInputStream inputStream =
        new ByteArrayInputStream(svgContent.getBytes(StandardCharsets.UTF_8))) {
      XMLEventReader reader = factory.createXMLEventReader(inputStream);

      while (reader.hasNext()) {
        XMLEvent event = reader.nextEvent();

        if (event.getEventType() == XMLStreamConstants.START_ELEMENT) {
          StartElement startElement = event.asStartElement();
          String elementName = startElement.getName().getLocalPart().toLowerCase();

          if ("style".equals(elementName)) {
            StringBuilder styleContent = new StringBuilder();

            while (reader.hasNext()) {
              XMLEvent nextEvent = reader.nextEvent();

              if (nextEvent.getEventType() == XMLStreamConstants.CHARACTERS) {
                styleContent.append(nextEvent.asCharacters().getData());
              } else if (nextEvent.getEventType() == XMLStreamConstants.END_ELEMENT
                  && "style".equalsIgnoreCase(nextEvent.asEndElement().getName().getLocalPart())) {
                break; // End of <style> element
              }
            }

            String styleText = styleContent.toString();
            styleText = decodeHtmlEntities(styleText).toLowerCase();

            // Check for suspicious JavaScript-like content inside <style>
            if (containsJavaScriptPayload(styleText)) {
              return true;
            }
          }
        }
      }
    }

    return false;
  }

  /**
   * Decodes HTML entities like &lt;, &gt;, &amp;, &quot; into their respective characters.
   *
   * @param encoded The encoded string.
   * @return Decoded string.
   */
  private static String decodeHtmlEntities(String encoded) {
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
   * Checks if a given string contains JavaScript execution vectors inside CSS.
   *
   * @param styleText CSS content extracted from <style> elements.
   * @return true if JavaScript execution vectors are found.
   */
  private static boolean containsJavaScriptPayload(String styleText) {
    // Patterns to detect JavaScript injection in CSS properties
    Pattern jsPatterns =
        Pattern.compile(
            "(<script.*?>|</script>|expression\\(|behavior:|javascript:|iframe|textarea)",
            Pattern.CASE_INSENSITIVE);

    Matcher matcher = jsPatterns.matcher(styleText);
    return matcher.find();
  }

  /**
   * Checks for JavaScript execution inside a <foreignObject> element. Looks for <script> or
   * event-handler attributes in foreignObject's XHTML content.
   *
   * @param reader XML Event Reader at a <foreignObject> start element.
   * @return true if JavaScript is found inside foreignObject.
   * @throws XMLStreamException If XML parsing fails.
   */
  private static boolean containsJavaScriptInForeignObject(XMLEventReader reader)
      throws XMLStreamException {
    int depth = 1;

    while (reader.hasNext() && depth > 0) {
      XMLEvent event = reader.nextEvent();

      if (event.isStartElement()) {
        StartElement startElement = event.asStartElement();
        String elementName = startElement.getName().getLocalPart().toLowerCase();

        // Check for <script> inside foreignObject
        if ("script".equals(elementName)) {
          return true;
        }

        // Check for event-handler attributes inside foreignObject XHTML content
        Iterator<Attribute> attributes = startElement.getAttributes();
        while (attributes.hasNext()) {
          Attribute attr = attributes.next();
          String attrName = attr.getName().getLocalPart().toLowerCase();
          if (attrName.startsWith("on")) {
            return true;
          }
        }
        depth++;
      } else if (event.isEndElement()) {
        depth--;
      }
    }
    return false;
  }

  /**
   * Detects if the given SVG string is trying to load external resources. It returns true if: - The
   * SVG contains a DOCTYPE declaration with external entity references (SYSTEM or PUBLIC). - An
   * <image>, <use>, <object>, or <iframe> element has an "href" attribute whose value does not
   * begin with "data:". - A <foreignObject> contains a <script> or an external <object>.
   *
   * @param svgXml The SVG content as a string.
   * @return true if external resource loading is detected, false otherwise.
   * @throws ParserConfigurationException
   * @throws IOException
   * @throws SAXException
   */
  public static boolean containsExternalResources(String svgXml)
      throws ParserConfigurationException, IOException, SAXException {

    // 1. Quick text-based check for DOCTYPE with external entity references.
    if (svgXml.contains("<!DOCTYPE")
        && (svgXml.contains(" SYSTEM ") || svgXml.contains(" PUBLIC "))) {
      return true;
    }

    // 2. Secure XML parsing setup
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    // Prevent external DTDs/entities from being loaded:
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setXIncludeAware(false);

    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(new ByteArrayInputStream(svgXml.getBytes(StandardCharsets.UTF_8)));

    // 3. Detect external resources in <image>, <use>, <a>, <object>, and <iframe>
    if (hasExternalReferences(doc, "image", "href")
        || hasExternalReferences(doc, "use", "href")
        || hasExternalReferences(doc, "a", "href")
        || hasExternalReferences(doc, "object", "data")
        || hasExternalReferences(doc, "iframe", "src")) {
      return true;
    }

    // 4. Detect external references in <foreignObject>
    if (containsExternalForeignObject(doc)) {
      return true;
    }

    return false;
  }

  /**
   * Checks if the given tag name contains an external reference in any of its specified attributes.
   *
   * @param doc The parsed XML document.
   * @param tagName The tag name to check (e.g., "image", "use").
   * @param attributeKeys The attribute names to check (e.g., "href", "…").
   * @return true if an external resource is found, false otherwise.
   */
  private static boolean hasExternalReferences(
      Document doc, String tagName, String... attributeKeys) {
    NodeList elements = doc.getElementsByTagName(tagName);
    for (int i = 0; i < elements.getLength(); i++) {
      Element element = (Element) elements.item(i);
      for (String attrKey : attributeKeys) {
        String attrValue = element.getAttribute(attrKey);
        if (attrValue.isEmpty()) {
          attrValue = element.getAttributeNS("http://www.w3.org/1999/xlink", attrKey);
        }
        if (isExternalResource(attrValue)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Detects if a <foreignObject> contains external resources, such as embedded <script> tags or
   * <object> elements.
   *
   * @param doc The parsed XML document.
   * @return true if a <foreignObject> has a reference to an external resource.
   */
  private static boolean containsExternalForeignObject(Document doc) {
    NodeList foreignObjects = doc.getElementsByTagName("foreignObject");
    for (int i = 0; i < foreignObjects.getLength(); i++) {
      Element foreignObject = (Element) foreignObjects.item(i);

      // Check for embedded JavaScript
      NodeList scriptNodes = foreignObject.getElementsByTagNameNS("*", "script");
      if (scriptNodes.getLength() > 0) {
        return true; // JavaScript inside foreignObject detected
      }

      // Check for external <object> references inside foreignObject
      NodeList objectNodes = foreignObject.getElementsByTagNameNS("*", "object");
      for (int j = 0; j < objectNodes.getLength(); j++) {
        Element objectElement = (Element) objectNodes.item(j);
        String dataAttr = objectElement.getAttribute("data");
        if (isExternalResource(dataAttr)) {
          return true; // External object reference detected
        }
      }
    }
    return false;
  }

  /**
   * Determines if a given URL is an external resource.
   *
   * @param url The URL string to check.
   * @return true if it's an external resource, false if it's inline (e.g., data:).
   */
  private static boolean isExternalResource(String url) {
    if (url == null || url.trim().isEmpty()) {
      return false;
    }
    url = url.trim().toLowerCase();
    return !(url.startsWith("data:") || url.startsWith("#")); // Allow data URIs and fragment IDs
  }

  /**
   * Detects whether an SVG string contains entity definitions.
   *
   * @param svgContent The SVG content to scan.
   * @return true if entity definitions are found, false otherwise.
   */
  public static boolean containsExternalEntities(String svgContent) {
    // Quick text-based check for DOCTYPE.
    return svgContent.contains("<!DOCTYPE");
  }
}
