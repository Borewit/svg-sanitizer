package io.github.borewit.sanitize;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.xml.stream.XMLEventFactory;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

public class SVGSanitizer {

  private static final Set<Integer> UNSAFE_EVENT_TYPES =
      Set.of(XMLStreamConstants.DTD, XMLStreamConstants.ENTITY_REFERENCE);

  private static final Set<String> UNSAFE_ELEMENTS =
      Set.of("script", "foreignObject", "iframe", "embed", "object", "style");

  private static final Set<String> UNSAFE_ATTRIBUTES =
      Set.of("onload", "onclick", "onmouseover", "onerror", "onfocus", "onblur", "onkeydown");

  public String sanitize(String svgContent) throws Exception {
    try (final ByteArrayInputStream inputStream =
            new ByteArrayInputStream(svgContent.getBytes(StandardCharsets.UTF_8));
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
      sanitize(inputStream, outputStream);
      return outputStream.toString(StandardCharsets.UTF_8);
    }
  }

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
            if (UNSAFE_ELEMENTS.contains(startElement.getName().getLocalPart())) {
              skipElementAndChildren(eventReader);
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
          || ("href".equals(attrName) && !attrValue.startsWith("data:"))) {
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
