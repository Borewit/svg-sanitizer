package io.github.borewit.sanitize;

import org.w3c.dom.*;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class SVGSanitizer {

  private final DocumentBuilderFactory factory;

  public SVGSanitizer() {
    try {
      this.factory = makeDocumentBuilderFactory();
    } catch (ParserConfigurationException e) {
      throw new RuntimeException("Failed to initialize DocumentBuilderFactory", e);
    }
  }

  private static DocumentBuilderFactory makeDocumentBuilderFactory() throws ParserConfigurationException {
    final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setValidating(false);
    factory.setNamespaceAware(true);
    factory.setFeature("http://xml.org/sax/features/namespaces", true);
    factory.setFeature("http://xml.org/sax/features/validation", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

    // Prevents exception: External Entity: Failed to read external document
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);

    // Do not include external parameter entities or the external DTD subset.
    // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
    // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

    // Disable external DTDs as well
    // Xerces 2 - https://xerces.apache.org/xerces2-j/features.html#nonvalidating.load-external-dtd
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setXIncludeAware(false);

    return factory;
  }

  private static final Set<String> UNSAFE_ELEMENTS = new HashSet<>(Arrays.asList(
    "script", "foreignObject", "iframe", "embed", "object", "xhtml:script", "style"
  ));

  private static final Set<String> UNSAFE_ATTRIBUTES = new HashSet<>(Arrays.asList(
    "onload", "onclick", "onmouseover", "onerror", "onfocus", "onblur", "onkeydown"
  ));

  public String sanitize(String svgContent) throws Exception {
    try (ByteArrayInputStream inputStream = new ByteArrayInputStream(svgContent.getBytes(StandardCharsets.UTF_8));
         ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
      this.sanitize(inputStream, outputStream);
      return outputStream.toString(StandardCharsets.UTF_8);
    }
  }

  public void sanitize(InputStream is, OutputStream os) throws Exception {
    final DocumentBuilder builder = this.factory.newDocumentBuilder();
    Document doc = builder.parse(is);

    removeUnsafeElements(doc);
    removeUnsafeAttributes(doc.getDocumentElement());

    final TransformerFactory transformerFactory = TransformerFactory.newInstance();
    transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    // Check OWASP recommendations XMLConstants.ACCESS_EXTERNAL_DTD & XMLConstants.ACCESS_EXTERNAL_STYLESHEET (are set with XMLConstants.FEATURE_SECURE_PROCESSING)
    // https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#transformerfactory
    assert ("".equals(transformerFactory.getAttribute(XMLConstants.ACCESS_EXTERNAL_DTD)));
    assert ("".equals(transformerFactory.getAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET)));

    final Transformer transformer = transformerFactory.newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");

    final DOMSource source = new DOMSource(doc);
    StreamResult result = new StreamResult(os);
    transformer.transform(source, result);
  }

  private static void removeUnsafeElements(Document doc) {
    for (String tag : UNSAFE_ELEMENTS) {
      final NodeList nodeList = doc.getElementsByTagName(tag);
      for (int i = nodeList.getLength() - 1; i >= 0; i--) {
        final Node node = nodeList.item(i);
        if (node.getParentNode() != null) {
          node.getParentNode().removeChild(node);
        }
      }
    }
  }

  private static void removeUnsafeAttributes(Element element) {
    final NamedNodeMap attributes = element.getAttributes();
    for (int i = attributes.getLength() - 1; i >= 0; i--) {
      final Node attr = attributes.item(i);
      String attrName = attr.getLocalName().toLowerCase();
      String attrValue = attr.getNodeValue().toLowerCase();

      if (UNSAFE_ATTRIBUTES.contains(attrName) || attrValue.startsWith("javascript:")) {
        element.removeAttribute(attr.getNodeName());
      }

      if ("href".equals(attrName) && !attrValue.startsWith("data:")) {
        element.removeAttribute(attr.getNodeName());
      }
    }

    NodeList children = element.getChildNodes();
    for (int i = 0; i < children.getLength(); i++) {
      final Node node = children.item(i);
      if (node instanceof Element) {
        removeUnsafeAttributes((Element) node);
      }
    }
  }
}
