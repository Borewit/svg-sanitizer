package io.github.borewit.sanitize;

import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class SVGSanitizer {

    private static final Set<String> UNSAFE_ELEMENTS = new HashSet<>(Arrays.asList(
            "script", "foreignObject", "iframe", "embed", "object", "xhtml:script", "style"
    ));

    private static final Set<String> UNSAFE_ATTRIBUTES = new HashSet<>(Arrays.asList(
            "onload", "onclick", "onmouseover", "onerror", "onfocus", "onblur", "onkeydown"
    ));

    public static String sanitize(String svgContent) throws Exception {
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(svgContent.getBytes(StandardCharsets.UTF_8));
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            sanitize(inputStream, outputStream);
            return outputStream.toString(StandardCharsets.UTF_8);
        }
    }

    public static void sanitize(InputStream is, OutputStream os) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setValidating(false);
        factory.setNamespaceAware(true);
        factory.setFeature("http://xml.org/sax/features/namespaces", false);
        factory.setFeature("http://xml.org/sax/features/validation", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);

        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(is);

        removeUnsafeElements(doc);
        removeUnsafeAttributes(doc.getDocumentElement());

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");

        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(os);
        transformer.transform(source, result);
    }

    private static void removeUnsafeElements(Document doc) {
        for (String tag : UNSAFE_ELEMENTS) {
            NodeList nodeList = doc.getElementsByTagName(tag);
            for (int i = nodeList.getLength() - 1; i >= 0; i--) {
                Node node = nodeList.item(i);
                if (node.getParentNode() != null) {
                    node.getParentNode().removeChild(node);
                }
            }
        }
    }

    private static void removeUnsafeAttributes(Element element) {
        NamedNodeMap attributes = element.getAttributes();
        for (int i = attributes.getLength() - 1; i >= 0; i--) {
            Node attr = attributes.item(i);
            String attrName = attr.getNodeName().toLowerCase();
            String attrValue = attr.getNodeValue().toLowerCase();

            if (UNSAFE_ATTRIBUTES.contains(attrName) || attrValue.startsWith("javascript:")) {
                element.removeAttribute(attr.getNodeName());
            }

            if (("href".equals(attrName) || "xlink:href".equals(attrName)) && !attrValue.startsWith("data:")) {
                element.removeAttribute(attr.getNodeName());
            }
        }

        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (node instanceof Element) {
                removeUnsafeAttributes((Element) node);
            }
        }
    }
}
