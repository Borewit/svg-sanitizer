package io.github.borewit.sanitize;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import javax.xml.parsers.DocumentBuilderFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

class SVGCssSanitizerTest {
  private static final String SVG_START = "<svg xmlns='http://www.w3.org/2000/svg'>";

  private Document sanitize(String content) throws Exception {
    String output = SVGSanitizer.sanitize(SVG_START + content + "</svg>");
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    return factory
        .newDocumentBuilder()
        .parse(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void sanitizesInlineStylesAndPresentationAttributes() throws Exception {
    Document doc =
        sanitize(
            "<rect style='fill:url(https://evil.test/attack);stroke:blue;--x:red' "
                + "fill='url(https://evil.test/attack)' stroke='url(#gradient)'/>");
    Element rect = (Element) doc.getElementsByTagName("rect").item(0);
    assertEquals("stroke:blue", rect.getAttribute("style"));
    assertFalse(rect.hasAttribute("fill"));
    assertEquals("url(#gradient)", rect.getAttribute("stroke"));
  }

  @Test
  void preservesLocalPaintReferencesAndOrdinaryStyles() throws Exception {
    Document doc =
        sanitize(
            "<defs><linearGradient id='gradient'/></defs>"
                + "<style>.a{fill:url(#gradient);stroke:navy;stroke-width:4}</style>"
                + "<rect class='a' width='10' height='10' style='opacity:.5'/>");
    assertEquals(1, doc.getElementsByTagName("linearGradient").getLength());
    assertTrue(doc.getElementsByTagName("style").item(0).getTextContent().contains("#gradient"));
    assertEquals("10", ((Element) doc.getElementsByTagName("rect").item(0)).getAttribute("width"));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "@import url(https://evil.test/attack);.a{fill:red}",
        "@font-face{font-family:attack;src:url(https://evil.test/attack)}.a{fill:red}",
        "@media screen{.a{fill:url(https://evil.test/attack);stroke:blue}}",
        ".a{fill:image-set('https://evil.test/attack' 1x);stroke:blue}",
        ".a{background:'</style><script>attack</script>';stroke:blue}"
      })
  void checksDecodedStylesheetText(String css) throws Exception {
    Document doc = sanitize("<style><![CDATA[" + css + "]]></style><rect/>");
    assertFalse(doc.getDocumentElement().getTextContent().contains("attack"));
    assertEquals(1, doc.getElementsByTagName("rect").getLength());
  }

  @Test
  void checksStyleElementAttributes() throws Exception {
    Document doc =
        sanitize(
            "<style onload='attack()' unknown='attack' "
                + "style='fill:url(https://evil.test/attack)'>.a{fill:red}</style>");
    Element style = (Element) doc.getElementsByTagName("style").item(0);
    assertFalse(style.hasAttribute("onload"));
    assertFalse(style.hasAttribute("unknown"));
    assertFalse(style.hasAttribute("style"));
  }

  @Test
  void consumesMalformedNestedStyleWithoutSwallowingFollowingElements() throws Exception {
    Document doc =
        sanitize(
            "<style>.a{fill:red}<style>.b{fill:blue}</style><script>attack()</script></style><rect/>");
    assertEquals(0, doc.getElementsByTagName("style").getLength());
    assertEquals(0, doc.getElementsByTagName("script").getLength());
    assertEquals(1, doc.getElementsByTagName("rect").getLength());
  }

  @Test
  void dropsOversizedStyleAndPreservesFollowingElements() throws Exception {
    Document doc =
        sanitize(
            "<style>/*"
                + "x".repeat(CssSanitizer.MAX_CSS_LENGTH)
                + "*/.a{fill:red}</style><rect/>");
    assertEquals(0, doc.getElementsByTagName("style").getLength());
    assertEquals(1, doc.getElementsByTagName("rect").getLength());
  }

  @Test
  void sanitizesXmlDecodedCssUrls() throws Exception {
    Document doc =
        sanitize(
            "<style>.a{fill:url(&#x68;ttps://evil.test/attack);stroke:blue}</style>"
                + "<rect style='fill:url(&#x68;ttps://evil.test/attack);stroke:blue'/>");
    assertEquals(
        ".a{stroke:blue}", doc.getElementsByTagName("style").item(0).getTextContent().trim());
    assertEquals(
        "stroke:blue", ((Element) doc.getElementsByTagName("rect").item(0)).getAttribute("style"));
  }
}
