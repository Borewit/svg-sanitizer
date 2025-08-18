package io.github.borewit.sanitize;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CssSanitizerTest {
  @Test
  void preservesSvgStylingAndFragments() {
    String result =
        CssSanitizer.sanitizeCss(
            ".shape{fill:url(#gradient);stroke:navy;stroke-width:4;opacity:.5;"
                + "font-family:'Example Font';transform:translate(2px,3px);color:rgb(1,2,3)}");
    assertTrue(result.contains("#gradient"));
    assertTrue(result.contains("stroke-width:4"));
    assertTrue(result.contains("Example Font"));
    assertTrue(result.contains("translate("));
    assertTrue(result.contains("rgb("));
    assertEquals(result, CssSanitizer.sanitizeCss(result));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "@import url('https://evil.test/attack');",
        "@namespace url('https://evil.test/attack');",
        "@font-face{font-family:attack;src:url('https://evil.test/attack')}",
        "@supports(display:block){.attack{fill:url('https://evil.test/attack')}}",
        "@keyframes attack{from{fill:url('https://evil.test/attack')}}",
        "@page{background:url('https://evil.test/attack')}",
        "@unknown attack{src:url('https://evil.test/attack')}",
        "@media screen{@font-face{font-family:attack;src:url('https://evil.test/attack')}}"
      })
  void removesUnsupportedRulesFromTheActualStylesheet(String attack) {
    String result = CssSanitizer.sanitizeCss(attack + ".safe{fill:red}");
    assertEquals(".safe{fill:red}", result.trim());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "fill:url(https://evil.test/attack)",
        "fill:url(//evil.test/attack)",
        "fill:url(/attack)",
        "fill:url(attack)",
        "fill:url('data:image/svg+xml,attack')",
        "fill:url('javascript:attack')",
        "fill:u\\72l('https://evil.test/attack')",
        "fill:url('\\68 ttps://evil.test/attack')",
        "fill:image-set('https://evil.test/attack' 1x)",
        "fill:image('https://evil.test/attack')",
        "fill:rgb(url('https://evil.test/attack'))",
        "fill:var(--attack)",
        "--attack:url(https://evil.test/attack)",
        "behavior:attack",
        "-moz-binding:attack",
        "width:expression(attack())",
        "width:e\\78pression(attack())",
        "custom-property:attack",
        "background:'<iframe>attack</iframe>'"
      })
  void removesUnsafeDeclarationsAndPreservesSafeOnes(String declaration) {
    String result = CssSanitizer.sanitizeCss(".safe{" + declaration + ";stroke:blue}");
    assertEquals(".safe{stroke:blue}", result.trim());
    assertEquals(
        "stroke:blue",
        CssSanitizer.sanitizeInlineStyle(declaration + ";stroke:blue").trim().replaceAll(";$", ""));
  }

  @Test
  void sanitizesNestedMediaRules() {
    String result =
        CssSanitizer.sanitizeCss(
            "@media screen{@media (min-width:1px){.safe{fill:red;stroke:url(https://evil.test/attack)}}}");
    assertTrue(result.contains("@media"));
    assertTrue(result.contains("fill:red"));
    assertFalse(result.contains("attack"));
    assertEquals("", CssSanitizer.sanitizeCss("@media screen{.a{behavior:attack}}"));
  }

  @Test
  void preservesWhitespaceAndCommentTokenBoundaries() {
    String result =
        CssSanitizer.sanitizeCss(
            ".safe{font-family:Example\nFont;stroke:red;/* ignored */fill:blue}");
    assertTrue(result.contains("Example Font"));
    assertTrue(result.contains("fill:blue"));
    assertFalse(result.contains("ignored"));
  }

  @Test
  void failsClosedBeforeParsingOversizedOrDeepInput() {
    assertEquals(
        "",
        CssSanitizer.sanitizeCss(
            "/*" + "x".repeat(CssSanitizer.MAX_CSS_LENGTH) + "*/.a{fill:red}"));
    assertEquals(
        "",
        CssSanitizer.sanitizeInlineStyle(
            "font-family:'" + "x".repeat(CssSanitizer.MAX_CSS_LENGTH) + "'"));
    assertEquals(
        "",
        CssSanitizer.sanitizeCss(
            "@media screen{".repeat(1000) + ".a{fill:red}" + "}".repeat(1000)));
    assertEquals("", CssSanitizer.sanitizeCss(".a{fill:rgb(".repeat(1000)));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "",
        " ",
        ".a{",
        ".a{fill:'unterminated}",
        ".a{fill:red\u0000}",
        "/* unclosed",
        "@\\69 mport url('https://evil.test/attack');.safe{fill:red}"
      })
  void rejectsInvalidInput(String css) {
    assertEquals("", CssSanitizer.sanitizeCss(css));
  }

  @Test
  void handlesNullInput() {
    assertEquals("", CssSanitizer.sanitizeCss(null));
    assertEquals("", CssSanitizer.sanitizeInlineStyle(null));
  }

  @Test
  void checksPresentationAttributes() {
    assertTrue(CssSanitizer.isSafePresentationAttribute("fill", "url(#gradient)"));
    assertFalse(CssSanitizer.isSafePresentationAttribute("fill", "url(https://evil.test/attack)"));
    assertFalse(CssSanitizer.isSafePresentationAttribute("fill", "red;stroke:blue"));
  }

  @Test
  void usesLocaleIndependentPropertyNames() {
    Locale original = Locale.getDefault();
    try {
      Locale.setDefault(Locale.forLanguageTag("tr-TR"));
      assertTrue(CssSanitizer.sanitizeCss(".a{FILL:red}").contains("red"));
    } finally {
      Locale.setDefault(original);
    }
  }
}
