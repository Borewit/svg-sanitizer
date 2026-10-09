package io.github.borewit.sanitize;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.borewit.sanitize.util.CheckSvg;
import io.github.borewit.sanitize.util.DigestException;
import io.github.borewit.sanitize.util.HashLoader;
import io.github.borewit.sanitize.util.SvgHash;
import io.github.borewit.sanitize.util.XmlHash;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SVGSanitizerTest {

  private static final String RESOURCE_SVG_PATH = "/";
  private static final Path PATH_BUILD = Paths.get(".", "build");
  private static final Path PATH_BUILD_SANITIZED = PATH_BUILD.resolve("sanitized");

  // Map of expected hashes keyed by filename
  private Map<String, String> EXPECTED_HASHES;

  @BeforeEach
  void setup() throws Exception {

    // Use the Java build in XML factory (xmlsec introduces other libraries)
    System.setProperty(
        "javax.xml.stream.XMLInputFactory", "com.sun.xml.internal.stream.XMLInputFactoryImpl");

    XmlHash.init(); // Needs to be called once, before using digest

    // Ensure the target directory exists
    Files.createDirectories(PATH_BUILD_SANITIZED); // ✅ Ensure target/ exists

    // Copy test SVG from resources to a temporary location
    try (InputStream inputStream = getClass().getResourceAsStream(RESOURCE_SVG_PATH)) {
      assertNotNull(inputStream, "Test SVG file should exist in resources");
    }

    EXPECTED_HASHES = HashLoader.loadExpectedHashes();
  }

  @Test
  @DisplayName("Generate JSON Hash-map")
  void generateJsonHashMap() throws Exception {
    // List of test files
    Set<String> testFiles =
        Set.of(
            "attacker-controlled.svg",
            "billionlaughs.svg",
            "circle.svg",
            "circleBlink.svg",
            "circleBlinkJS.svg",
            "circleWithS.svg",
            "eicar.svg",
            "externalimage.svg",
            "externalimage2.svg",
            "friendly.svg",
            "Flag_of_the_United_States.svg",
            "form-action.svg",
            "form-action2.svg",
            "form-action2-case.svg",
            "form-action3.svg",
            "form-action-case.svg",
            "javascriptalert.svg",
            "image-href.svg",
            "ontouchstart.svg",
            "recursive-foreignobject.svg",
            "S.svg",
            "style.svg",
            "style-empty.svg",
            "style-external-resource.svg",
            "svg.svg",
            "SVG-alert.svg",
            "SVG-alert-eicar.svg",
            "SVG-alertv2(1).svg",
            "SVG-alertv2.svg",
            "test(1).svg",
            "test(2).svg",
            "test(3).svg",
            "test(4).svg",
            "test.svg",
            "test2(1).svg",
            "test2.svg",
            "test-href-javascript.svg",
            "test-href-javascript2.svg",
            "test-href-javascript3.svg");

    // Create a map with sanitized SVG XML hashes
    Map<String, String> svgXmlHashMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    for (String svgTestFile : testFiles) {
      String dirtySvg = this.getFixtureAsString(svgTestFile);
      String sanitizedSvg;
      try {
        sanitizedSvg = SVGSanitizer.sanitize(dirtySvg);
      } catch (Exception e) {
        throw new Exception("Failed to sanitize " + svgTestFile, e);
      }
      try {
        svgXmlHashMap.put(svgTestFile, XmlHash.digest(sanitizedSvg));
      } catch (Exception e) {
        fail("Failed to calculate digest for " + svgTestFile, e);
      }
    }

    // Write JSON to file
    ObjectMapper mapper = new ObjectMapper();
    String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(svgXmlHashMap);
    json += "\n"; // Add empty line for Git
    Files.write(PATH_BUILD.resolve("svg-xml-hash-map.json"), json.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  @DisplayName("Regression for visual changes in SVG output")
  void svgRegression() throws Exception {

    final String svgTestFile = "friendly.svg";
    // Convert output to string for verification
    final String dirtySvg = this.getFixtureAsString(svgTestFile);
    // The rendering maybe different on different systems, hence the hash
    final String dirtyVisualHash = SvgHash.digest(dirtySvg);
    final String sanitizedSvg = SVGSanitizer.sanitize(dirtySvg);
    final String sanitizedVisualHash = SvgHash.digest(sanitizedSvg);
    assertEquals(dirtyVisualHash, sanitizedVisualHash, "Visual hash sanitized SVG file");

    // Save sanitized SVG for debugging
    saveSvg(sanitizedSvg, svgTestFile);
  }

  @ParameterizedTest
  @DisplayName("Sanitize JavaScript code in SVG")
  @ValueSource(
      strings = {
        "attacker-controlled.svg",
        "circleBlinkJS.svg",
        "eicar.svg",
        "form-action.svg",
        "form-action-case.svg",
        "form-action3.svg",
        "javascriptalert.svg",
        "svg.svg",
        "SVG-alert.svg",
        "SVG-alert-eicar.svg",
        "SVG-alertv2(1).svg",
        "SVG-alertv2.svg",
        "recursive-foreignobject.svg",
        "test(1).svg",
        "test.svg",
        "test2(1).svg",
        "test2.svg"
      })
  void sanitizeJavaScriptInSVG(String svgTestFile) throws Exception {
    // Convert output to string for verification
    String dirtySvg = this.getFixtureAsString(svgTestFile);
    assertTrue(
        CheckSvg.containsJavaScript(dirtySvg),
        String.format("Dirty \"%s\" should contain JavaScript", svgTestFile));

    String sanitizedSvg = SVGSanitizer.sanitize(dirtySvg);

    // Save sanitized SVG for debugging
    saveSvg(sanitizedSvg, svgTestFile);

    assertFalse(
        CheckSvg.containsJavaScript(sanitizedSvg),
        String.format("Sanitized \"%s\" contain not contain JavaScript", svgTestFile));
  }

  @ParameterizedTest
  @DisplayName("Sanitize JavaScript embedded in style")
  @ValueSource(strings = {"form-action2.svg", "form-action2-case.svg"})
  void sanitizeJavaScriptInStyle(String svgTestFile) throws Exception {
    // Convert output to string for verification
    String dirtySvg = this.getFixtureAsString(svgTestFile);
    assertTrue(
        CheckSvg.containsJavaScriptInStyle(dirtySvg),
        String.format("Dirty \"%s\" should contain JavaScript", svgTestFile));

    String sanitizedSvg = SVGSanitizer.sanitize(dirtySvg);

    // Save sanitized SVG for debugging
    saveSvg(sanitizedSvg, svgTestFile);
  }

  @ParameterizedTest
  @DisplayName("Sanitize external resources")
  @ValueSource(
      strings = {
        "circleWithS.svg",
        "externalimage.svg",
        "externalimage2.svg",
        "recursive-foreignobject.svg",
        "test(2).svg",
        "test(3).svg",
        "test(4).svg",
        "test-href-javascript.svg",
        "test-href-javascript2.svg",
        "test-href-javascript3.svg"
      })
  void sanitizeExternalResources(String svgTestFile) throws Exception {
    // Convert output to string for verification
    String dirtySvg = this.getFixtureAsString(svgTestFile);
    assertTrue(
        CheckSvg.containsExternalResources(dirtySvg),
        String.format("Dirty \"%s\" should contain an external resource", svgTestFile));

    String sanitizedSvg = SVGSanitizer.sanitize(dirtySvg);

    // Save sanitized SVG for debugging
    saveSvg(sanitizedSvg, svgTestFile);
  }

  /** Verifies that local references retain their XLink namespace for SVG 1.1 renderers. */
  @Test
  @DisplayName("Preserve XLink local references")
  void preserveLocalAnchorXLinkHref() throws Exception {
    String svgTestFile = "Flag_of_the_United_States.svg";
    // Convert output to string for verification
    String dirtySvg = this.getFixtureAsString(svgTestFile);
    assertTrue(
        CheckSvg.hasInternalReferences(dirtySvg),
        String.format("Dirty \"%s\" should contain internal references", svgTestFile));

    String sanitizedSvg = SVGSanitizer.sanitize(dirtySvg);

    assertTrue(
        sanitizedSvg.contains("<use xlink:href=\"#s\" y=\"420\"/>"),
        "should preserve local references");

    // Save sanitized SVG for debugging
    saveSvg(sanitizedSvg, svgTestFile);
  }

  /**
   * Verifies that sanitizing an entity-expansion fixture removes its entity definitions.
   *
   * @param svgTestFile fixture containing entity declarations
   */
  @ParameterizedTest
  @DisplayName("Sanitize entity references")
  @ValueSource(strings = {"billionlaughs.svg"})
  void sanitizeSvgExploits(String svgTestFile) throws Exception {
    // Convert output to string for verification
    String dirtySvg = this.getFixtureAsString(svgTestFile);
    assertTrue(
        CheckSvg.containsExternalEntities(dirtySvg),
        String.format("Dirty \"%s\" should contain entity definitions", svgTestFile));

    String sanitizedSvg = SVGSanitizer.sanitize(dirtySvg);

    // Save sanitized SVG for debugging
    saveSvg(sanitizedSvg, svgTestFile);

    assertFalse(
        CheckSvg.containsExternalEntities(sanitizedSvg),
        String.format("Sanitized \"%s\" should not contain entity definitions", svgTestFile));
    assertTrue(
        dirtySvg.length() > sanitizedSvg.length(),
        String.format("Sanitized \"%s\" should be smaller than original", svgTestFile));
  }

  private InputStream getFixture(String fixtureName) {
    return getClass().getResourceAsStream(RESOURCE_SVG_PATH + fixtureName);
  }

  private String getFixtureAsString(String fixtureName) throws IOException {
    try (InputStream inputStream = this.getFixture(fixtureName)) {
      return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  @ParameterizedTest
  @DisplayName("Sanitize from InputStream to InputStream")
  @ValueSource(
      strings = {
        "form-action3.svg",
        "javascriptalert.svg",
        "svg.svg",
        "SVG-alert.svg",
        "SVG-alert-eicar.svg",
        "SVG-alertv2(1).svg",
        "SVG-alertv2.svg",
        "recursive-foreignobject.svg",
        "test(1).svg",
        "test.svg",
        "test2(1).svg",
        "test2.svg",
        "circleWithS.svg",
        "externalimage.svg",
        "externalimage2.svg",
        "recursive-foreignobject.svg",
        "test(2).svg",
        "test(3).svg",
        "test(4).svg",
        "test-href-javascript.svg",
        "test-href-javascript2.svg",
        "test-href-javascript3.svg"
      })
  void sanitizeToInputStream(String svgTestFile) throws Exception {
    String sanitizedSvg;
    try (InputStream inputStream = SVGSanitizer.sanitize(this.getFixture(svgTestFile))) {
      ByteArrayOutputStream result = new ByteArrayOutputStream();
      byte[] buffer = new byte[1024];
      for (int length; (length = inputStream.read(buffer)) != -1; ) {
        result.write(buffer, 0, length);
      }
      // StandardCharsets.UTF_8.name() > JDK 7
      sanitizedSvg = result.toString(StandardCharsets.UTF_8);
      assertHash(sanitizedSvg, svgTestFile);
    }
    assertFalse(
        CheckSvg.containsExternalEntities(sanitizedSvg),
        String.format("Sanitized \"%s\" should not contain entity definitions", svgTestFile));
  }

  /** Regression test, to alert for any changes in the output */
  private void assertHash(String sanitizedSvg, String svgTestFile) throws DigestException {
    final String actualHash = XmlHash.digest(sanitizedSvg);
    assertTrue(
        EXPECTED_HASHES.containsKey(svgTestFile),
        String.format("Missing hash for \"%s\": \"%s\"", svgTestFile, actualHash));
    assertEquals(
        EXPECTED_HASHES.get(svgTestFile),
        actualHash,
        String.format("Hash mismatch for \"%s\"", svgTestFile));
  }

  /** Saves the sanitized SVG file to `build/sanitized/` for debugging. */
  private void saveSvg(String sanitizedSvg, String testFileName)
      throws IOException, DigestException {
    Files.createDirectories(PATH_BUILD_SANITIZED); // Ensure directory exists
    String sanitizedFilename = testFileName.replace(".svg", "-sanitized.svg");

    Path outputPath = PATH_BUILD_SANITIZED.resolve(sanitizedFilename);
    Files.writeString(outputPath, sanitizedSvg);
    assertHash(sanitizedSvg, testFileName);
  }

  @Test
  @DisplayName("Preserve style element")
  void preserveStyleElement() throws Exception {
    String svgTestFile = "style.svg";

    // Convert output to string for verification
    String dirtySvg = this.getFixtureAsString(svgTestFile);

    assertTrue(
        CheckSvg.containsStyleElement(dirtySvg),
        String.format("Test SVG \"%s\" contain a style element", svgTestFile));

    String sanitizedSvg = SVGSanitizer.sanitize(dirtySvg);

    // Save sanitized SVG for debugging
    saveSvg(sanitizedSvg, svgTestFile);

    assertTrue(
        CheckSvg.containsStyleElement(sanitizedSvg),
        String.format("Sanitized SVG \"%s\" contain a style element", svgTestFile));
  }

  @Test
  @DisplayName("Sanitize style element")
  void sanitizeStyleElement() throws Exception {
    String svgTestFile = "style-external-resource.svg";

    // Convert output to string for verification
    String dirtySvg = this.getFixtureAsString(svgTestFile);

    assertTrue(
        CheckSvg.containsStyleElement(dirtySvg),
        String.format("Test SVG \"%s\" contain a style element", svgTestFile));

    String sanitizedSvg = SVGSanitizer.sanitize(dirtySvg);

    // Save sanitized SVG for debugging
    saveSvg(sanitizedSvg, svgTestFile);

    assertTrue(
        CheckSvg.containsStyleElement(sanitizedSvg),
        String.format("Sanitized SVG \"%s\" contains a style element", svgTestFile));

    assertFalse(sanitizedSvg.contains("evil.css"), "Should not contain any external URLs");
  }

  /** Verifies that sanitizing removes JavaScript touch event handlers. */
  @Test
  @DisplayName("Sanitize ontouchstart")
  void clearOnTouchStart() throws Exception {
    String svgTestFile = "ontouchstart.svg";

    // Convert output to string for verification
    String dirtySvg = this.getFixtureAsString(svgTestFile);

    assertTrue(
        CheckSvg.containsJavaScript(dirtySvg),
        String.format("Dirty SVG \"%s\" should contains ontouchstart attribute", svgTestFile));

    // Convert output to string for verification
    String sanitizedSvg = SVGSanitizer.sanitize(dirtySvg);

    assertFalse(
        CheckSvg.containsJavaScript(sanitizedSvg),
        String.format(
            "Sanitized SVG \"%s\" should not contain ontouchstart attribute", svgTestFile));

    // Save sanitized SVG for debugging
    saveSvg(sanitizedSvg, svgTestFile);
  }

  /**
   * Verifies that preserving an embedded image and its XLink references preserves rendered pixels.
   */
  @Test
  @DisplayName("Preserve an embedded PNG referenced through a pattern")
  void preserveEmbeddedImageInPattern() throws Exception {
    String original = getFixtureAsString("embedded-image-pattern.svg");
    String sanitized = SVGSanitizer.sanitize(original);

    String originalVisualHash = SvgHash.digest(original);
    assertNotEquals(
        originalVisualHash,
        SvgHash.digest(original.replace("<use xlink:href=\"#embedded\"/>", "")),
        "The fixture must visibly render the embedded PNG");
    assertEquals(originalVisualHash, SvgHash.digest(sanitized));
    assertTrue(sanitized.contains("xlink:href=\"data:image/png;base64,"));
    assertTrue(sanitized.contains("xlink:href=\"#embedded\""));
  }

  /**
   * Verifies that embedded images and local references survive while event handlers are removed.
   *
   * @param href unqualified or XLink attribute name, including an alternative XLink prefix
   */
  @ParameterizedTest
  @ValueSource(strings = {"href", "xlink:href", "link:href"})
  void preserveEmbeddedPngAndRemoveEventHandlers(String href) throws Exception {
    String png =
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==";
    String original =
        "<svg xmlns=\"http://www.w3.org/2000/svg\""
            + " xmlns:xlink=\"http://www.w3.org/1999/xlink\""
            + " xmlns:link=\"http://www.w3.org/1999/xlink\">"
            + "<image id=\"embedded\" "
            + href
            + "=\""
            + png
            + "\" onload=\"alert(1)\"/>"
            + "<use "
            + href
            + "=\"#embedded\" onclick=\"alert(1)\"/></svg>";

    String sanitized = SVGSanitizer.sanitize(original);

    assertTrue(sanitized.contains("<image"));
    assertTrue(sanitized.contains(href + "=\"" + png + "\""));
    assertTrue(sanitized.contains(href + "=\"#embedded\""));
    assertFalse(sanitized.contains("onload"));
    assertFalse(sanitized.contains("onclick"));
  }

  /**
   * Verifies that unsafe image URLs and XLink use references are removed in both supported
   * namespaces.
   *
   * @param url external, relative, file, or JavaScript reference that must be rejected
   */
  @ParameterizedTest
  @ValueSource(
      strings = {
        "https://example.com/image.png", "//example.com/image.png", "image.png",
        "file:///tmp/image.png", "javascript:alert(1)", "JaVaScRiPt:alert(1)"
      })
  void rejectUnsafeImageReferencesInBothNamespaces(String url) throws Exception {
    String original =
        "<svg xmlns=\"http://www.w3.org/2000/svg\""
            + " xmlns:xlink=\"http://www.w3.org/1999/xlink\">"
            + "<image href=\""
            + url
            + "\"/>"
            + "<image xlink:href=\""
            + url
            + "\"/>"
            + "<use xlink:href=\""
            + url
            + "\"/></svg>";

    String sanitized = SVGSanitizer.sanitize(original);

    assertFalse(sanitized.contains("<image"));
    assertFalse(sanitized.contains("href="));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"href", "xlink:href", "link:href", " href ", "&#x68;ref", "xlink:hr&#x65;f"})
  void rejectAnimationsTargetingImageReferences(String target) throws Exception {
    for (String animation : Set.of("animate", "set", "animateTransform", "animateMotion")) {
      for (String valueAttribute : Set.of("to", "from", "by", "values")) {
        String original =
            "<svg xmlns=\"http://www.w3.org/2000/svg\""
                + " xmlns:xlink=\"http://www.w3.org/1999/xlink\""
                + " xmlns:link=\"http://www.w3.org/1999/xlink\">"
                + "<image id=\"embedded\" xlink:href=\"#safe\"><"
                + animation
                + " attributeName=\""
                + target
                + "\" "
                + valueAttribute
                + "=\"#safe;https://example.com/image.png\"/></image>"
                + "<"
                + animation
                + " href=\"#embedded\" attributeName=\""
                + target
                + "\" "
                + valueAttribute
                + "=\"https://example.com/image.png\"/>"
                + "<rect id=\"following\"/></svg>";

        String sanitized = SVGSanitizer.sanitize(original);

        assertFalse(sanitized.contains("<" + animation), animation + " targeting " + target);
        assertFalse(sanitized.contains("example.com"));
        assertTrue(sanitized.contains("xlink:href=\"#safe\""));
        assertTrue(sanitized.contains("id=\"following\""));
      }
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"animate", "set"})
  void preserveVisualAnimations(String animation) throws Exception {
    String original =
        "<svg xmlns=\"http://www.w3.org/2000/svg\"><rect><"
            + animation
            + " attributeName=\"opacity\" from=\"0\" to=\"1\" dur=\"1s\"/></rect></svg>";

    String sanitized = SVGSanitizer.sanitize(original);

    assertTrue(sanitized.contains("<" + animation));
    assertTrue(sanitized.contains("attributeName=\"opacity\""));
    assertTrue(sanitized.contains("to=\"1\""));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9J2FsZXJ0KDEpJy8+",
        "data:image/svg+xml,%3Csvg%20onload='alert(1)'/%3E",
        "data:image/png;base64,PHN2ZyBvbmxvYWQ9J2FsZXJ0KDEpJy8+",
        "data:image/png;base64,iVBORw0KGgo=!!!",
        "data:image/png;base64,iVBORw0KGgo=PHN2Zz4=",
        "data:image/png;charset=utf-8;base64,iVBORw0KGgo=",
        "data:image/png;base64,"
      })
  void rejectActiveOrMalformedEmbeddedData(String url) throws Exception {
    for (String href : Set.of("href", "xlink:href", "link:href")) {
      String original =
          "<svg xmlns=\"http://www.w3.org/2000/svg\""
              + " xmlns:xlink=\"http://www.w3.org/1999/xlink\""
              + " xmlns:link=\"http://www.w3.org/1999/xlink\">"
              + "<image "
              + href
              + "=\""
              + url
              + "\"/>"
              + "<feImage "
              + href
              + "=\""
              + url
              + "\"/>"
              + "<a "
              + href
              + "=\""
              + url
              + "\"/></svg>";
      String sanitized = SVGSanitizer.sanitize(original);
      assertFalse(sanitized.contains("href="), url);
      assertFalse(sanitized.contains("<image"), url);
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"a", "use", "animate", "set", "svg"})
  void restrictRasterDataToImageElements(String element) throws Exception {
    String original =
        "<svg xmlns=\"http://www.w3.org/2000/svg\""
            + " xmlns:xlink=\"http://www.w3.org/1999/xlink\"><"
            + element
            + " xlink:href=\"data:image/png;base64,iVBORw0KGgo=\"/></svg>";
    assertFalse(SVGSanitizer.sanitize(original).contains("href="));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "data:image/png;base64,iVBORw0KGgo=",
        "data:image/jpeg;base64,/9j/2Q==",
        "data:image/gif;base64,R0lGODlh"
      })
  void allowRasterSignaturesOnlyInImageContexts(String url) throws Exception {
    for (String element : Set.of("image", "feImage")) {
      for (String href : Set.of("href", "xlink:href")) {
        String original =
            "<svg xmlns=\"http://www.w3.org/2000/svg\""
                + " xmlns:xlink=\"http://www.w3.org/1999/xlink\"><"
                + element
                + " "
                + href
                + "=\""
                + url
                + "\"/></svg>";
        assertTrue(SVGSanitizer.sanitize(original).contains(href + "=\"" + url + "\""));
      }
    }
  }

  @Test
  void preserveBothSafeReferencesWithoutDuplicateAttributes() throws Exception {
    String sanitized =
        SVGSanitizer.sanitize(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">"
                + "<image href=\"#modern\" xlink:href=\"#legacy\"/></svg>");
    assertTrue(sanitized.contains("href=\"#modern\""));
    assertTrue(sanitized.contains("xlink:href=\"#legacy\""));
    assertEquals(XmlHash.digest(sanitized), XmlHash.digest(SVGSanitizer.sanitize(sanitized)));
  }

  @Test
  void preserveSafeXLinkWhenModernReferenceIsUnsafe() throws Exception {
    String sanitized =
        SVGSanitizer.sanitize(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">"
                + "<image href=\"javascript:alert(1)\" xlink:href=\"#legacy\"/></svg>");
    assertTrue(sanitized.contains("<image"));
    assertTrue(sanitized.contains("xlink:href=\"#legacy\""));
    assertFalse(sanitized.contains("javascript:"));
  }

  @Test
  void removeActiveDataXLinkFallback() throws Exception {
    String original =
        "<svg xmlns=\"http://www.w3.org/2000/svg\""
            + " xmlns:xlink=\"http://www.w3.org/1999/xlink\">"
            + "<a href=\"#safe\" xlink:href=\"data:text/html;base64,PHNjcmlwdD4=\"/></svg>";
    String sanitized = SVGSanitizer.sanitize(original);
    assertTrue(sanitized.contains("href=\"#safe\""));
    assertFalse(sanitized.contains("xlink:href="));
  }

  /** Verifies that a safe href does not allow an unsafe XLink fallback to survive. */
  @Test
  void removeUnsafeXLinkFallbackWhenSafeHrefIsPresent() throws Exception {
    String sanitized =
        SVGSanitizer.sanitize(
            "<svg xmlns=\"http://www.w3.org/2000/svg\""
                + " xmlns:xlink=\"http://www.w3.org/1999/xlink\">"
                + "<image href=\"#safe\" xlink:href=\"https://example.com/image.png\"/></svg>");

    assertTrue(sanitized.contains("href=\"#safe\""));
    assertFalse(sanitized.contains("xlink:href="));
    assertFalse(sanitized.contains("example.com"));
  }

  @Test
  void preserveXmlSpaceAndRejectLookalikeXLinkNamespace() throws Exception {
    String sanitized =
        SVGSanitizer.sanitize(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" xml:space=\"preserve\""
                + " xmlns:fake=\"HTTP://WWW.W3.ORG/1999/XLINK\">"
                + "<image href=\"#safe\" fake:href=\"#forged\"/></svg>");
    assertTrue(sanitized.contains("xml:space=\"preserve\""));
    assertTrue(sanitized.contains("href=\"#safe\""));
    assertFalse(sanitized.contains("fake:href="));
  }

  /** Verifies that an unknown namespace cannot supply an otherwise allowed image data URL. */
  @Test
  void rejectHrefInUnknownNamespace() throws Exception {
    String sanitized =
        SVGSanitizer.sanitize(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:other=\"urn:other\">"
                + "<image other:href=\"data:image/png;base64,iVBORw0KGgo=\"/></svg>");

    assertFalse(sanitized.contains("<image"));
  }

  /** Verifies that unqualified image references retain embedded data and reject external URLs. */
  @Test
  @DisplayName("Sanitize image href")
  void testSanitizingImageHref() throws Exception {
    String svgTestFile = "image-href.svg";

    // Convert output to string for verification
    String dirtySvg = this.getFixtureAsString(svgTestFile);

    assertTrue(dirtySvg.contains("href=\"data:image/png;base64,"), "dirty SVG contains data URL");
    assertTrue(dirtySvg.contains("href=\"http://external\""), "dirty SVG contains external URL");

    // Convert output to string for verification
    String sanitizedSvg = SVGSanitizer.sanitize(dirtySvg);

    assertTrue(
        sanitizedSvg.contains("href=\"data:image/png;base64,"), "sanitized SVG contains data URL");
    assertFalse(
        sanitizedSvg.contains("href=\"http://external\""),
        "dirty SVG does not contain external URL");

    // Save sanitized SVG for debugging
    saveSvg(sanitizedSvg, svgTestFile);
  }
}
