package io.github.borewit.sanitize;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.borewit.sanitize.util.CheckSvg;
import io.github.borewit.sanitize.util.DigestException;
import io.github.borewit.sanitize.util.HashLoader;
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
            "Flag_of_the_United_States.svg",
            "form-action.svg",
            "form-action2.svg",
            "form-action2-case.svg",
            "form-action3.svg",
            "form-action-case.svg",
            "javascriptalert.svg",
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
      String sanitizedSvg = SVGSanitizer.sanitize(dirtySvg);
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

  @Test
  @DisplayName("Convert xlink SVG 2 namespace and preserve local reference")
  void preserveLocalAnchorXLinkHref() throws Exception {
    String svgTestFile = "Flag_of_the_United_States.svg";
    // Convert output to string for verification
    String dirtySvg = this.getFixtureAsString(svgTestFile);
    assertTrue(
        CheckSvg.hasInternalReferences(dirtySvg),
        String.format("Dirty \"%s\" should contain internal references", svgTestFile));

    String sanitizedSvg = SVGSanitizer.sanitize(dirtySvg);

    assertFalse(sanitizedSvg.contains("xlink:href=\""), "should not contain any xlink attributes");
    assertTrue(
        sanitizedSvg.contains("<use href=\"#s\" y=\"420\"/>"), "should preserve local references");

    // Save sanitized SVG for debugging
    saveSvg(sanitizedSvg, svgTestFile);
  }

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
  }

  @Test
  @DisplayName("form-action3.svg")
  void tmp() throws Exception {
    final String svgTestFile = "form-action3.svg";
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
}
