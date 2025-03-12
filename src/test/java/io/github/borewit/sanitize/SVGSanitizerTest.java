package io.github.borewit.sanitize;

import io.github.borewit.sanitize.util.CheckSvg;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class SVGSanitizerTest {

  private static final String RESOURCE_SVG_PATH = "/";
  private static final String SANITIZED_PATH = "build/sanitized";

  private SVGSanitizer svgSanitizer;

  @BeforeEach
  void setup() throws Exception {
    // Ensure the target directory exists
    Files.createDirectories(Paths.get(SANITIZED_PATH));  // ✅ Ensure target/ exists

    // Copy test SVG from resources to a temporary location
    try (InputStream inputStream = getClass().getResourceAsStream(RESOURCE_SVG_PATH)) {
      assertNotNull(inputStream, "Test SVG file should exist in resources");
    }

    this.svgSanitizer = new SVGSanitizer();
  }

  private String sanitizeSvgToString(String svgFixtureName) throws IOException {
    try (InputStream inputStream = this.getFixture(svgFixtureName);
         ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {

      assertNotNull(inputStream, String.format("Test file \"%s\" should exist in resources", svgFixtureName));

      try {
        // Run the sanitizer
        this.svgSanitizer.sanitize(inputStream, outputStream);
      } catch (Exception exception) {
        fail(String.format("Sanitizing file \"%s\"", svgFixtureName), exception);
      }

      // Convert output to string for verification
      return outputStream.toString(StandardCharsets.UTF_8);
    }
  }

  @ParameterizedTest
  @DisplayName("Sanitize JavaScript code in SVG")
  @ValueSource(strings = {
    "attacker-controlled.svg",
    "circleBlinkJS.svg",
    "eicar.svg",
    "form-action.svg",
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
    assertTrue(CheckSvg.containsJavaScript(dirtySvg), String.format("Dirty \"%s\" should contain JavaScript", svgTestFile));

    String sanitizedSvg = this.svgSanitizer.sanitize(dirtySvg);

    // Save sanitized SVG for debugging
    saveSvg(sanitizedSvg, svgTestFile);

    assertFalse(CheckSvg.containsJavaScript(sanitizedSvg), String.format("Sanitized \"%s\" contain not contain JavaScript", svgTestFile));
  }

  @ParameterizedTest
  @DisplayName("Sanitize JavaScript embedded in style")
  @ValueSource(strings = {
    "form-action2.svg"
  })
  void sanitizeJavaScriptInStyle(String svgTestFile) throws Exception {
    // Convert output to string for verification
    String dirtySvg = this.getFixtureAsString(svgTestFile);
    assertTrue(CheckSvg.containsJavaScriptInStyle(dirtySvg), String.format("Dirty \"%s\" should contain JavaScript", svgTestFile));

    String sanitizedSvg = this.svgSanitizer.sanitize(dirtySvg);

    // Save sanitized SVG for debugging
    saveSvg(sanitizedSvg, svgTestFile);

    assertFalse(CheckSvg.containsJavaScriptInStyle(sanitizedSvg), String.format("Sanitized \"%s\" contain not contain JavaScript", svgTestFile));
  }

  @ParameterizedTest
  @DisplayName("Sanitize external resources")
  @ValueSource(strings = {
    "circleWithS.svg",
    "externalimage.svg",
    "recursive-foreignobject.svg",
    "test(2).svg",
    "test(3).svg"
  })
  void sanitizeExternalResources(String svgTestFile) throws Exception {
    // Convert output to string for verification
    String dirtySvg = this.getFixtureAsString(svgTestFile);
    assertTrue(CheckSvg.containsExternalResources(dirtySvg), String.format("Dirty \"%s\" should contains an external resource", svgTestFile));

    String sanitizedSvg = new SVGSanitizer().sanitize(dirtySvg);

    // Save sanitized SVG for debugging
    saveSvg(sanitizedSvg, svgTestFile);

    assertFalse(CheckSvg.containsExternalResources(sanitizedSvg), String.format("Sanitized \"%s\" contains an external resource", svgTestFile));
  }

  @Disabled("SVG exploits not supported yet")
  @ParameterizedTest
  @DisplayName("Sanitize JavaScript code")
  @ValueSource(strings = {
    "billionlaughs.svg",
    "circleBlink.svg",
    "S.svg",
  })
  void sanitizeSvgExploits(String svgTestFile) {
    // ToDo?
  }

  private InputStream getFixture(String fixtureName) {
    return getClass().getResourceAsStream(RESOURCE_SVG_PATH + fixtureName);
  }

  private String getFixtureAsString(String fixtureName) throws IOException {
    try (InputStream inputStream = this.getFixture(fixtureName)) {
      return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  /**
   * Saves the sanitized SVG file to `build/sanitized/` for debugging.
   */
  private void saveSvg(String sanitizedSvg, String testFileName) throws IOException {
    Files.createDirectories(Paths.get(SANITIZED_PATH));  // Ensure directory exists
    String sanitizedFilename = testFileName.replace(".svg", "-sanitized.svg");

    String outputPath = SANITIZED_PATH + "/" + sanitizedFilename;
    Files.write(Paths.get(outputPath), sanitizedSvg.getBytes("UTF-8"));
  }

}
