package io.github.borewit.sanitize;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.borewit.sanitize.util.CheckSvg;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SVGSanitizerTest {

  private static final String RESOURCE_SVG_PATH = "/";
  private static final String SANITIZED_PATH = "build/sanitized";

  @BeforeEach
  void setup() throws Exception {
    // Ensure the target directory exists
    Files.createDirectories(Paths.get(SANITIZED_PATH)); // ✅ Ensure target/ exists

    // Copy test SVG from resources to a temporary location
    try (InputStream inputStream = getClass().getResourceAsStream(RESOURCE_SVG_PATH)) {
      assertNotNull(inputStream, "Test SVG file should exist in resources");
    }
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

    assertFalse(
        CheckSvg.containsJavaScriptInStyle(sanitizedSvg),
        String.format("Sanitized \"%s\" should not contain JavaScript", svgTestFile));
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

    assertFalse(
        CheckSvg.containsExternalResources(sanitizedSvg),
        String.format("Sanitized \"%s\" should not contain an external resource", svgTestFile));
  }

  @Test
  @DisplayName("Preserve local anchor xlink:href")
  void preserveLocalAnchorXLinkHref() throws Exception {
    String svgTestFile = "Flag_of_the_United_States.svg";
    // Convert output to string for verification
    String dirtySvg = this.getFixtureAsString(svgTestFile);
    assertTrue(
        CheckSvg.hasInternalReferences(dirtySvg),
        String.format("Dirty \"%s\" should contain internal references", svgTestFile));

    String sanitizedSvg = SVGSanitizer.sanitize(dirtySvg);

    // Save sanitized SVG for debugging
    saveSvg(sanitizedSvg, svgTestFile);

    assertTrue(
        CheckSvg.hasInternalReferences(sanitizedSvg),
        String.format(
            "Dirty \"%s\" should still contain internal references after sanitization",
            svgTestFile));
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
    }
    assertFalse(
        CheckSvg.containsExternalEntities(sanitizedSvg),
        String.format("Sanitized \"%s\" should not contain entity definitions", svgTestFile));
  }

  /** Saves the sanitized SVG file to `build/sanitized/` for debugging. */
  private void saveSvg(String sanitizedSvg, String testFileName) throws IOException {
    Files.createDirectories(Paths.get(SANITIZED_PATH)); // Ensure directory exists
    String sanitizedFilename = testFileName.replace(".svg", "-sanitized.svg");

    String outputPath = SANITIZED_PATH + "/" + sanitizedFilename;
    Files.writeString(Paths.get(outputPath), sanitizedSvg);
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
}
