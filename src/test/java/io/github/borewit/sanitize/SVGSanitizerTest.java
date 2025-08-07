package io.github.borewit.sanitize;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.borewit.sanitize.util.CheckSvg;
import io.github.borewit.sanitize.util.XmlHash;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.parser.XMLParserException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SVGSanitizerTest {

  private static final String RESOURCE_SVG_PATH = "/";
  private static final String SANITIZED_PATH = "build/sanitized";

  // Map of expected hashes keyed by filename
  private static final Map<String, String> EXPECTED_HASHES =
      Map.ofEntries(
          Map.entry(
              "attacker-controlled.svg",
              "6e33ca4096b552fabb7c1baa33d7e0a2281e455519465acfd583813779551b3c"),
          Map.entry(
              "billionlaughs.svg",
              "b7a4cfd7e051e3babf5fddcb9a1dd37b987df8b2f592653c6495452b226ef343"),
          Map.entry(
              "form-action2.svg",
              "eb01f0235328631a114673513ddefc0fe250f5d1ac2c6c42342a05f422520e2d"),
          Map.entry(
              "circleBlinkJS.svg",
              "5f83e2876fc458ac786e33a82a5a08c2b78f52b4aa31e12940e33e8a08ad3ce8"),
          Map.entry(
              "eicar.svg", "7d7560b91affedef4f395aef312435e84825eb186f1d42c79f980b53a490de84"),
          Map.entry(
              "Flag_of_the_United_States.svg",
              "249a930f7adc0e078bc8167998b6a9558e4e06c5e3b099e3af419bd23c67be97"),
          Map.entry(
              "form-action.svg",
              "7e2e6328e7b0f47b022d10ce8b4fe843ccf651e1ded833b9e8f1e783f3227b13"),
          Map.entry(
              "form-action-case.svg",
              "44eddf60cc1f0c6c37111c478fa8e0d432ca8350b130b6022df34149640bcd4b"),
          Map.entry(
              "form-action2-case.svg",
              "ba86c67cc703779b689f7aa31ff31216e6f02a36431f5b6af24cf1f23c72040f"),
          Map.entry(
              "form-action3.svg",
              "8188e1401967e5525fc090ff95697fe30b3c810ad67a397f401ea0e5d4d3824c"),
          Map.entry(
              "javascriptalert.svg",
              "cfd74f25e4bd5340cd580d27e491cf9ba97de917e74190f7e4e3da8a8e715c73"),
          Map.entry("svg.svg", "0a71dea370125735233faff95e9d37d7745ef078f083a6e56e87594da2b2a99a"),
          Map.entry(
              "SVG-alert.svg", "85bb989d868b1a4a8fc7a1529479313f43d8d733336743b510aa802e9763ad4b"),
          Map.entry(
              "SVG-alert-eicar.svg",
              "85bb989d868b1a4a8fc7a1529479313f43d8d733336743b510aa802e9763ad4b"),
          Map.entry(
              "SVG-alertv2(1).svg",
              "85bb989d868b1a4a8fc7a1529479313f43d8d733336743b510aa802e9763ad4b"),
          Map.entry(
              "SVG-alertv2.svg",
              "85bb989d868b1a4a8fc7a1529479313f43d8d733336743b510aa802e9763ad4b"),
          Map.entry(
              "recursive-foreignobject.svg",
              "4a156f801b31b5dbdcb7bb0c6d16d6aa8b46ac4de5461d0c4fc77fac9a6ba3f0"),
          Map.entry(
              "test(1).svg", "7d7560b91affedef4f395aef312435e84825eb186f1d42c79f980b53a490de84"),
          Map.entry("test.svg", "9ddd88849fb1dbb516a992490cc5f92c9e9e6361f013fb80f7ee1720972a209a"),
          Map.entry(
              "test2(1).svg", "7d7560b91affedef4f395aef312435e84825eb186f1d42c79f980b53a490de84"),
          Map.entry(
              "test2.svg", "7d7560b91affedef4f395aef312435e84825eb186f1d42c79f980b53a490de84"),
          Map.entry(
              "circleWithS.svg",
              "e5ba76c1630eab587e7ec46df812cefefa34bc6a65f3175fbd3e3e1bac494388"),
          Map.entry(
              "externalimage.svg",
              "4ba2ad7d20adfcd7d75b86cf57b1ae7fb759322ab14f4fbd7b119ea9fbb046bb"),
          Map.entry(
              "externalimage2.svg",
              "cd79c741d81e781f389438788f376a0d007e2e3ad3dcb885850959cda3c9ba37"),
          Map.entry(
              "test(2).svg", "e69ce54ff2a61e67cc88d65b63889851217608a0a9851df085325651cf413389"),
          Map.entry(
              "test(3).svg", "dadbb58f3881b0b4491598ca9e74c80e5de61492f9390969acc30a44a439babb"),
          Map.entry(
              "test(4).svg", "928c4817e7fa0933e3d53e86d19861addfec9f89bda22b45f30f4015b97a2f2e"),
          Map.entry(
              "test-href-javascript.svg",
              "ed9f2b82ba1878429c14703d897218475fe3969654e4aeb9010289429eae5a86"),
          Map.entry(
              "test-href-javascript2.svg",
              "80dc3945e9b22205712ee72ead45f9ba94a8c903f8dd61d1937460e5f920c9bf"),
          Map.entry(
              "test-href-javascript3.svg",
              "80dc3945e9b22205712ee72ead45f9ba94a8c903f8dd61d1937460e5f920c9bf"),
          Map.entry(
              "style.svg", "82684c5031c30cad3c44333ae73c23f3483ee64a666c22b4b47a5b12fa8e748a"),
          Map.entry(
              "style-external-resource.svg",
              "fd23f8fde57b01e6433be65bd87f0fe770954d13ccde56bc4d5ac67f4ec28b3b"));

  @BeforeEach
  void setup() throws Exception {

    // Use the Java build in XML factory (xmlsec introduces other libraries)
    System.setProperty(
        "javax.xml.stream.XMLInputFactory", "com.sun.xml.internal.stream.XMLInputFactoryImpl");

    XmlHash.init(); // Needs to be called once, before using digest

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
  private void assertHash(String sanitizedSvg, String svgTestFile)
      throws IOException,
          InvalidCanonicalizerException,
          NoSuchAlgorithmException,
          XMLParserException,
          CanonicalizationException {
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
      throws IOException,
          XMLParserException,
          InvalidCanonicalizerException,
          CanonicalizationException,
          NoSuchAlgorithmException {
    Files.createDirectories(Paths.get(SANITIZED_PATH)); // Ensure directory exists
    String sanitizedFilename = testFileName.replace(".svg", "-sanitized.svg");

    String outputPath = SANITIZED_PATH + "/" + sanitizedFilename;
    Files.writeString(Paths.get(outputPath), sanitizedSvg);
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
        String.format("Dirty SVG \"%s\" contains ontouchstart attribute", svgTestFile));

    // Convert output to string for verification
    String sanitizedSvg = SVGSanitizer.sanitize(dirtySvg);

    assertFalse(
        CheckSvg.containsJavaScript(sanitizedSvg),
        String.format(
            "Sanitized SVG \"%s\" should not contain ontouchstart attribute", svgTestFile));

    System.out.println(sanitizedSvg);
  }
}
