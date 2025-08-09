package io.github.borewit.sanitize.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.parser.XMLParserException;

public class XmlHash {

  public static void init() {
    org.apache.xml.security.Init.init();
  }
  ;

  public static String digest(String xml)
      throws IOException,
          InvalidCanonicalizerException,
          NoSuchAlgorithmException,
          XMLParserException,
          CanonicalizationException {

    // Get the canonicalizer instance
    Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);

    // Prepare an output stream to capture canonicalized output
    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    // Canonicalize the whole document subtree
    canon.canonicalize(xml.getBytes(StandardCharsets.UTF_8), baos, true);

    byte[] canonicalizedBytes = baos.toByteArray();

    // Hash the canonicalized XML (SHA-256)
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] digest = md.digest(canonicalizedBytes);

    // Convert hash to hex string
    StringBuilder hex = new StringBuilder();
    for (byte b : digest) {
      hex.append(String.format("%02x", b));
    }

    return hex.toString();
  }
}
