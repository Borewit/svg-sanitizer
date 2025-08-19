package io.github.borewit.sanitize.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CommonUtil {

  /**
   * Computes the SHA-256 hash of the given input and returns it as a lowercase hexadecimal string.
   *
   * <p>This method uses {@link java.security.MessageDigest} with the "SHA-256" algorithm to
   * calculate the hash.
   *
   * @param input the byte array to hash; must not be {@code null}
   * @return the SHA-256 hash of the input, represented as a hexadecimal string (64 characters long)
   * @throws NoSuchAlgorithmException if the SHA-256 algorithm is not available in the environment
   *     (should not normally occur on standard JVMs)
   */
  public static String sha256Sum(byte[] input) throws NoSuchAlgorithmException {
    // Hash the raw input
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] digest = md.digest(input);

    StringBuilder hex = new StringBuilder();
    for (byte b : digest) {
      hex.append(String.format("%02x", b));
    }
    return hex.toString();
  }
}
