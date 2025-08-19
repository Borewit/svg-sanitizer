package io.github.borewit.sanitize.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.Document;
import org.w3c.dom.DocumentType;

public class XmlHash {

  private static final String DOCTYPE_PUBLIC_FMT = "<!DOCTYPE %1$s PUBLIC \"%2$s\" \"%3$s\">";
  private static final String DOCTYPE_SYSTEM_FMT = "<!DOCTYPE %1$s SYSTEM \"%2$s\">";

  public static void init() {
    org.apache.xml.security.Init.init();
  }

  private static String getDoctypeStr(Document doc) {
    DocumentType dt = doc.getDoctype();
    if (dt != null) {
      String name = dt.getName();
      String publicId = dt.getPublicId();
      String systemId = dt.getSystemId();
      if (publicId != null) {
        return String.format(DOCTYPE_PUBLIC_FMT, name, publicId, systemId);
      } else if (systemId != null) {
        return String.format(DOCTYPE_SYSTEM_FMT, name, systemId);
      }
    }
    return "";
  }

  public static String digest(byte[] xmlData) throws DigestException {
    // Parse XML safely

    Document doc;
    try {
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      dbf.setNamespaceAware(true);
      dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
      dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
      dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
      DocumentBuilder db = dbf.newDocumentBuilder();
      doc = db.parse(new ByteArrayInputStream(xmlData));
    } catch (Exception exception) {
      throw new DigestException("Failed to process XML document");
    }

    // Capture DOCTYPE as string
    String doctypeStr = getDoctypeStr(doc);

    // Canonicalize the DOM document
    ByteArrayOutputStream baos;
    try {
      Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
      baos = new ByteArrayOutputStream();
      canon.canonicalizeSubtree(doc, baos);
    } catch (InvalidCanonicalizerException | CanonicalizationException e) {
      throw new DigestException("Failed to canonicalize XML", e);
    }

    try {
      // Combine DOCTYPE + canonicalized content
      ByteArrayOutputStream combined = new ByteArrayOutputStream();
      combined.write(doctypeStr.getBytes(StandardCharsets.UTF_8));
      combined.write(baos.toByteArray());

      // Hash combined canonicalized content
      return CommonUtil.sha256Sum(combined.toByteArray());
    } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
      throw new DigestException("Failed to hash canonicalized XML data", e);
    } catch (IOException ioException) {
      throw new DigestException("Failed to convert to byte array", ioException);
    }
  }

  public static String digest(String xml) throws DigestException {
    return digest(xml.getBytes(StandardCharsets.UTF_8));
  }
}
