package io.github.borewit.sanitize.util;

import io.sf.carte.echosvg.transcoder.TranscoderException;
import io.sf.carte.echosvg.transcoder.TranscoderInput;
import io.sf.carte.echosvg.transcoder.TranscoderOutput;
import io.sf.carte.echosvg.transcoder.image.ImageTranscoder;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class SvgHash {

  public static String digest(String svg) throws DigestException {
    return digest(svg.getBytes(StandardCharsets.UTF_8));
  }

  public static String digest(byte[] svgData) throws DigestException {
    try (InputStream targetStream = new ByteArrayInputStream(svgData)) {
      return digest(targetStream);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static String digest(InputStream svgInputStream) throws DigestException {
    try {
      // Parse SVG safely, ignoring DTDs
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      dbf.setNamespaceAware(true);
      dbf.setValidating(false);
      dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

      DocumentBuilder db = dbf.newDocumentBuilder();
      db.setEntityResolver(
          new EntityResolver() {
            @Override
            public InputSource resolveEntity(String publicId, String systemId) {
              // Ignore all external entities (like DTDs)
              return new InputSource(new ByteArrayInputStream(new byte[0]));
            }
          });

      Document doc = db.parse(svgInputStream);
      TranscoderInput input = new TranscoderInput(doc);

      // Custom transcoder to capture BufferedImage instead of writing a file
      class BufferedImageTranscoderImpl extends ImageTranscoder {
        private BufferedImage image;

        @Override
        public BufferedImage createImage(int width, int height) {
          return new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        }

        @Override
        public void writeImage(BufferedImage img, TranscoderOutput out) {
          this.image = img;
        }

        public BufferedImage getImage() {
          return image;
        }
      }

      BufferedImageTranscoderImpl transcoder = new BufferedImageTranscoderImpl();
      transcoder.addTranscodingHint(ImageTranscoder.KEY_EXECUTE_ONLOAD, Boolean.FALSE);

      transcoder.transcode(input, null); // capture image
      BufferedImage img = transcoder.getImage();

      if (img == null) {
        throw new DigestException("Failed to render SVG to image");
      }

      // Convert pixel data to byte array (ARGB)
      int width = img.getWidth();
      int height = img.getHeight();
      byte[] pixels = new byte[width * height * 4];
      int idx = 0;
      for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
          int argb = img.getRGB(x, y);
          pixels[idx++] = (byte) ((argb >> 24) & 0xFF); // alpha
          pixels[idx++] = (byte) ((argb >> 16) & 0xFF); // red
          pixels[idx++] = (byte) ((argb >> 8) & 0xFF); // green
          pixels[idx++] = (byte) (argb & 0xFF); // blue
        }
      }

      return CommonUtil.sha256Sum(pixels);

    } catch (ParserConfigurationException | SAXException | IOException | TranscoderException e) {
      throw new DigestException("Failed to transcode SVG", e);
    } catch (NoSuchAlgorithmException e) {
      throw new DigestException("SHA-256 algorithm not available", e);
    }
  }
}
