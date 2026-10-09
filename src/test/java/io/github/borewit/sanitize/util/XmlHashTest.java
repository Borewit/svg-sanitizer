package io.github.borewit.sanitize.util;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class XmlHashTest {

  @BeforeAll
  static void init() {
    XmlHash.init();
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void doesNotFetchExternalDtd(boolean publicDoctype) throws Exception {
    AtomicInteger requests = new AtomicInteger();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/svg.dtd",
        exchange -> {
          requests.incrementAndGet();
          byte[] dtd = "<!ATTLIST svg injected CDATA 'external'>".getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(200, dtd.length);
          try (var body = exchange.getResponseBody()) {
            body.write(dtd);
          }
        });
    server.start();
    try {
      String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/svg.dtd";
      String doctype =
          "<!DOCTYPE svg "
              + (publicDoctype ? "PUBLIC \"-//W3C//DTD SVG 1.1//EN\"" : "SYSTEM")
              + " \""
              + url
              + "\">";

      String digest = XmlHash.digest(doctype + "<svg/>");

      assertEquals(0, requests.get(), "Hashing XML must not make external DTD requests");
      assertEquals(
          CommonUtil.sha256Sum((doctype + "<svg></svg>").getBytes(StandardCharsets.UTF_8)), digest);
    } finally {
      server.stop(0);
    }
  }

  @Test
  void doesNotReadExternalDtd(@TempDir Path directory) throws Exception {
    Path dtd = directory.resolve("svg.dtd");
    Files.writeString(dtd, "<!ATTLIST svg injected CDATA 'local-file-content'>");
    String doctype = "<!DOCTYPE svg SYSTEM \"" + dtd.toUri() + "\">";

    assertEquals(
        CommonUtil.sha256Sum((doctype + "<svg></svg>").getBytes(StandardCharsets.UTF_8)),
        XmlHash.digest(doctype + "<svg/>"),
        "Local DTD content must not affect the XML digest");
  }
}
