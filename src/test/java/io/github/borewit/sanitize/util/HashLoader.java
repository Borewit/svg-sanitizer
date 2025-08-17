package io.github.borewit.sanitize.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

public class HashLoader {

  public static Map<String, String> loadExpectedHashes() throws IOException {

    ObjectMapper mapper = new ObjectMapper();
    TypeReference<Map<String, String>> typeRef = new TypeReference<>() {};
    try (InputStream in = HashLoader.class.getResourceAsStream("/svg-xml-hash-map.json")) {
      return mapper.readValue(in, typeRef);
    }
  }
}
