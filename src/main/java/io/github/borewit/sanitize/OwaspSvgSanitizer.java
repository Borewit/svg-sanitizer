package io.github.borewit.sanitize;

import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

public class OwaspSvgSanitizer {

  private PolicyFactory svgPolicy;

  public OwaspSvgSanitizer() {
    this.svgPolicy = new HtmlPolicyBuilder()
      .allowElements("svg", "g", "path", "circle", "rect", "line", "polyline", "polygon", "text", "tspan")
      .allowAttributes("d").onElements("path")
      .allowAttributes("cx", "cy", "r").onElements("circle")
      .allowAttributes("x", "y", "width", "height").onElements("rect")
      .allowAttributes("points").onElements("polyline", "polygon")
      .allowAttributes("x", "y").onElements("text", "tspan")
      .allowAttributes("stroke", "fill", "stroke-width", "stroke-linecap", "stroke-linejoin").onElements("path", "circle", "rect", "line", "polyline", "polygon", "text")
      .allowAttributes("viewBox", "xmlns").onElements("svg")
      .toFactory();
  }


  public void sanitize(InputStream is, OutputStream os) throws Exception {
    // Define allowed SVG tags and attributes
    PolicyFactory svgPolicy = new HtmlPolicyBuilder()
      .allowElements("svg", "g", "path", "circle", "rect", "line", "polyline", "polygon", "text", "tspan")
      .allowAttributes("d").onElements("path")
      .allowAttributes("cx", "cy", "r").onElements("circle")
      .allowAttributes("x", "y", "width", "height").onElements("rect")
      .allowAttributes("points").onElements("polyline", "polygon")
      .allowAttributes("x", "y").onElements("text", "tspan")
      .allowAttributes("stroke", "fill", "stroke-width", "stroke-linecap", "stroke-linejoin").onElements("path", "circle", "rect", "line", "polyline", "polygon", "text")
      .allowAttributes("viewBox", "xmlns").onElements("svg")
      .toFactory();

    String dirtySvg = new String(is.readAllBytes(), StandardCharsets.UTF_8);
    String cleanSvg = sanitize(dirtySvg);

    try (OutputStreamWriter writer = new OutputStreamWriter(os, "UTF-8")) {
      writer.write(cleanSvg);
      writer.flush(); // Ensure all data is written
    }
  }

  public String sanitize(String svg)  {
    return this.svgPolicy.sanitize(svg);
  }
}
