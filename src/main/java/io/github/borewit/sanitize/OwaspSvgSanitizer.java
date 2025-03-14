package io.github.borewit.sanitize;

import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

public class OwaspSvgSanitizer {

  public String sanitize(String unsafeSvg) throws Exception {
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
    return svgPolicy.sanitize(unsafeSvg);
  }
}
