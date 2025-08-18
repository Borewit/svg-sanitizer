package io.github.borewit.sanitize;

import com.helger.css.ECSSVersion;
import com.helger.css.decl.AbstractHasTopLevelRules;
import com.helger.css.decl.CSSDeclaration;
import com.helger.css.decl.CSSDeclarationList;
import com.helger.css.decl.CSSExpression;
import com.helger.css.decl.CSSExpressionMemberFunction;
import com.helger.css.decl.CSSExpressionMemberTermSimple;
import com.helger.css.decl.CSSExpressionMemberTermURI;
import com.helger.css.decl.CSSMediaRule;
import com.helger.css.decl.CSSStyleRule;
import com.helger.css.decl.CascadingStyleSheet;
import com.helger.css.decl.ECSSExpressionOperator;
import com.helger.css.decl.ICSSExpressionMember;
import com.helger.css.decl.ICSSTopLevelRule;
import com.helger.css.handler.DoNothingCSSParseExceptionCallback;
import com.helger.css.reader.CSSReader;
import com.helger.css.reader.CSSReaderDeclarationList;
import com.helger.css.reader.CSSReaderSettings;
import com.helger.css.reader.errorhandler.ThrowingCSSParseErrorHandler;
import com.helger.css.writer.CSSWriter;
import com.helger.css.writer.CSSWriterSettings;
import java.util.Locale;
import java.util.Set;

/** A conservative CSS subset for SVG. Unsupported syntax is discarded, never repaired. */
public final class CssSanitizer {
  static final int MAX_CSS_LENGTH = 100_000;
  private static final int MAX_NESTING_DEPTH = 10;

  // Only properties whose values cannot load resources except via a checked url() are supported.
  private static final Set<String> SAFE_PROPERTIES =
      Set.of(
          "alignment-baseline",
          "baseline-shift",
          "clip",
          "clip-path",
          "clip-rule",
          "color",
          "color-interpolation",
          "color-interpolation-filters",
          "color-rendering",
          "cursor",
          "direction",
          "display",
          "dominant-baseline",
          "fill",
          "fill-opacity",
          "fill-rule",
          "filter",
          "flood-color",
          "flood-opacity",
          "font-family",
          "font-size",
          "font-size-adjust",
          "font-stretch",
          "font-style",
          "font-variant",
          "font-weight",
          "image-rendering",
          "letter-spacing",
          "lighting-color",
          "marker",
          "marker-start",
          "marker-mid",
          "marker-end",
          "mask",
          "opacity",
          "overflow",
          "paint-order",
          "pointer-events",
          "shape-rendering",
          "stop-color",
          "stop-opacity",
          "stroke",
          "stroke-dasharray",
          "stroke-dashoffset",
          "stroke-linecap",
          "stroke-linejoin",
          "stroke-miterlimit",
          "stroke-opacity",
          "stroke-width",
          "text-anchor",
          "text-decoration",
          "text-rendering",
          "transform",
          "transform-origin",
          "unicode-bidi",
          "vector-effect",
          "visibility",
          "white-space",
          "word-spacing",
          "writing-mode",
          "background",
          "background-color",
          "background-image",
          "border",
          "border-color",
          "border-width",
          "border-style",
          "width",
          "height",
          "margin",
          "padding",
          "text-align",
          "line-height",
          "position",
          "top",
          "left",
          "right",
          "bottom",
          "z-index",
          "float",
          "clear");

  private static final Set<String> SAFE_FUNCTIONS =
      Set.of(
          "rgb",
          "rgba",
          "hsl",
          "hsla",
          "hwb",
          "lab",
          "lch",
          "oklab",
          "oklch",
          "matrix",
          "matrix3d",
          "translate",
          "translatex",
          "translatey",
          "translatez",
          "translate3d",
          "scale",
          "scalex",
          "scaley",
          "scalez",
          "scale3d",
          "rotate",
          "rotatex",
          "rotatey",
          "rotatez",
          "rotate3d",
          "skew",
          "skewx",
          "skewy",
          "perspective",
          "rect");

  private CssSanitizer() {}

  /** Returns a stylesheet containing only checked style and media rules. */
  public static String sanitizeCss(String css) {
    if (!isBoundedInput(css)) return "";
    try {
      CascadingStyleSheet sheet = CSSReader.readFromStringReader(css, readerSettings());
      if (sheet == null) return "";
      // Imports and namespaces are stored separately from ordinary rules by ph-css.
      sheet.removeAllImportRules();
      sheet.removeAllNamespaceRules();
      sanitizeRules(sheet);
      CSSWriter writer = new CSSWriter(writerSettings());
      writer.setWriteHeaderText(false);
      return writer.getCSSAsString(sheet);
    } catch (RuntimeException exception) {
      return "";
    }
  }

  /** Applies the same policy to an inline style declaration list. */
  public static String sanitizeInlineStyle(String css) {
    if (!isBoundedInput(css)) return "";
    try {
      CSSDeclarationList declarations =
          CSSReaderDeclarationList.readFromString(css, readerSettings());
      if (declarations == null) return "";
      for (int i = declarations.getDeclarationCount() - 1; i >= 0; i--) {
        if (!isSafeDeclaration(declarations.getDeclarationAtIndex(i))) {
          declarations.removeDeclaration(i);
        }
      }
      return declarations.getAsCSSString(writerSettings(), 0);
    } catch (RuntimeException exception) {
      return "";
    }
  }

  static boolean isCssProperty(String name) {
    return SAFE_PROPERTIES.contains(name);
  }

  /** Checks the complete value without allowing extra declarations to be injected. */
  static boolean isSafePresentationAttribute(String name, String value) {
    if (!isBoundedInput(value)) return false;
    try {
      CSSDeclarationList declarations =
          CSSReaderDeclarationList.readFromString(name + ":" + value, readerSettings());
      return declarations != null
          && declarations.getDeclarationCount() == 1
          && name.equals(declarations.getDeclarationAtIndex(0).getProperty())
          && isSafeDeclaration(declarations.getDeclarationAtIndex(0));
    } catch (RuntimeException exception) {
      return false;
    }
  }

  private static CSSReaderSettings readerSettings() {
    return new CSSReaderSettings()
        .setCSSVersion(ECSSVersion.CSS30)
        .setCustomErrorHandler(new ThrowingCSSParseErrorHandler())
        .setCustomExceptionHandler(new DoNothingCSSParseExceptionCallback());
  }

  private static CSSWriterSettings writerSettings() {
    return new CSSWriterSettings(ECSSVersion.CSS30, true);
  }

  private static void sanitizeRules(AbstractHasTopLevelRules container) {
    // getAllRules()/getAllDeclarations() return copies; mutate through the owning AST node.
    for (int i = container.getRuleCount() - 1; i >= 0; i--) {
      ICSSTopLevelRule rule = container.getRuleAtIndex(i);
      if (rule instanceof CSSStyleRule) {
        CSSStyleRule style = (CSSStyleRule) rule;
        for (int j = style.getDeclarationCount() - 1; j >= 0; j--) {
          if (!isSafeDeclaration(style.getDeclarationAtIndex(j))) style.removeDeclaration(j);
        }
        if (!style.hasDeclarations()) container.removeRule(i);
      } else if (rule instanceof CSSMediaRule) {
        CSSMediaRule media = (CSSMediaRule) rule;
        sanitizeRules(media);
        if (!media.hasRules()) container.removeRule(i);
      } else {
        // Font faces, keyframes, supports, layers, pages and unknown rules require separate review.
        container.removeRule(i);
      }
    }
  }

  private static boolean isSafeDeclaration(CSSDeclaration declaration) {
    return SAFE_PROPERTIES.contains(declaration.getProperty().toLowerCase(Locale.ROOT))
        && isSafeExpression(declaration.getExpression())
        && ("font-family".equalsIgnoreCase(declaration.getProperty())
            || declaration.getExpression().getAllMembers().stream()
                .noneMatch(
                    member ->
                        member instanceof CSSExpressionMemberTermSimple
                            && ((CSSExpressionMemberTermSimple) member).isStringLiteral()));
  }

  private static boolean isSafeExpression(CSSExpression expression) {
    if (expression == null || expression.getAllMembers().isEmpty()) return false;
    for (ICSSExpressionMember member : expression.getAllMembers()) {
      if (member instanceof CSSExpressionMemberTermURI) {
        // Restrict references to a simple fragment. No external, relative or data URLs.
        String uri = ((CSSExpressionMemberTermURI) member).getURIString();
        if (uri == null || !uri.matches("#[A-Za-z0-9_.:-]+")) return false;
      } else if (member instanceof CSSExpressionMemberFunction) {
        CSSExpressionMemberFunction function = (CSSExpressionMemberFunction) member;
        if (!SAFE_FUNCTIONS.contains(function.getFunctionName().toLowerCase(Locale.ROOT))
            || !isSafeExpression(function.getExpression())) return false;
      } else if (!(member instanceof CSSExpressionMemberTermSimple)
          && !(member instanceof ECSSExpressionOperator)) {
        return false;
      }
    }
    return true;
  }

  /** Bound work before parsing. Scan CSS strings/comments without altering token boundaries. */
  private static boolean isBoundedInput(String css) {
    if (css == null || css.isBlank() || css.length() > MAX_CSS_LENGTH) return false;
    int depth = 0;
    char quote = 0;
    boolean comment = false;
    for (int i = 0; i < css.length(); i++) {
      char c = css.charAt(i);
      if (c < 32 && c != '\n' && c != '\r' && c != '\t' && c != '\f') return false;
      if (comment) {
        if (c == '*' && i + 1 < css.length() && css.charAt(i + 1) == '/') {
          comment = false;
          i++;
        }
      } else if (c == '\\') {
        i++;
      } else if (quote != 0) {
        if (c == quote) quote = 0;
      } else if (c == '/' && i + 1 < css.length() && css.charAt(i + 1) == '*') {
        comment = true;
        i++;
      } else if (c == '\'' || c == '"') {
        quote = c;
      } else if (c == '{' || c == '(' || c == '[') {
        if (++depth > MAX_NESTING_DEPTH) return false;
      } else if (c == '}' || c == ')' || c == ']') {
        if (--depth < 0) return false;
      }
    }
    return depth == 0 && quote == 0 && !comment;
  }
}
