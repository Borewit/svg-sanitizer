package io.github.borewit.sanitize;

import com.helger.css.ECSSVersion;
import com.helger.css.decl.CSSDeclaration;
import com.helger.css.decl.CSSExpression;
import com.helger.css.decl.CSSExpressionMemberTermSimple;
import com.helger.css.decl.CSSExpressionMemberTermURI;
import com.helger.css.decl.CSSImportRule;
import com.helger.css.decl.CSSMediaRule;
import com.helger.css.decl.CSSNamespaceRule;
import com.helger.css.decl.CSSStyleRule;
import com.helger.css.decl.CascadingStyleSheet;
import com.helger.css.decl.ICSSExpressionMember;
import com.helger.css.decl.ICSSTopLevelRule;
import com.helger.css.reader.CSSReader;
import com.helger.css.writer.CSSWriter;
import com.helger.css.writer.CSSWriterSettings;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public class CssSanitizer {
  private static final Logger logger = Logger.getLogger(CssSanitizer.class.getName());

  // Comprehensive patterns for dangerous content
  private static final Pattern IMPORT_PATTERN =
      Pattern.compile(
          "(?i)@import\\s+(?:url\\s*\\([^)]*\\)|['\"][^'\"]*['\"])\\s*[^;]*;?", Pattern.MULTILINE);

  private static final Set<String> DANGEROUS_AT_RULES =
      Set.of("import", "namespace", "document", "supports");

  private static final Set<String> DANGEROUS_FUNCTIONS =
      Set.of("expression", "javascript", "behavior", "-moz-binding", "binding");

  private static final Set<String> DANGEROUS_PROTOCOLS =
      Set.of("javascript:", "vbscript:", "data:", "file:", "ftp:");

  private static final Set<String> DANGEROUS_KEYWORDS =
      Set.of(
          "<script",
          "<iframe",
          "<object",
          "<embed",
          "<form",
          "<input",
          "<textarea",
          "<select",
          "<button",
          "<link",
          "<meta",
          "<base",
          "srcdoc=",
          "onload=",
          "onerror=",
          "onclick=",
          "eval(");

  private static final Set<String> SAFE_PROPERTIES =
      Set.of(
          "color",
          "background-color",
          "border-color",
          "font-family",
          "font-size",
          "font-weight",
          "font-style",
          "text-align",
          "text-decoration",
          "margin",
          "padding",
          "border",
          "border-width",
          "border-style",
          "width",
          "height",
          "display",
          "position",
          "top",
          "left",
          "right",
          "bottom",
          "z-index",
          "opacity",
          "visibility",
          "overflow",
          "float",
          "clear",
          "line-height");

  /**
   * Sanitizes CSS string by removing dangerous constructs while preserving safe styling.
   *
   * @param css The CSS string to sanitize
   * @return Sanitized CSS string, or empty string if input is invalid
   */
  public static String sanitizeCss(String css) {
    return sanitizeCss(css, new SanitizationOptions());
  }

  /**
   * Sanitizes CSS string with custom options.
   *
   * @param css The CSS string to sanitize
   * @param options Sanitization options
   * @return Sanitized CSS string, or empty string if input is invalid
   */
  public static String sanitizeCss(String css, SanitizationOptions options) {
    if (css == null || css.trim().isEmpty()) {
      return "";
    }

    try {
      // Pre-sanitization: Remove obvious dangerous patterns
      css = preSanitize(css, options);

      // Parse CSS using ph-css library
      CascadingStyleSheet styleSheet = CSSReader.readFromString(css, ECSSVersion.CSS30);
      if (styleSheet == null) {
        logger.log(Level.WARNING, "Failed to parse CSS, returning empty string");
        return "";
      }

      // Sanitize the parsed stylesheet
      sanitizeStyleSheet(styleSheet, options);

      // Generate clean CSS output
      return generateCleanCss(styleSheet);

    } catch (Exception e) {
      logger.log(Level.SEVERE, "Error sanitizing CSS", e);
      return "";
    }
  }

  /** Pre-sanitization to remove obvious dangerous patterns before parsing. */
  private static String preSanitize(String css, SanitizationOptions options) {
    // Remove @import rules more thoroughly
    css = IMPORT_PATTERN.matcher(css).replaceAll("");

    // Remove comments that might hide dangerous content
    css = css.replaceAll("/\\*.*?\\*/", "");

    // Remove null bytes and control characters
    css = css.replaceAll("[\u0000-\u001F\u007F]", "");

    // Limit CSS size to prevent DoS
    if (css.length() > options.maxCssLength) {
      css = css.substring(0, options.maxCssLength);
      logger.log(Level.WARNING, "CSS truncated due to size limit");
    }

    return css;
  }

  /** Sanitizes the parsed CSS stylesheet. */
  private static void sanitizeStyleSheet(
      CascadingStyleSheet styleSheet, SanitizationOptions options) {
    if (styleSheet.getAllRules() == null) return;

    sanitizeTopLevelRules(styleSheet.getAllRules(), options);
  }

  /** Sanitizes top-level CSS rules. */
  private static void sanitizeTopLevelRules(
      List<ICSSTopLevelRule> rules, SanitizationOptions options) {
    Iterator<ICSSTopLevelRule> iter = rules.iterator();

    while (iter.hasNext()) {
      ICSSTopLevelRule rule = iter.next();

      // Remove dangerous at-rules
      if (isDangerousAtRule(rule)) {
        iter.remove();
        continue;
      }

      // Sanitize style rules
      if (rule instanceof CSSStyleRule) {
        CSSStyleRule styleRule = (CSSStyleRule) rule;
        if (!sanitizeStyleRule(styleRule, options)) {
          // Remove the entire rule if it's dangerous
          iter.remove();
          continue;
        }
      }

      // Recursively sanitize media rules and other container rules
      if (rule instanceof CSSMediaRule) {
        CSSMediaRule mediaRule = (CSSMediaRule) rule;
        sanitizeTopLevelRules(mediaRule.getAllRules(), options);
      }
    }
  }

  /** Checks if an at-rule is dangerous. */
  private static boolean isDangerousAtRule(ICSSTopLevelRule rule) {
    if (rule instanceof CSSImportRule || rule instanceof CSSNamespaceRule) {
      return true;
    }

    // Additional checks for other dangerous at-rules can be added here
    return false;
  }

  /**
   * Sanitizes a CSS style rule.
   *
   * @return true if the rule is safe to keep, false if it should be removed
   */
  private static boolean sanitizeStyleRule(CSSStyleRule styleRule, SanitizationOptions options) {
    if (styleRule.getAllDeclarations() == null) return false;

    // Sanitize selector if it contains dangerous patterns
    CSSWriterSettings writerSettings = new CSSWriterSettings(ECSSVersion.CSS30, false);
    String selector = styleRule.getSelectorsAsCSSString(writerSettings, 0);
    if (containsDangerousContent(selector)) {
      // Remove the entire rule if selector is dangerous
      return false;
    }

    sanitizeDeclarations(styleRule.getAllDeclarations(), options);

    // Check if any declarations remain after sanitization
    return styleRule.getAllDeclarations() != null && !styleRule.getAllDeclarations().isEmpty();
  }

  /** Sanitizes CSS declarations. */
  private static void sanitizeDeclarations(
      List<CSSDeclaration> declarations, SanitizationOptions options) {
    for (int i = declarations.size() - 1; i >= 0; i--) {
      CSSDeclaration decl = declarations.get(i);
      if (decl == null) continue;

      String property = decl.getProperty();
      if (property == null) {
        declarations.remove(i);
        continue;
      }

      property = property.toLowerCase().trim();

      // Remove if property is not in whitelist (when strict mode is enabled)
      if (options.strictPropertyWhitelist && !SAFE_PROPERTIES.contains(property)) {
        declarations.remove(i);
        continue;
      }

      // Sanitize the declaration value
      if (!sanitizeDeclaration(decl, options)) {
        declarations.remove(i);
      }
    }
  }

  /**
   * Sanitizes a single CSS declaration.
   *
   * @return true if declaration is safe (possibly modified), false if it should be removed
   */
  private static boolean sanitizeDeclaration(CSSDeclaration decl, SanitizationOptions options) {
    CSSExpression expr = decl.getExpression();
    if (expr == null) return false;

    String property = decl.getProperty().toLowerCase();
    List<ICSSExpressionMember> members = expr.getAllMembers();
    if (members == null) return false;

    boolean foundDanger = false;

    for (ICSSExpressionMember member : members) {
      if (member == null) continue;

      // Block all URI references in strict mode, or validate them in lenient mode
      if (member instanceof CSSExpressionMemberTermURI) {
        CSSExpressionMemberTermURI uriMember = (CSSExpressionMemberTermURI) member;
        String uri = uriMember.getURIString();

        if (options.allowUris && isUriSafe(uri)) {
          continue;
        } else {
          foundDanger = true;
          break;
        }
      }

      // Check for dangerous content in member values
      String memberValue = member.getAsCSSString();
      if (memberValue != null && containsDangerousContent(decodeCssEscapes(memberValue))) {
        foundDanger = true;
        break;
      }
    }

    if (foundDanger) {
      // Replace with safe default value instead of removing entirely
      replaceDangerousDeclaration(decl, property);
    }

    return true;
  }

  /** Checks if a URI is safe to include. */
  private static boolean isUriSafe(String uri) {
    if (uri == null) return false;

    String lowerUri = uri.toLowerCase().trim();

    // Block dangerous protocols
    for (String protocol : DANGEROUS_PROTOCOLS) {
      if (lowerUri.startsWith(protocol)) {
        return false;
      }
    }

    // Block data URLs with executable content
    if (lowerUri.startsWith("data:")) {
      return !lowerUri.contains("javascript") && !lowerUri.contains("<script");
    }

    return true;
  }

  /** Checks if content contains dangerous patterns. */
  private static boolean containsDangerousContent(String content) {
    if (content == null) return false;

    String lower = content.toLowerCase();

    // Check for dangerous functions
    for (String func : DANGEROUS_FUNCTIONS) {
      if (lower.contains(func + "(")) {
        return true;
      }
    }

    // Check for dangerous protocols
    for (String protocol : DANGEROUS_PROTOCOLS) {
      if (lower.contains(protocol)) {
        return true;
      }
    }

    // Check for dangerous keywords
    for (String keyword : DANGEROUS_KEYWORDS) {
      if (lower.contains(keyword)) {
        return true;
      }
    }

    return false;
  }

  /** Replaces a dangerous declaration with a safe default. */
  private static void replaceDangerousDeclaration(CSSDeclaration decl, String property) {
    CSSExpression safeExpr = new CSSExpression();

    switch (property) {
      case "background":
      case "background-image":
        safeExpr.addMember(new CSSExpressionMemberTermSimple("none"));
        break;
      case "content":
        safeExpr.addMember(new CSSExpressionMemberTermSimple("normal"));
        break;
      case "color":
      case "background-color":
      case "border-color":
        safeExpr.addMember(new CSSExpressionMemberTermSimple("transparent"));
        break;
      default:
        safeExpr.addMember(new CSSExpressionMemberTermSimple("initial"));
    }

    decl.setExpression(safeExpr);
  }

  /** Generates clean CSS from the sanitized stylesheet. */
  private static String generateCleanCss(CascadingStyleSheet styleSheet) {
    CSSWriterSettings settings = new CSSWriterSettings(ECSSVersion.CSS30, false);
    settings.setOptimizedOutput(true);
    settings.setRemoveUnnecessaryCode(true);

    CSSWriter writer = new CSSWriter(settings);
    writer.setWriteHeaderText(false);

    return writer.getCSSAsString(styleSheet);
  }

  /** Enhanced CSS escape decoder that handles various escape formats. */
  private static String decodeCssEscapes(String s) {
    if (s == null || s.isEmpty()) return "";

    StringBuilder sb = new StringBuilder();
    int len = s.length();

    for (int i = 0; i < len; i++) {
      char c = s.charAt(i);

      if (c == '\\' && i + 1 < len) {
        char next = s.charAt(i + 1);

        // Handle newline escapes
        if (next == '\n' || next == '\r') {
          i++; // Skip the newline
          continue;
        }

        // Handle hex escapes
        StringBuilder hex = new StringBuilder();
        int j = i + 1;

        while (j < len && hex.length() < 6 && isHexDigit(s.charAt(j))) {
          hex.append(s.charAt(j));
          j++;
        }

        if (hex.length() > 0) {
          try {
            int codePoint = Integer.parseInt(hex.toString(), 16);
            if (Character.isValidCodePoint(codePoint)) {
              sb.appendCodePoint(codePoint);
            }
            i = j - 1;

            // Skip optional whitespace after hex escape
            if (i + 1 < len && Character.isWhitespace(s.charAt(i + 1))) {
              i++;
            }
            continue;
          } catch (NumberFormatException e) {
            // Fall through to character escape handling
          }
        }

        // Handle single character escapes
        if (i + 1 < len) {
          sb.append(s.charAt(i + 1));
          i++;
          continue;
        }
      }

      sb.append(c);
    }

    return sb.toString();
  }

  private static boolean isHexDigit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  }

  /** Configuration options for CSS sanitization. */
  public static class SanitizationOptions {
    public boolean allowUris = false;
    public boolean strictPropertyWhitelist = false;
    public int maxCssLength = 100000; // 100KB limit
    public int maxNestingDepth = 10;

    public SanitizationOptions() {}

    public SanitizationOptions allowUris(boolean allow) {
      this.allowUris = allow;
      return this;
    }

    public SanitizationOptions strictPropertyWhitelist(boolean strict) {
      this.strictPropertyWhitelist = strict;
      return this;
    }

    public SanitizationOptions maxCssLength(int length) {
      this.maxCssLength = length;
      return this;
    }
  }
}
