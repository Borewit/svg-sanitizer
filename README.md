[![CI](https://github.com/Borewit/svg-sanitizer/actions/workflows/ci.yml/badge.svg)](https://github.com/Borewit/svg-sanitizer/actions/workflows/ci.yml)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.borewit/svg-sanitizer/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.github.borewit/svg-sanitizer)
[![javadoc](https://javadoc.io/badge2/io.github.borewit/svg-sanitizer/javadoc.svg)](https://javadoc.io/doc/io.github.borewit/svg-sanitizer)

# SVG Sanitizer

**SVG Sanitizer** is a Java library designed to clean [SVG files](https://en.wikipedia.org/wiki/SVG) by removing potentially dangerous JavaScript, blocking
external resource loading, and preventing [XSS (Cross-Site Scripting)](https://owasp.org/www-community/attacks/xss/) vulnerabilities. It is useful for ensuring that SVG
files are safe to use in a variety of applications, including web environments.

## Features

* Removes JavaScript from SVG files, including inline event handlers and `<script>` tags.
* Blocks loading of external resources, including href and xlink:href attributes pointing to external URLs.
* Prevents XSS vulnerabilities by sanitizing dangerous elements and attributes.
* Can be integrated easily into Java projects as a library.

## Usage

### Maven Dependency

To use the SVG Sanitizer in your Java project, include the following Maven dependency:

```xml
<dependency>
    <groupId>io.github.borewit</groupId>
    <artifactId>svg-sanitizer</artifactId>
    <version>0.1.0</version>
</dependency>
```

```java
public class MyApp {
  public static void main(String[] args) {
    String dirtySvgContent = """
      <svg xmlns="http://www.w3.org/2000/svg" width="400" height="400" viewBox="0 0 124 124" fill="none">
        <rect width="124" height="124" rx="24" fill="#000000"/>
          <script type="text/javascript">
            alert(0x539);
         </script>
      </svg>""";
    try {
      SVGSanitizer svgSanitizer = new SVGSanitizer();
      String sanitizedSvg = svgSanitizer.sanitize(dirtySvgContent);
      System.out.println(sanitizedSvg);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
```
Which will output the sanitized SVG:
```xml
<svg xmlns="http://www.w3.org/2000/svg" fill="none" height="400" viewBox="0 0 124 124" width="400">
    <rect fill="#000000" height="124" rx="24" width="124"/>
</svg>
```

### Available Methods

```java
public static String sanitize(String svgContent)
```

```java
public static void sanitize(InputStream is, OutputStream os)
```

## License
This project is licensed under the [MIT License](LICENSE.txt)
