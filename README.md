[![CI](https://github.com/Borewit/svg-sanitizer/actions/workflows/ci.yml/badge.svg)](https://github.com/Borewit/svg-sanitizer/actions/workflows/ci.yml)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.borewit/svg-sanitizer)](https://central.sonatype.com/artifact/io.github.borewit/svg-sanitizer)
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
* Can handle huge SVG files, as the SVG is sanitized in a streaming manner

## Usage

### Maven Dependency

To use the SVG Sanitizer in your Java project, include the [**io.github.borewit:svg-sanitizer** Maven dependency](https://central.sonatype.com/artifact/io.github.borewit/svg-sanitizer).

```java
public class SVGSanitizerExample {
  public static void main(String[] args) {
    String dirtySvgContent = """
      <svg xmlns="http://www.w3.org/2000/svg" width="400" height="400" viewBox="0 0 124 124" fill="none">
        <rect width="124" height="124" rx="24" fill="#000000"/>
          <script type="text/javascript">
            alert(0x539);
         </script>
      </svg>""";
    try {
      String sanitizedSvg = SVGSanitizer.sanitize(dirtySvgContent);
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

Sanitize from `InputStream` to `OutputStream`:
```java
import java.io.*;

public class SVGSanitizerExample {
  public static void main(String[] args) throws Exception {
    File inputFile = new File("unsafe.svg");
    File outputFile = new File("sanitized.svg");

    try (InputStream inputStream = new FileInputStream(inputFile);
         OutputStream outputStream = new FileOutputStream(outputFile)) {

      SVGSanitizer.sanitize(inputStream, outputStream);
    }

    System.out.println("Sanitized SVG has been saved to " + outputFile.getAbsolutePath());
  }
}
```

Sanitize from `InputStream` to `InputStream`:
```java
import java.io.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class SVGSanitizerExample {
  public static void main(String[] args) throws Exception {
    File inputFile = new File("unsafe.svg"); // Potentially unsafe SVG file

    try (InputStream inputStream = new FileInputStream(inputFile);
         InputStream sanitizedStream = SVGSanitizer.sanitize(inputStream)) {

      // Pass the sanitized stream to an XML parser (without converting it to a String)
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document doc = builder.parse(sanitizedStream);

      System.out.println("SVG file successfully parsed after sanitization.");
    }
  }
}
```

### Available Methods

```java
public static String sanitize(String svgContent)
```
This method should only be used if loading the entire SVG in memory, is not a problem.

```java
public static void sanitize(InputStream inputStream, OutputStream outputStream)
```
Writes the sanitized SVG to the given outputStream

```java
public static InputStream sanitize(InputStream inputStream)
```
Acts as a filter, returning a new `InputStream` with the sanitized SVG.

## License
This project is licensed under the [MIT License](LICENSE.txt)
