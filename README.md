# SVG Sanitizer

**SVG Sanitizer** is a Java library designed to clean SVG files by removing potentially dangerous JavaScript, blocking
external resource loading, and preventing XSS (Cross-Site Scripting) vulnerabilities. It is useful for ensuring that SVG
files are safe to use in a variety of applications, including web environments.

## Features

* Removes JavaScript from SVG files, including inline event handlers and <script> tags.
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
    <version>1.0.0</version>
</dependency>
```

```java
import io.github.borewit.sanitize.SVGSanitizer;

public class Main {
    public static void main(String[] args) {
        String svgContent = "<svg>...</svg>"; // Your SVG content here
        try {
            String sanitizedSvg = SVGSanitizer.sanitize(svgContent);
            System.out.println("Sanitized SVG: " + sanitizedSvg);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
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
