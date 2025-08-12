# SVG security best practices

User-uploaded SVG files may embed malicious code or include it via an external reference.
When a malicious SVG file is published on your website,
it can be used to exploit multiple attack vectors, including:

- [Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/):
  executing JavaScript inside the SVG to steal cookies, session tokens, or perform actions on behalf of the user.
- [Data exfiltration](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html#rule-2---avoid-documentwrite) via external resource loading:
  Using `<image>`, `<script>`, or `<use>` tags to send sensitive information to attacker-controlled servers.
- [Phishing overlays](https://owasp.org/www-community/attacks/Clickjacking):
  creating deceptive clickable areas or visual elements to trick users into revealing credentials.
- Local file access: embed `<image xlink:href="file:///...">` or `<use>` references to attempt to read local or server-side files.

There are **3 measures** I can recommend to avoid your website being vulnerable to such attacks.
Best to apply them all of them:

#### 1: Wrap the SVG in an `<img>` Tag

Instead of directly embedding an SVG using `<svg>` or `<object>`, use the `<img>` tag to render it:

```html
<img src="safe-image.svg" alt="Safe SVG">
```


The `<img>` tag ensures that the SVG is treated as an image and prevents JavaScript execution inside it,
but it doesn’t remove malicious code from the SVG file.

**Please be aware** that this measure alone is insufficient.
If a user opens the SVG file directly in a new browser tab or window,
the protection provided by the `<img>` wrapper is bypassed and any malicious code within the SVG may still execute.

#### 2: Apply a Content Security Policy (CSP) header
Enabling the [Content Security Policy (CSP)](https://developer.mozilla.org/docs/Web/HTTP/Guides/CSP)
_HTTP response header_ also prevents JavaScript execution inside the SVG.

For example:

```text
Content-Security-Policy: default-src 'none'; img-src 'self'; style-src 'none'; script-src 'none'; sandbox
```

Which applies the following policy:

| **Directive** | **Purpose** |
| --- | --- |
| `default-src 'none'` | Blocks all content by default. |
| `img-src 'self'` | Allows images only from the same origin. |
| `style-src 'none'` | Prevents inline and external CSS styles. |
| `script-src 'none'` | Blocks inline and external JavaScript to prevent XSS. |
| `sandbox` | Disables scripts, forms, and top-level navigation for the SVG. |

#### 3: Server-side sanitization of uploaded SVGs

Strip potentially harmful elements like `<script>`, `<iframe>`, `<foreignObject>`,
inline event handlers (e.g. `onclick`) or inclusion of other (potentially malicious) files.

Examples of libraries for SVG sanitization:
- Java: [SVG Sanitizer](https://github.com/Borewit/svg-sanitizer)
- JavaScript: [DOMPurify](https://github.com/cure53/DOMPurify)
- PHP: [svg-sanitizer](https://github.com/darylldoyle/svg-sanitizer)
- Python: [py-svg-hush](https://github.com/jams2/py-svg-hush)

#### Alternative: Rasterize SVG server-side

Render the SVG server side to a [raster based format](https://en.wikipedia.org/wiki/Raster_graphics), like PNG.
This may protect visiting users, but could introduce vulnerabilities at the rendering side at the server,
especially using server side JavaScript (like Node.js).
