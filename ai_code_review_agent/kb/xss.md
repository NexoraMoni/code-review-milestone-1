# Cross-Site Scripting (XSS) Prevention

## What it is
XSS occurs when untrusted data is included in a web page without proper encoding, so the browser runs attacker-controlled script. CWE-79, OWASP A03:2021.

## Defence
Use template engines with automatic escaping (Jinja2 autoescape, Thymeleaf, JSP with c:out). Avoid render_template_string with user input, Markup, mark_safe, the safe filter and innerHTML. In Java servlets never write request parameters straight to the response; encode with the OWASP Java Encoder (Encode.forHtml). Apply context-specific encoding for HTML body, attributes, JavaScript and URLs.

## Additional layers
Set a Content-Security-Policy header, mark session cookies HttpOnly and Secure, and sanitize rich text with a vetted library such as bleach or OWASP HTML Sanitizer.
