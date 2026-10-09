# Cross-Site Scripting (XSS) Indicator Analysis

Review the request/response evidence below (reflection locations,
response content-type, encoding applied, DOM context if available).

Determine whether this looks like a genuine XSS indicator (reflected,
stored, or DOM-based) or a false positive. Specifically weigh:
- was the input reflected unencoded in an HTML/JS/attribute context?
- was any output encoding or CSP observed that would mitigate it?
- is there more than one piece of evidence, or just a single reflection?

A bare reflected parameter is NOT sufficient evidence on its own. Require
reflection context plus absence of encoding/mitigation before treating
this as anything above "low" confidence.
