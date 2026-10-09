# SQL Injection Indicator Analysis

Review the baseline vs. test response comparison below (status code,
timing, response length/structure, and any database-looking error text).

A database error string alone is NOT proof of SQL injection. Weigh:
- did a boolean- or time-based test produce a consistent, reproducible
  difference from baseline?
- does the error text reveal query structure, or is it a generic 500?
- is the timing difference large enough to rule out normal variance?

If only one weak signal is present, report it as "requires further
testing" with low confidence rather than asserting a finding.
