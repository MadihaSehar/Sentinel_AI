# API Security Analysis

Review the discovered API surface below (routes, methods, auth scheme
observed, response schemas).

Flag indicators of: missing or weak authentication, missing per-object
authorization checks, excessive data exposure (more fields returned than
the UI uses), missing rate limiting, and mass-assignment-style parameter
acceptance. Be explicit about which indicators are directly observed in
the evidence versus inferred from route naming alone, and lower
confidence accordingly for inferred items.
