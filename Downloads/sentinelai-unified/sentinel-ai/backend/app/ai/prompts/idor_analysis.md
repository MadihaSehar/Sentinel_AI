# IDOR / Broken Object-Level Authorization Analysis

Review the evidence below: the endpoint, the object identifier pattern,
and the responses obtained when the identifier was varied under
different authorization contexts.

A different HTTP response for a different ID is NOT proof of IDOR by
itself — it may just mean the object doesn't exist. Require evidence
that a response successfully returned another user's or tenant's data,
or allowed an unauthorized state change, before treating this as a
credible finding. Map to OWASP A01 / CWE-639 where applicable.
