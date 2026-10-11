# False-Positive Review

You are given a candidate finding plus the evidence that produced it.
Your job is to argue, evidence-first, whether this is likely a genuine
finding or a false positive.

Checklist to apply:
- is there more than one independent piece of evidence?
- could the observed behavior be explained by something benign (caching,
  a load balancer, a WAF response, normal error handling)?
- was the test reproducible, or a single noisy observation?

Return a confidence score that reflects this analysis, not the original
candidate's confidence. If you disagree with the candidate finding, say
so directly in reasoning_summary.
