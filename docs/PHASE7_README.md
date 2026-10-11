# SentinelAI — Phase 7: Vulnerability Analyzers

Implements Section 8 (Vulnerability Analysis Engine) and Section 14
(Evidence Model) on top of Phase 6's AnalyzedExchange evidence.

## Layout
```
backend/app/schemas/finding.py          FindingCandidate, Severity,
                                          VulnerabilityCategory, RiskScore
                                          (Evidence/Confidence/Exploitability/
                                          Impact -> Final Risk, Section 13)
backend/app/analyzers/base.py           ExchangeAnalyzer / ComparativeAnalyzer
backend/app/analyzers/scoring.py        Shared risk-scoring (caps confidence
                                          when evidence is single-source)
backend/app/analyzers/reflected_xss.py  Reflection + DOM/context corroboration
backend/app/analyzers/sql_injection.py  DB error signature + status/timing
backend/app/analyzers/open_redirect.py  Redirect-chain vs param analysis
backend/app/analyzers/security_headers.py  Misconfig / clickjacking / CORS
backend/app/analyzers/idor.py           Comparative: same path-shape,
                                          different object, same auth outcome
backend/app/analyzers/registry.py       Orchestrator: applies_to() gating,
                                          per-analyzer error isolation
backend/tests/                          55 tests total, all passing
```

## Design notes (false-positive guards, per Section 13)
- **Reflected XSS**: a plain-text, escaped, or uncorroborated reflection
  produces NO finding at all — requires either a high-risk context
  (js_string/html_attribute) or DOM-shape corroboration (new <script>,
  new event handler).
- **SQLi**: a DB error string alone still produces a candidate but at
  capped confidence (<=0.55); a status-code or timing anomaly alongside
  it raises both confidence and severity.
- **IDOR**: comparative only — needs two exchanges for the same
  path-shape but different object IDs, both succeeding with >=80%
  structural similarity. Capped at confidence 0.5 pending human/AI
  consensus review, per Section 12's REQUIRES_MANUAL_REVIEW philosophy.
- **Security headers**: the one analyzer with high confidence by
  design — a missing header is directly observed fact, not inference.
- Every analyzer traces every finding back to specific indicators/
  responses in `evidence[]` — nothing is asserted without a referenced
  source (Section 14: "Never create a finding without evidence").
- The registry isolates analyzer crashes as INFO-severity, zero-risk
  "analyzer error" findings rather than losing them silently or letting
  one bad analyzer take down a whole batch (Section 22: auditability).

## Run tests
```
cd backend && pytest tests/ -v
```
Result: 55 passed (28 from Phase 6 + 27 new).

## Next phase
Phase 8 (Payload Knowledge Base) would feed richer, category-specific
test payloads to the discovery tools that produce the AnalyzedExchanges
these analyzers consume. Phase 9 (AI integration) is where
FindingCandidates get sent to Gemini/Grok/DeepSeek for independent
review and consensus scoring.
