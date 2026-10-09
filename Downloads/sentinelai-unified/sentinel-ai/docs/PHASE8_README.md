# SentinelAI — Phase 8: Payload Knowledge Base

Implements Section 7 of the master spec: a normalized, queryable index
of attack-technique metadata, NOT a bulk payload dump.

## Layout
```
payload-kb/
  xss.json                  4 entries
  sql_injection.json        4 entries
  injection_and_access.json 9 entries (cmdi, ssrf, lfi, path_traversal,
                                        rfi, csrf, xxe, ssti)
  api_and_misc.json         13 entries (idor, open_redirect, cors, jwt,
                                         auth, api_security, graphql,
                                         file_upload, deserialization,
                                         prototype_pollution)
  -> 30 entries total, all 20 Section-7 categories covered

backend/app/schemas/payload_kb.py       PayloadEntry / Category / Context /
                                          RiskLevel / Encoding schema
backend/app/payloads/knowledge_base.py  Loader, indices (by id/category/
                                          context), select_relevant()
backend/tests/test_payload_kb.py        16 tests, all passing
```

## Design notes
- **This is a knowledge index, not an attack library.** Each entry has
  `description` + `detection_method` as the primary content — most
  entries carry *no* example payload string at all, and the few that do
  (`<script>alert(1)</script>`, `../../../etc/passwd`, `{{7*7}}`, a bare
  `'`) are textbook-level examples already in every OWASP Testing Guide
  page, kept singular (never an arsenal) by a test that enforces it.
- **`select_relevant(detected_technologies)`** is the context-aware
  selection function Section 7 calls for: it maps fingerprinted tech
  tags (`mysql`, `php`, `jwt-auth`, `graphql-api`, ...) to relevant
  categories with a stated reason — mirroring Section 6's "if an API is
  detected, prioritize API analysis" logic. It never returns raw
  payloads, only which *families* are worth investigating; actually
  firing a test still goes through the allowlisted Tool Registry.
- `requires_authorization: true` on every single entry, and a test
  enforces that invariant.
- Loader validates every entry through Pydantic, rejects duplicate IDs,
  and fails loudly (not silently) on malformed JSON — all exercised by
  dedicated error-path tests.

## Run tests
```
cd backend && pytest tests/ -v
```
Result: 72 passed (55 from Phases 6–7 + 17 new).

## Next phase
Phase 9 (AI integration — Gemini/Grok/DeepSeek) is the first phase that
actually calls an LLM: it will take `select_relevant()`'s category
shortlist plus the `FindingCandidate`s from Phase 7 and ask each model
for an independent read, feeding into Phase 10's consensus engine.
