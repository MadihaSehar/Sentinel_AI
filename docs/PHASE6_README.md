# SentinelAI — Phase 6: Response Intelligence Engine

Implements Section 9 of the master spec: request/response storage,
similarity analysis, reflection detection, DOM analysis.

## Layout
```
backend/app/schemas/response_intel.py   Normalized data contracts (Pydantic)
backend/app/models/response_intel.py    SQLAlchemy ORM (requests/responses/
                                          comparisons/indicators), Postgres
                                          in prod, SQLite-portable for tests
backend/app/analysis/similarity.py      Text + structural similarity, hashing
backend/app/analysis/reflection.py      Marker-based reflection detection
backend/app/analysis/dom_analysis.py    BeautifulSoup DOM diffing
backend/app/analysis/headers.py         Header diffing (volatile-header aware)
backend/app/analysis/error_signatures.py Pattern-based error fingerprinting
backend/app/analysis/comparison.py      Orchestrator -> AnalyzedExchange
backend/app/analysis/storage.py         Persistence + dedup by body_hash
backend/tests/                          28 unit tests, all passing
```

## Design notes
- Everything here is deterministic — no LLM calls, no payload execution.
  This is the evidence layer Section 10 (AI Orchestrator) later consumes.
- `security_indicators` are explicitly NOT vulnerability findings — Section
  13's false-positive rules (e.g. "an error string alone isn't SQLi") are
  enforced by keeping confidence_hint low and requiring the consensus/
  false-positive engine (future phase) to combine multiple indicators.
- Reflection detection only searches for markers the caller supplies
  (inert canary tokens) — this module has no knowledge of attack payloads.
- Dedup by `body_hash` lets the orchestrator skip deep-analyzing
  byte-identical pages it has already seen (Section 30).
- `GUID` TypeDecorator keeps models identical between prod Postgres and
  the in-memory SQLite used by the test suite.

## Run tests
```
cd backend && pip install -r requirements.txt
pytest tests/ -v
```
Result: 28 passed.

## Next phase
Phase 7 (Vulnerability analyzers) consumes `AnalyzedExchange` + its
`security_indicators` as input evidence.
