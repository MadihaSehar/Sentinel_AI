# Phase 10 — Consensus Engine

## What this phase delivers

`backend/app/ai/consensus/engine.py` — a pure, deterministic reducer that
turns a list of independent `AIAnalysisResult`s (one per provider, from
Phase 9's `analyze_multi()`) into a single verdict:

```python
consensus = await ai_service.analyze_with_consensus("sqli_analysis", evidence)

consensus.status        # CONFIRMED | NO_FINDING | REQUIRES_MANUAL_REVIEW | INSUFFICIENT_DATA
consensus.confidence     # mean confidence across responding models
consensus.agreement_score  # 1.0 = perfect agreement, 0.0 = maximal disagreement
consensus.severity        # conservative: highest severity among agreeing models
consensus.evidence        # deduped union of every model's evidence
consensus.disagreement_notes  # human-readable reasons, when relevant
consensus.per_model        # full audit trail — every model's raw result, including failures
```

## Key design decisions

**1. Deterministic, no network calls.**
The engine only ever consumes `AIAnalysisResult` objects — it never calls
a provider itself. That makes every test in `test_consensus.py` instant
and mock-free, and means a consensus decision is always reproducible from
logged `per_model` data alone (useful for the `ai_consensus` audit table
in section 16).

**2. A low-confidence "finding" counts as a "no finding" vote.**
If a model reports a finding but at 0.2 confidence, that's treated as a
vote for finding-absent, not finding-present (`finding_confidence_threshold`,
default 0.5). This directly implements section 13's false-positive
intent: a shaky guess shouldn't inflate apparent agreement.

**3. Unanimous direction is necessary but not sufficient.**
Three models all voting "finding present" still gets sent to manual
review if their confidence scores are wildly spread
(`disagreement_stdev_threshold`, default 0.25). The worked example in
section 12 — Gemini 0.91, Grok 0.84, DeepSeek 0.88 — passes this
(stdev ≈ 0.03); three scores like 0.98 / 0.72 / 0.55 would not, even
though all three "agree" there's a finding.

**4. Severity is aggregated conservatively, not averaged.**
If agreeing models report "critical" and "low" for the same finding, the
consensus severity is "critical" — the highest, not a blended "medium".
Section 15 asks the system to explain *why* a severity was assigned, not
to average it into something nobody actually observed; a human reviewer
downgrading an over-flagged critical is a much safer failure mode than
under-flagging a real one.

**5. Fewer than `min_models_for_auto_confirm` responses can never auto-confirm.**
Default is 2. If only one provider succeeded (the others errored or
timed out), the single opinion is still returned — with its confidence,
severity, and evidence intact — but `status` is forced to
`REQUIRES_MANUAL_REVIEW` rather than `CONFIRMED`, because "consensus"
requires more than one voice by definition.

**6. Failed providers are excluded from scoring but never dropped from the record.**
`model_count` and all averages only count `success=True` results, but
`per_model` keeps every result, failures included. A finding's audit
trail should show that DeepSeek errored out, not silently omit it.

**7. Evidence is merged by exact-string dedup, not semantic merge.**
Two models citing the identical evidence string collapse to one entry;
different phrasings of the same observation are kept as separate entries
rather than guessing they're equivalent. A smarter merge (embedding
similarity, etc.) is a reasonable future enhancement but adds a second
AI call just to compare evidence — not worth it for Phase 10.

## What Phase 10 deliberately does NOT do

- **No database writes.** Persisting `ai_consensus` rows (section 16) is
  the orchestrator/service layer's job, same boundary as Phase 9.
- **No false-positive engine proper.** Section 13's Evidence/Confidence/
  Exploitability/Impact/Final Risk scores are a distinct, broader
  component that also pulls in deterministic scanner evidence (response
  diffing, etc.), not just AI opinions — that's a later phase. This
  engine's `finding_confidence_threshold` filter is the first layer of
  that pipeline, not the whole thing.
- **No retry/re-query of disagreeing models.** `REQUIRES_MANUAL_REVIEW`
  is a terminal status for this engine; asking a model to "reconsider"
  given the others' answers is a reasonable future experiment but changes
  the independence property the whole multi-model design relies on
  (section 37's research framing — comparing single-LLM vs. multi-LLM
  consensus — depends on each model's opinion being untainted by the
  others').

## Running the tests

```bash
cd backend
pytest tests/ai/ -v
```

27 tests total now (15 from Phase 9 + 10 for `ConsensusEngine` +
2 integration tests wiring `AIAnalysisService.analyze_with_consensus()`
through fake providers). Still zero network calls.

## Orchestrator usage (Phase 11+ preview)

```python
consensus = await ai_service.analyze_with_consensus("idor_analysis", evidence)

if consensus.status == ConsensusStatus.CONFIRMED:
    # safe to create a `findings` row automatically
    ...
elif consensus.status == ConsensusStatus.REQUIRES_MANUAL_REVIEW:
    # surface to the dashboard's "requires manual review" queue (section 2's
    # pipeline: ... -> Confidence Scoring -> Human Confirmation -> Report)
    ...
# NO_FINDING / INSUFFICIENT_DATA: nothing to report, move on
```
