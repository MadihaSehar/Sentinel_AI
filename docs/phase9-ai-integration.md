# Phase 9 — AI Integration

## What this phase delivers

A provider-agnostic AI layer under `backend/app/ai/` that the orchestrator
(Phase 10+) and vulnerability analyzers call through one interface:

```python
result = await ai_service.analyze("sqli_analysis", evidence_dict)
```

No call site ever imports `GeminiProvider`, `GrokProvider`, etc. directly —
only `AIAnalysisService`.

## Layout

```
backend/app/ai/
├── __init__.py          # public exports
├── service.py            # AIAnalysisService — the entrypoint everything else uses
├── settings.py           # env-var config (AISettings)
├── prompt_loader.py       # loads prompts/*.md by name, cached
├── prompts/               # one short, single-purpose prompt per vuln class (section 27)
│   ├── recon_analysis.md
│   ├── endpoint_analysis.md
│   ├── xss_analysis.md
│   ├── sqli_analysis.md
│   ├── idor_analysis.md
│   ├── ssrf_analysis.md
│   ├── api_analysis.md
│   ├── false_positive_analysis.md
│   ├── severity_analysis.md
│   └── report_generation.md
└── providers/
    ├── base.py             # AIProvider ABC + AIAnalysisResult/AIUsage + error types
    ├── _openai_compat.py   # shared parsing for OpenAI-shaped chat APIs
    ├── gemini_provider.py
    ├── grok_provider.py
    ├── deepseek_provider.py
    ├── local_provider.py   # OpenAI-compatible local server (Ollama/vLLM/etc)
    └── factory.py           # build_provider() + AIProviderRouter (fallback chain)
```

## Key design decisions

**1. One normalized result shape, everywhere.**
Every provider parses its own vendor response format internally and returns
`AIAnalysisResult` — never a raw dict, never the vendor's JSON shape. The
consensus engine (Phase 10) and report generator only ever see this one
type, so adding a 5th provider later touches nothing outside `providers/`.

**2. Errors are caught, not raised, at the `analyze()` boundary.**
`AIProvider._call()` raises `AIProviderError` subclasses (timeout, rate
limit, auth, malformed response). `AIProvider.analyze()` catches all of
them and returns a `success=False` result instead. This matters because
section 28 of the spec requires the deterministic scanner to keep running
even if every AI provider is down — a raised exception would propagate
into the orchestrator and risk killing the pipeline; a failed result just
gets logged and skipped.

**3. `AIProviderRouter` implements the fallback chain, not each provider.**
Gemini → Grok → DeepSeek → local is a *policy* decision (which order, which
providers are even enabled), not something each provider should know about.
The router holds an ordered list built from whichever API keys are present
in `.env`; `analyze()` walks the list and returns the first success.
`analyze_all()` (for Phase 10's multi-model consensus) runs every provider
independently instead of stopping at the first success.

**4. Grok and DeepSeek share a parser; Gemini doesn't.**
Grok and DeepSeek both expose OpenAI-compatible `/chat/completions`
endpoints, so `_openai_compat.py` holds one shared response parser rather
than duplicating it. Gemini's `generateContent` response shape is
different enough (nested `candidates[].content.parts[].text`, different
usage-metadata keys) that forcing it through the same helper would just
add conditionals; it gets its own small parser instead.

**5. Structured JSON output is requested at the API level, not just the prompt.**
Grok and DeepSeek get `response_format: {"type": "json_object"}`; Gemini
gets `responseMimeType: "application/json"`. The system prompt also asks
for strict JSON as a second line of defense, and every provider strips
accidental ```json fences before parsing, because models don't always
honor the format parameter perfectly.

**6. Evidence is capped before it reaches a prompt.**
`AIProvider._render_user_prompt()` truncates the serialized evidence JSON
to 12,000 characters. This is the first, cheapest layer of the cost
control called for in section 29 — the orchestrator/analyzers are still
responsible for only calling `analyze()` with high-value evidence in the
first place, not raw unbounded scan dumps.

**7. The local provider is a first-class fallback, not an afterthought.**
If `LOCAL_MODEL_BASE_URL` is set, `LocalModelProvider` joins the router as
the last entry. It speaks the same OpenAI-compatible shape as Grok/DeepSeek
(works out of the box with Ollama's `/v1` endpoint, vLLM, or LM Studio), so
if all three cloud providers fail or no budget is configured, AI-assisted
analysis can still run entirely offline.

**8. Confidence is clamped server-side.**
`_parse_result()` clamps whatever confidence value a model returns into
`[0.0, 1.0]`. Models occasionally return out-of-range values; the
consensus/risk-scoring math downstream assumes a real probability, so this
is enforced once, here, rather than trusted at every consumer.

## What Phase 9 deliberately does NOT do

- **No consensus logic.** `analyze_all()` returns a list of independent
  results; averaging/agreement scoring and `REQUIRES_MANUAL_REVIEW` status
  is Phase 10's job.
- **No database writes.** Persisting `ai_analyses` / `ai_consensus` rows
  belongs to the orchestrator/service layer that calls this module.
- **No arbitrary tool invocation.** Providers only ever return structured
  JSON describing a finding; nothing here executes shell commands or
  triggers scanner tools. That stays in the Tool Registry (section 5),
  completely separate from this module.

## Config additions (merge into `.env.example`, section 31)

```
GEMINI_API_KEY=
GEMINI_MODEL=gemini-2.0-flash

XAI_API_KEY=
GROK_MODEL=grok-2-latest

DEEPSEEK_API_KEY=
DEEPSEEK_MODEL=deepseek-chat

# Optional — enables the local fallback provider. Leave blank to disable.
LOCAL_MODEL_BASE_URL=
LOCAL_MODEL_API_KEY=
LOCAL_MODEL_NAME=llama3.1

AI_TIMEOUT_SECONDS=30
AI_MAX_OUTPUT_TOKENS=1024
```

## Running the tests

```bash
cd backend
pip install -r requirements-ai.txt   # merge into requirements.txt
pytest tests/ai/ -v
```

15 tests, all mocked at the HTTP layer — no API keys or network access
required. Covers: success parsing for each provider, auth/rate-limit/
malformed-JSON error wrapping, markdown-fence stripping, confidence
clamping, and the full router fallback chain (including
`from_settings()` only building providers whose key is present).

## Wiring into the orchestrator (Phase 10 preview)

```python
from app.ai import AIAnalysisService

ai = AIAnalysisService.from_env()

result = await ai.analyze("idor_analysis", {
    "endpoint": "/api/orders/{id}",
    "baseline_response": {...},
    "test_response": {...},
})

if result.success and result.confidence >= 0.6:
    # hand off to the false-positive / consensus layer
    ...
```
