"""
SentinelAI - Phase 6: Response Intelligence Engine
Comparison orchestrator.

Combines similarity.py, dom_analysis.py, headers.py, error_signatures.py,
and reflection.py into the normalized ResponseComparison / AnalyzedExchange
structures defined in app.schemas.response_intel (Section 9 of the spec).

This is the last purely-deterministic stage before anything is handed to
the AI Orchestrator (Section 10). Nothing here calls an LLM.
"""

from __future__ import annotations

from app.analysis import similarity
from app.analysis.dom_analysis import diff_dom
from app.analysis.error_signatures import detect_error_signature
from app.analysis.headers import diff_headers
from app.analysis.reflection import MarkerInput, find_reflections
from app.schemas.response_intel import (
    AnalyzedExchange,
    NormalizedRequest,
    NormalizedResponse,
    ResponseComparison,
    SecurityIndicator,
)

# Timing deltas below this are considered noise (network jitter).
_TIMING_SIGNIFICANCE_THRESHOLD_MS = 500.0
_HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")


def _is_html(response: NormalizedResponse) -> bool:
    return bool(response.content_type) and any(
        ct in response.content_type.lower() for ct in _HTML_CONTENT_TYPES
    )


def compare_responses(
    baseline: NormalizedResponse, test: NormalizedResponse
) -> ResponseComparison:
    """Deterministic baseline-vs-test comparison (Section 9)."""
    length_cmp = similarity.length_comparison(baseline.body, test.body)
    text_sim = similarity.text_similarity(baseline.body, test.body)
    struct_sim = similarity.structural_similarity(baseline.body, test.body)
    header_diff = diff_headers(baseline.headers, test.headers)

    timing_delta = test.elapsed_ms - baseline.elapsed_ms

    dom_diff = None
    if _is_html(baseline) and _is_html(test):
        dom_diff = diff_dom(baseline.body, test.body)

    test_error_sig = detect_error_signature(test.body)
    baseline_error_sig = detect_error_signature(baseline.body)
    # Only report an error signature if it's new relative to the baseline --
    # some apps always render a benign-looking "error" string.
    error_sig = test_error_sig if test_error_sig and test_error_sig != baseline_error_sig else None

    return ResponseComparison(
        baseline_response_id=baseline.id,
        test_response_id=test.id,
        status_code_match=baseline.status_code == test.status_code,
        status_code_delta=test.status_code - baseline.status_code,
        length_delta=length_cmp.delta,
        length_ratio=length_cmp.ratio,
        text_similarity=round(text_sim, 4),
        structural_similarity=round(struct_sim, 4),
        timing_delta_ms=round(timing_delta, 2),
        timing_significant=abs(timing_delta) >= _TIMING_SIGNIFICANCE_THRESHOLD_MS,
        header_diff=header_diff,
        dom_diff=dom_diff,
        error_signature_match=error_sig,
    )


def derive_indicators(
    comparison: ResponseComparison,
    reflections: list,
) -> list[SecurityIndicator]:
    """Translate deterministic comparison output into narrowly-scoped
    SecurityIndicators. These feed the false-positive engine (Section 13)
    and AI orchestrator -- they are explicitly NOT findings."""
    indicators: list[SecurityIndicator] = []

    if comparison.error_signature_match:
        indicators.append(
            SecurityIndicator(
                kind="error_signature",
                description=(
                    f"Response contains a '{comparison.error_signature_match}' "
                    "error signature not present in baseline."
                ),
                confidence_hint=0.3,
                evidence_refs=[str(comparison.test_response_id)],
            )
        )

    if comparison.timing_significant:
        indicators.append(
            SecurityIndicator(
                kind="timing_anomaly",
                description=(
                    f"Response time differs from baseline by "
                    f"{comparison.timing_delta_ms}ms."
                ),
                confidence_hint=0.2,
                evidence_refs=[str(comparison.test_response_id)],
            )
        )

    if not comparison.status_code_match:
        indicators.append(
            SecurityIndicator(
                kind="status_anomaly",
                description=(
                    f"Status code changed from baseline by "
                    f"{comparison.status_code_delta}."
                ),
                confidence_hint=0.15,
                evidence_refs=[str(comparison.test_response_id)],
            )
        )

    if comparison.dom_diff and comparison.dom_diff.new_script_tags > 0:
        indicators.append(
            SecurityIndicator(
                kind="dom_new_script",
                description=(
                    f"{comparison.dom_diff.new_script_tags} new <script> tag(s) "
                    "appeared relative to baseline."
                ),
                confidence_hint=0.35,
                evidence_refs=[str(comparison.test_response_id)],
            )
        )

    if comparison.dom_diff and comparison.dom_diff.new_event_handlers:
        indicators.append(
            SecurityIndicator(
                kind="dom_new_event_handler",
                description=(
                    "New inline event-handler attribute(s) appeared: "
                    + ", ".join(comparison.dom_diff.new_event_handlers[:5])
                ),
                confidence_hint=0.4,
                evidence_refs=[str(comparison.test_response_id)],
            )
        )

    for r in reflections:
        hint = 0.25
        if r.context in ("js_string", "html_attribute") and not r.html_escaped:
            hint = 0.45
        elif r.context == "html_body" and not r.html_escaped:
            hint = 0.35
        indicators.append(
            SecurityIndicator(
                kind="reflection",
                description=(
                    f"Input for parameter '{r.parameter}' was reflected in "
                    f"{r.context}"
                    + (" (HTML-escaped)" if r.html_escaped else "")
                    + "."
                ),
                confidence_hint=hint,
                evidence_refs=[r.marker],
            )
        )

    return indicators


def build_analyzed_exchange(
    request: NormalizedRequest,
    response: NormalizedResponse,
    baseline: NormalizedResponse | None = None,
    markers: list[MarkerInput] | None = None,
) -> AnalyzedExchange:
    """Build the full normalized evidence record for one exchange.

    - request/response: required, as captured.
    - baseline: optional prior response to the "clean" version of the same
      request, used for comparison.
    - markers: optional list of (parameter, marker) pairs this request is
      known to have carried, used for reflection detection.
    """
    features: dict = {
        "body_hash": similarity.body_hash(response.body),
        "size_bytes": response.size_bytes or len(response.body or ""),
        "content_type": response.content_type,
        "status_code": response.status_code,
        "redirect_count": len(response.redirect_chain),
    }

    reflections = []
    if markers:
        reflections = find_reflections(response.body, markers, response.headers)
        if reflections:
            features["reflection_count"] = len(reflections)

    comparison = None
    indicators: list[SecurityIndicator] = []
    if baseline is not None:
        comparison = compare_responses(baseline, response)
        indicators = derive_indicators(comparison, reflections)
    elif reflections:
        # No baseline available, but we can still surface raw reflections.
        indicators = derive_indicators(
            ResponseComparison(
                baseline_response_id=response.id,
                test_response_id=response.id,
                status_code_match=True,
                status_code_delta=0,
                length_delta=0,
                length_ratio=1.0,
                text_similarity=1.0,
                structural_similarity=1.0,
                timing_delta_ms=0.0,
                timing_significant=False,
                header_diff={},
                dom_diff=None,
                error_signature_match=detect_error_signature(response.body),
            ),
            reflections,
        )

    return AnalyzedExchange(
        request=request,
        response=response,
        features=features,
        comparison=comparison,
        security_indicators=indicators,
    )
