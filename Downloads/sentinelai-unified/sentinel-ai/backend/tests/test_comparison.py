import uuid

from app.analysis.comparison import build_analyzed_exchange, compare_responses
from app.analysis.reflection import MarkerInput
from app.schemas.response_intel import NormalizedRequest, NormalizedResponse


def _req(**overrides) -> NormalizedRequest:
    defaults = dict(
        assessment_id=uuid.uuid4(),
        method="GET",
        url="https://lab.local/search?q=test",
        path="/search",
        query_params={"q": "test"},
    )
    defaults.update(overrides)
    return NormalizedRequest(**defaults)


def _resp(request_id, **overrides) -> NormalizedResponse:
    defaults = dict(
        request_id=request_id,
        status_code=200,
        headers={"Content-Type": "text/html"},
        content_type="text/html",
        body="<html><body>Hello</body></html>",
        elapsed_ms=120.0,
    )
    defaults.update(overrides)
    return NormalizedResponse(**defaults)


def test_compare_identical_responses():
    req = _req()
    baseline = _resp(req.id)
    test = _resp(req.id, id=uuid.uuid4())
    cmp = compare_responses(baseline, test)
    assert cmp.status_code_match is True
    assert cmp.length_delta == 0
    assert cmp.text_similarity == 1.0
    assert cmp.timing_significant is False


def test_compare_detects_status_and_timing_change():
    req = _req()
    baseline = _resp(req.id)
    test = _resp(
        req.id,
        id=uuid.uuid4(),
        status_code=500,
        body="<html><body>Internal error</body></html>",
        elapsed_ms=900.0,
    )
    cmp = compare_responses(baseline, test)
    assert cmp.status_code_match is False
    assert cmp.status_code_delta == 300
    assert cmp.timing_significant is True


def test_compare_detects_error_signature():
    req = _req()
    baseline = _resp(req.id)
    test = _resp(
        req.id,
        id=uuid.uuid4(),
        status_code=500,
        body="Warning: you have an error in your sql syntax near line 1",
    )
    cmp = compare_responses(baseline, test)
    assert cmp.error_signature_match == "mysql"


def test_build_analyzed_exchange_with_baseline_and_markers():
    req = _req()
    marker = "SENTINEL_CANARY_999"
    baseline = _resp(req.id, body="<html><body>No results</body></html>")
    test_body = f"<html><body>Results for {marker}</body></html>"
    test = _resp(req.id, id=uuid.uuid4(), body=test_body)

    exchange = build_analyzed_exchange(
        request=req,
        response=test,
        baseline=baseline,
        markers=[MarkerInput(parameter="q", marker=marker)],
    )

    assert exchange.comparison is not None
    assert exchange.features["reflection_count"] == 1
    kinds = {i.kind for i in exchange.security_indicators}
    assert "reflection" in kinds


def test_build_analyzed_exchange_without_baseline_still_detects_reflection():
    req = _req()
    marker = "SENTINEL_CANARY_NOBASE"
    body = f"<html><body>{marker}</body></html>"
    resp = _resp(req.id, body=body)

    exchange = build_analyzed_exchange(
        request=req,
        response=resp,
        baseline=None,
        markers=[MarkerInput(parameter="q", marker=marker)],
    )

    assert exchange.comparison is None
    kinds = {i.kind for i in exchange.security_indicators}
    assert "reflection" in kinds
