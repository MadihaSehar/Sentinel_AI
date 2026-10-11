from app.analysis.comparison import build_analyzed_exchange
from app.analysis.reflection import MarkerInput
from app.analyzers.reflected_xss import ReflectedXssAnalyzer
from tests.analyzer_helpers import make_request, make_response


def test_plain_text_reflection_alone_is_not_a_candidate():
    """A reflection with no DOM corroboration and in plain html_body
    context should NOT by itself produce a finding (false-positive guard)."""
    req = make_request()
    marker = "SENTINEL_XSS_PLAIN"
    resp = make_response(req.id, body=f"<html><body>Hello {marker}</body></html>")

    exchange = build_analyzed_exchange(
        request=req, response=resp, markers=[MarkerInput(parameter="name", marker=marker)]
    )
    analyzer = ReflectedXssAnalyzer()
    assert analyzer.applies_to(exchange) is True
    findings = analyzer.analyze(exchange)
    assert findings == []


def test_reflection_in_script_context_is_a_candidate():
    req = make_request()
    marker = "SENTINEL_XSS_JS"
    body = f"<html><body><script>var x = '{marker}';</script></body></html>"
    resp = make_response(req.id, body=body)

    exchange = build_analyzed_exchange(
        request=req, response=resp, markers=[MarkerInput(parameter="x", marker=marker)]
    )
    analyzer = ReflectedXssAnalyzer()
    findings = analyzer.analyze(exchange)
    assert len(findings) == 1
    assert findings[0].category.value == "xss_reflected"
    assert findings[0].risk.confidence_score < 0.6  # single evidence kind, capped


def test_reflection_with_dom_corroboration_scores_higher():
    req = make_request()
    marker = "SENTINEL_XSS_DOM"
    baseline = make_response(req.id, body="<html><body>No input</body></html>")
    test_body = f"<html><body><img src=x onerror='{marker}()'></body></html>"
    test_resp = make_response(req.id, body=test_body)

    exchange = build_analyzed_exchange(
        request=req,
        response=test_resp,
        baseline=baseline,
        markers=[MarkerInput(parameter="cb", marker=marker)],
    )
    analyzer = ReflectedXssAnalyzer()
    findings = analyzer.analyze(exchange)
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    assert findings[0].risk.confidence_score > 0.4


def test_html_escaped_reflection_is_not_a_candidate():
    req = make_request()
    marker = "<script>x</script>"
    escaped_body = "<html><body>&lt;script&gt;x&lt;/script&gt;</body></html>"
    resp = make_response(req.id, body=escaped_body)

    exchange = build_analyzed_exchange(
        request=req, response=resp, markers=[MarkerInput(parameter="q", marker=marker)]
    )
    analyzer = ReflectedXssAnalyzer()
    findings = analyzer.analyze(exchange)
    assert findings == []


def test_analyzer_does_not_apply_without_reflection_indicator():
    req = make_request()
    resp = make_response(req.id)
    exchange = build_analyzed_exchange(request=req, response=resp)
    analyzer = ReflectedXssAnalyzer()
    assert analyzer.applies_to(exchange) is False
