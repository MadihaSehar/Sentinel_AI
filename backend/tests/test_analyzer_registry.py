from app.analysis.comparison import build_analyzed_exchange
from app.analysis.reflection import MarkerInput
from app.analyzers.registry import analyze_batch, analyze_exchange, analyze_exchange_pair
from tests.analyzer_helpers import make_request, make_response


def test_analyze_exchange_runs_multiple_applicable_analyzers():
    req = make_request(query_params={"id": "1"})
    baseline = make_response(req.id, body="<html><body>ok</body></html>")
    marker = "SENTINEL_REGISTRY_TEST"
    test_body = (
        "<html><body>"
        f"<script>var x = '{marker}';</script>"
        "Warning: you have an error in your sql syntax"
        "</body></html>"
    )
    test_resp = make_response(req.id, body=test_body, status_code=500)

    exchange = build_analyzed_exchange(
        request=req,
        response=test_resp,
        baseline=baseline,
        markers=[MarkerInput(parameter="id", marker=marker)],
    )

    findings = analyze_exchange(exchange)
    categories = {f.category.value for f in findings}
    assert "xss_reflected" in categories
    assert "sql_injection" in categories
    # security headers also applicable (HTML content-type, status < 400 is
    # false here since 500 >= 400, so misconfig/clickjacking are skipped)
    assert all(f.severity.value != "critical" for f in findings)  # sanity


def test_analyze_exchange_with_no_signals_returns_empty_for_signal_based_analyzers():
    req = make_request()
    resp = make_response(
        req.id,
        headers={
            "Content-Type": "text/html",
            "Strict-Transport-Security": "max-age=1",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
        },
    )
    exchange = build_analyzed_exchange(request=req, response=resp)
    findings = analyze_exchange(exchange)
    # headers are all fine and no reflection/error signatures exist
    assert findings == []


def test_analyze_batch_aggregates_across_exchanges():
    req1 = make_request(path="/a")
    resp1 = make_response(req1.id, headers={"Content-Type": "text/html"})
    ex1 = build_analyzed_exchange(request=req1, response=resp1)

    req2 = make_request(path="/b")
    resp2 = make_response(req2.id, headers={"Content-Type": "text/html"})
    ex2 = build_analyzed_exchange(request=req2, response=resp2)

    findings = analyze_batch([ex1, ex2])
    # each missing-headers finding covers one endpoint
    endpoints = {f.endpoint for f in findings if f.category.value == "security_misconfiguration"}
    assert endpoints == {"/a", "/b"}


def test_analyze_exchange_pair_delegates_to_comparative_analyzers():
    body_template = (
        '{{"order_id": "{id}", "status": "shipped", "total": 10, '
        '"currency": "USD", "customer": "acme-corp"}}'
    )
    req_a = make_request(
        url="https://lab.local/api/orders/1", path="/api/orders/1", method="GET"
    )
    resp_a = make_response(
        req_a.id, body=body_template.format(id="1"), content_type="application/json"
    )
    ex_a = build_analyzed_exchange(request=req_a, response=resp_a)

    req_b = make_request(
        url="https://lab.local/api/orders/2", path="/api/orders/2", method="GET"
    )
    resp_b = make_response(
        req_b.id, body=body_template.format(id="2"), content_type="application/json"
    )
    ex_b = build_analyzed_exchange(request=req_b, response=resp_b)

    findings = analyze_exchange_pair(ex_a, ex_b)
    assert len(findings) == 1
    assert findings[0].category.value == "idor"


def test_analyzer_exception_is_isolated_and_recorded(monkeypatch):
    req = make_request()
    resp = make_response(req.id, headers={"Content-Type": "text/html"})
    exchange = build_analyzed_exchange(request=req, response=resp)

    from app.analyzers import registry as registry_module

    class BoomAnalyzer:
        name = "boom_analyzer"

        def applies_to(self, exchange):
            return True

        def analyze(self, exchange):
            raise RuntimeError("simulated analyzer bug")

    monkeypatch.setattr(
        registry_module, "EXCHANGE_ANALYZERS", registry_module.EXCHANGE_ANALYZERS + [BoomAnalyzer()]
    )

    findings = analyze_exchange(exchange)
    error_findings = [f for f in findings if f.analyzer_name == "boom_analyzer"]
    assert len(error_findings) == 1
    assert error_findings[0].severity.value == "info"
    assert error_findings[0].risk.confidence_score == 0.0
