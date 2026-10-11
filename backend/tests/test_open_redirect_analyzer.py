from app.analysis.comparison import build_analyzed_exchange
from app.analyzers.open_redirect import OpenRedirectAnalyzer
from tests.analyzer_helpers import make_request, make_response


def test_external_redirect_matching_param_is_flagged():
    req = make_request(
        url="https://lab.local/login?next=https://evil.example.com/phish",
        path="/login",
        query_params={"next": "https://evil.example.com/phish"},
    )
    resp = make_response(
        req.id,
        status_code=302,
        redirect_chain=["https://evil.example.com/phish"],
    )
    exchange = build_analyzed_exchange(request=req, response=resp)

    analyzer = OpenRedirectAnalyzer()
    assert analyzer.applies_to(exchange) is True
    findings = analyzer.analyze(exchange)
    assert len(findings) == 1
    assert findings[0].parameter == "next"
    assert findings[0].severity.value == "medium"


def test_internal_redirect_is_not_flagged():
    req = make_request(
        url="https://lab.local/login?next=/dashboard",
        path="/login",
        query_params={"next": "/dashboard"},
    )
    resp = make_response(req.id, status_code=302, redirect_chain=["https://lab.local/dashboard"])
    exchange = build_analyzed_exchange(request=req, response=resp)

    analyzer = OpenRedirectAnalyzer()
    findings = analyzer.analyze(exchange)
    assert findings == []


def test_no_redirect_param_does_not_apply():
    req = make_request(query_params={"q": "search term"})
    resp = make_response(req.id)
    exchange = build_analyzed_exchange(request=req, response=resp)
    analyzer = OpenRedirectAnalyzer()
    assert analyzer.applies_to(exchange) is False
