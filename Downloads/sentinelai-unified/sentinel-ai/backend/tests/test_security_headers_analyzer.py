from app.analysis.comparison import build_analyzed_exchange
from app.analyzers.security_headers import SecurityHeadersAnalyzer
from tests.analyzer_helpers import make_request, make_response


def test_missing_hardening_headers_flagged():
    req = make_request()
    resp = make_response(req.id, headers={"Content-Type": "text/html"})
    exchange = build_analyzed_exchange(request=req, response=resp)

    analyzer = SecurityHeadersAnalyzer()
    findings = analyzer.analyze(exchange)
    categories = {f.category.value for f in findings}
    assert "security_misconfiguration" in categories
    assert "clickjacking" in categories  # also missing X-Frame-Options/CSP


def test_well_configured_headers_produce_no_misconfig_or_clickjacking_findings():
    req = make_request()
    resp = make_response(
        req.id,
        headers={
            "Content-Type": "text/html",
            "Strict-Transport-Security": "max-age=63072000",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
        },
    )
    exchange = build_analyzed_exchange(request=req, response=resp)
    analyzer = SecurityHeadersAnalyzer()
    findings = analyzer.analyze(exchange)
    categories = {f.category.value for f in findings}
    assert "security_misconfiguration" not in categories
    assert "clickjacking" not in categories


def test_x_frame_options_sameorigin_prevents_clickjacking_finding():
    req = make_request()
    resp = make_response(
        req.id,
        headers={
            "Content-Type": "text/html",
            "X-Frame-Options": "SAMEORIGIN",
            "Strict-Transport-Security": "max-age=1",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
        },
    )
    exchange = build_analyzed_exchange(request=req, response=resp)
    analyzer = SecurityHeadersAnalyzer()
    findings = analyzer.analyze(exchange)
    assert all(f.category.value != "clickjacking" for f in findings)


def test_cors_reflected_origin_with_credentials_flagged():
    req = make_request(headers={"Origin": "https://attacker.example"})
    resp = make_response(
        req.id,
        headers={
            "Content-Type": "text/html",
            "Access-Control-Allow-Origin": "https://attacker.example",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    exchange = build_analyzed_exchange(request=req, response=resp)
    analyzer = SecurityHeadersAnalyzer()
    findings = analyzer.analyze(exchange)
    cors_findings = [f for f in findings if f.category.value == "cors_misconfiguration"]
    assert len(cors_findings) == 1
    assert cors_findings[0].severity.value == "high"


def test_cors_wildcard_without_credentials_not_flagged():
    req = make_request(headers={"Origin": "https://attacker.example"})
    resp = make_response(
        req.id,
        headers={
            "Content-Type": "text/html",
            "Access-Control-Allow-Origin": "*",
        },
    )
    exchange = build_analyzed_exchange(request=req, response=resp)
    analyzer = SecurityHeadersAnalyzer()
    findings = analyzer.analyze(exchange)
    assert all(f.category.value != "cors_misconfiguration" for f in findings)


def test_non_html_response_does_not_apply():
    req = make_request()
    resp = make_response(req.id, content_type="application/json", body="{}")
    exchange = build_analyzed_exchange(request=req, response=resp)
    analyzer = SecurityHeadersAnalyzer()
    assert analyzer.applies_to(exchange) is False
