from app.analysis.comparison import build_analyzed_exchange
from app.analyzers.sql_injection import SqlInjectionAnalyzer
from tests.analyzer_helpers import make_request, make_response


def test_db_error_alone_produces_low_confidence_candidate():
    req = make_request(query_params={"id": "1"})
    baseline = make_response(req.id, body="<html><body>No error</body></html>")
    test_resp = make_response(
        req.id,
        body="Warning: you have an error in your sql syntax near 'foo'",
        status_code=200,
    )
    exchange = build_analyzed_exchange(request=req, response=test_resp, baseline=baseline)

    analyzer = SqlInjectionAnalyzer()
    assert analyzer.applies_to(exchange) is True
    findings = analyzer.analyze(exchange)
    assert len(findings) == 1
    assert findings[0].category.value == "sql_injection"
    assert findings[0].risk.confidence_score <= 0.55


def test_db_error_with_status_anomaly_scores_higher_and_high_severity():
    req = make_request(query_params={"id": "1"})
    baseline = make_response(req.id, body="<html><body>No error</body></html>", status_code=200)
    test_resp = make_response(
        req.id,
        body="Warning: you have an error in your sql syntax near 'foo'",
        status_code=500,
    )
    exchange = build_analyzed_exchange(request=req, response=test_resp, baseline=baseline)

    analyzer = SqlInjectionAnalyzer()
    findings = analyzer.analyze(exchange)
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    assert findings[0].risk.confidence_score > 0.4


def test_no_error_signature_means_no_candidate():
    req = make_request()
    resp = make_response(req.id, body="<html><body>all good</body></html>")
    exchange = build_analyzed_exchange(request=req, response=resp)
    analyzer = SqlInjectionAnalyzer()
    assert analyzer.applies_to(exchange) is False
    assert analyzer.analyze(exchange) == []


def test_non_db_error_like_python_traceback_is_ignored_by_sqli_analyzer():
    req = make_request()
    baseline = make_response(req.id, body="ok")
    test_resp = make_response(
        req.id, body="Traceback (most recent call last):\n  File ...", status_code=500
    )
    exchange = build_analyzed_exchange(request=req, response=test_resp, baseline=baseline)
    analyzer = SqlInjectionAnalyzer()
    assert analyzer.analyze(exchange) == []
