from app.analysis.comparison import build_analyzed_exchange
from app.analyzers.idor import IdorAnalyzer
from tests.analyzer_helpers import make_request, make_response


def _exchange_for_order(order_id: str, body: str, status: int = 200):
    req = make_request(
        url=f"https://lab.local/api/orders/{order_id}",
        path=f"/api/orders/{order_id}",
    )
    resp = make_response(req.id, body=body, status_code=status, content_type="application/json")
    return build_analyzed_exchange(request=req, response=resp)


def test_similar_successful_responses_for_different_ids_flagged():
    body_template = (
        '{{"order_id": "{id}", "status": "shipped", "total": 42.00, '
        '"items": [{{"sku": "A1"}}]}}'
    )
    ex_a = _exchange_for_order("1001", body_template.format(id="1001"))
    ex_b = _exchange_for_order("1002", body_template.format(id="1002"))

    analyzer = IdorAnalyzer()
    assert analyzer.applies_to(ex_a, ex_b) is True
    findings = analyzer.analyze(ex_a, ex_b)
    assert len(findings) == 1
    assert findings[0].category.value == "idor"
    assert findings[0].risk.confidence_score < 0.6  # still needs human review


def test_dissimilar_responses_not_flagged():
    """applies_to() is a cheap path-shape pre-check only; the actual
    status/similarity gate lives in analyze(), which must reject this
    pair (one is a 403 error page, the other a successful order body)."""
    ex_a = _exchange_for_order("1001", '{"order_id": "1001", "status": "shipped"}')
    ex_b = _exchange_for_order("1002", '{"error": "forbidden"}', status=403)

    analyzer = IdorAnalyzer()
    assert analyzer.applies_to(ex_a, ex_b) is True
    assert analyzer.analyze(ex_a, ex_b) == []


def test_same_path_does_not_apply():
    ex_a = _exchange_for_order("1001", '{"order_id": "1001"}')
    ex_b = _exchange_for_order("1001", '{"order_id": "1001"}')
    analyzer = IdorAnalyzer()
    assert analyzer.applies_to(ex_a, ex_b) is False


def test_different_path_shape_does_not_apply():
    req_a = make_request(url="https://lab.local/api/orders/1001", path="/api/orders/1001")
    resp_a = make_response(req_a.id, body="{}", content_type="application/json")
    ex_a = build_analyzed_exchange(request=req_a, response=resp_a)

    req_b = make_request(url="https://lab.local/api/users/5", path="/api/users/5")
    resp_b = make_response(req_b.id, body="{}", content_type="application/json")
    ex_b = build_analyzed_exchange(request=req_b, response=resp_b)

    analyzer = IdorAnalyzer()
    assert analyzer.applies_to(ex_a, ex_b) is False
