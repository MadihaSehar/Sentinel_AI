import uuid

from app.analysis.comparison import build_analyzed_exchange
from app.analysis.reflection import MarkerInput
from app.analysis.similarity import body_hash
from app.analysis.storage import ResponseStore
from app.schemas.response_intel import NormalizedRequest, NormalizedResponse


def _req(assessment_id):
    return NormalizedRequest(
        assessment_id=assessment_id,
        method="GET",
        url="https://lab.local/profile?id=1",
        path="/profile",
        query_params={"id": "1"},
    )


def _resp(request_id, body="<html><body>Hi</body></html>"):
    return NormalizedResponse(
        request_id=request_id,
        status_code=200,
        content_type="text/html",
        headers={"Content-Type": "text/html"},
        body=body,
        elapsed_ms=100.0,
    )


def test_save_and_fetch_request_response(db_session):
    assessment_id = uuid.uuid4()
    store = ResponseStore(db_session)

    req = _req(assessment_id)
    resp = _resp(req.id)

    store.save_request(req)
    store.save_response(resp)
    db_session.commit()

    fetched = store.get_response(resp.id)
    assert fetched is not None
    assert fetched.status_code == 200
    assert fetched.body_hash == body_hash(resp.body)


def test_save_analyzed_exchange_persists_indicators(db_session):
    assessment_id = uuid.uuid4()
    store = ResponseStore(db_session)

    req = _req(assessment_id)
    marker = "SENTINEL_CANARY_STORE"
    baseline = _resp(req.id, body="<html><body>No match</body></html>")
    test_resp = _resp(req.id, body=f"<html><body>{marker}</body></html>")

    exchange = build_analyzed_exchange(
        request=req,
        response=test_resp,
        baseline=baseline,
        markers=[MarkerInput(parameter="id", marker=marker)],
    )

    store.save_analyzed_exchange(assessment_id, exchange)

    indicators = store.get_indicators_for_response(test_resp.id)
    assert len(indicators) >= 1
    assert any(i.kind == "reflection" for i in indicators)


def test_find_duplicate_response_by_hash(db_session):
    assessment_id = uuid.uuid4()
    store = ResponseStore(db_session)

    req1 = _req(assessment_id)
    resp1 = _resp(req1.id, body="duplicate content")
    store.save_request(req1)
    store.save_response(resp1)
    db_session.commit()

    candidate_hash = body_hash("duplicate content")
    dup = store.find_duplicate_response(assessment_id, candidate_hash)
    assert dup is not None
    assert dup.id == resp1.id

    no_match = store.find_duplicate_response(assessment_id, body_hash("something else"))
    assert no_match is None
