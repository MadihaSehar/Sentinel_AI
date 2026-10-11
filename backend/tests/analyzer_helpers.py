import uuid

from app.schemas.response_intel import NormalizedRequest, NormalizedResponse


def make_request(**overrides) -> NormalizedRequest:
    defaults = dict(
        assessment_id=uuid.uuid4(),
        method="GET",
        url="https://lab.local/app/page",
        path="/app/page",
        query_params={},
        headers={},
    )
    defaults.update(overrides)
    return NormalizedRequest(**defaults)


def make_response(request_id, **overrides) -> NormalizedResponse:
    defaults = dict(
        request_id=request_id,
        status_code=200,
        content_type="text/html",
        headers={"Content-Type": "text/html"},
        body="<html><body>OK</body></html>",
        elapsed_ms=100.0,
    )
    defaults.update(overrides)
    return NormalizedResponse(**defaults)
