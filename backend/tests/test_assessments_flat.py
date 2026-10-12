"""
End-to-end tests for the flat (dashboard) assessment endpoints.

These verify the one-form create → authorize → start → stop flow the
dashboard drives, including that the authorization gate is still enforced
(no start before AUTHORIZED) and that scope rules + the default project are
materialized correctly. The scan orchestrator itself is covered separately
by test_scan_orchestrator.py, so here we patch launch_scan to a spy and only
assert that start dispatches it.
"""
import pytest

from app.api.routes import assessments_flat


@pytest.fixture
def _spy_launch(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        assessments_flat, "launch_scan", lambda aid: calls.append(str(aid))
    )
    return calls


async def _create(client, **overrides):
    body = {
        "target": "example.com",
        "assessmentType": "Bug Bounty",
        "scope": {
            "allowedDomains": ["*.example.com"],
            "excludedDomains": ["admin.example.com"],
            "excludedCidrs": ["10.0.0.0/8"],
            "rateLimitPerSecond": 5,
            "concurrency": 10,
            "authorizationConfirmed": False,
        },
    }
    body.update(overrides)
    return await client.post("/api/assessments", json=body)


@pytest.mark.asyncio
async def test_create_flat_draft_then_authorize_and_start(authed_client, _spy_launch):
    # Create without confirmation → DRAFT, cannot start.
    resp = await _create(authed_client)
    assert resp.status_code == 201, resp.text
    created = resp.json()
    assert created["status"] == "draft"
    assert created["authorization_confirmed"] is False
    aid = created["id"]

    # Target is auto-added as an include rule; excludes are preserved.
    rule_pairs = {(r["rule_type"], r["value"]) for r in created["scope_rules"]}
    assert ("domain_include", "example.com") in rule_pairs
    assert ("domain_include", "*.example.com") in rule_pairs
    assert ("domain_exclude", "admin.example.com") in rule_pairs
    assert ("cidr_exclude", "10.0.0.0/8") in rule_pairs

    # Start is refused while unauthorized — the gate holds.
    resp = await authed_client.post(f"/api/assessments/{aid}/start")
    assert resp.status_code == 403
    assert _spy_launch == []


@pytest.mark.asyncio
async def test_create_flat_with_confirmation_authorizes_and_starts(authed_client, _spy_launch):
    resp = await _create(
        authed_client,
        scope={
            "allowedDomains": [],
            "authorizationConfirmed": True,
            "rateLimitPerSecond": 5,
            "concurrency": 10,
        },
    )
    assert resp.status_code == 201, resp.text
    created = resp.json()
    assert created["status"] == "authorized"
    assert created["authorization_confirmed"] is True
    aid = created["id"]

    resp = await authed_client.post(f"/api/assessments/{aid}/start")
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "queued"
    assert _spy_launch == [aid]

    # Stop marks it cancelled.
    resp = await authed_client.post(f"/api/assessments/{aid}/stop")
    assert resp.status_code == 200
    assert resp.json()["status"] == "stopped"


@pytest.mark.asyncio
async def test_rate_limit_clamped_to_ceiling(authed_client):
    resp = await _create(
        authed_client,
        scope={"authorizationConfirmed": False, "rateLimitPerSecond": 9999, "concurrency": 9999},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    # MAX_SCAN_RATE_LIMIT / MAX_SCAN_CONCURRENCY ceilings are enforced.
    assert body["rate_limit_rps"] <= 20
    assert body["concurrency"] <= 25


@pytest.mark.asyncio
async def test_unknown_assessment_type_rejected(authed_client):
    resp = await _create(authed_client, assessmentType="Nonsense")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_flat_create_reuses_single_default_project(authed_client):
    r1 = await _create(authed_client)
    r2 = await _create(authed_client)
    assert r1.status_code == 201 and r2.status_code == 201
    assert r1.json()["project_id"] == r2.json()["project_id"]


@pytest.mark.asyncio
async def test_list_and_get_flat(authed_client):
    created = (await _create(authed_client)).json()
    aid = created["id"]

    listing = await authed_client.get("/api/assessments")
    assert listing.status_code == 200
    assert any(a["id"] == aid for a in listing.json())

    one = await authed_client.get(f"/api/assessments/{aid}")
    assert one.status_code == 200
    assert one.json()["id"] == aid


@pytest.mark.asyncio
async def test_flat_endpoints_require_auth(client):
    # No bearer token → 401 from the auth dependency.
    resp = await client.post("/api/assessments", json={"target": "example.com", "assessmentType": "Lab"})
    assert resp.status_code == 401
