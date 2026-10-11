"""
These tests exist to prove the one invariant the whole platform depends on:
an assessment cannot be started unless authorization has been explicitly
and correctly confirmed. Every later phase (recon, discovery, nuclei,
exploitation-adjacent analyzers) will check the same `status` field this
suite validates — so if this suite is green, the gate holds everywhere
downstream too.
"""
import pytest
from httpx import AsyncClient


async def _create_project(client: AsyncClient) -> str:
    resp = await client.post(
        "/api/projects",
        json={"name": "Acme Bug Bounty", "authorization_reference": "https://hackerone.com/acme"},
    )
    assert resp.status_code == 201
    return resp.json()["id"]


async def _create_assessment(client: AsyncClient, project_id: str) -> dict:
    resp = await client.post(
        f"/api/projects/{project_id}/assessments",
        json={
            "name": "Initial recon",
            "target": "*.example.com",
            "assessment_type": "bug_bounty",
            "scope_rules": [
                {"rule_type": "domain_exclude", "value": "admin.example.com"},
                {"rule_type": "cidr_exclude", "value": "10.0.0.0/8"},
            ],
        },
    )
    assert resp.status_code == 201
    return resp.json()


@pytest.mark.asyncio
async def test_assessment_starts_in_draft_unauthorized(authed_client: AsyncClient):
    project_id = await _create_project(authed_client)
    assessment = await _create_assessment(authed_client, project_id)

    assert assessment["status"] == "draft"
    assert assessment["authorization_confirmed"] is False


@pytest.mark.asyncio
async def test_cannot_start_unauthorized_assessment(authed_client: AsyncClient):
    project_id = await _create_project(authed_client)
    assessment = await _create_assessment(authed_client, project_id)

    resp = await authed_client.post(
        f"/api/projects/{project_id}/assessments/{assessment['id']}/start"
    )
    assert resp.status_code == 403
    assert "authorized" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_authorize_requires_exact_confirmation_phrase(authed_client: AsyncClient):
    project_id = await _create_project(authed_client)
    assessment = await _create_assessment(authed_client, project_id)

    resp = await authed_client.post(
        f"/api/projects/{project_id}/assessments/{assessment['id']}/authorize",
        json={"confirmation_phrase": "yes i agree", "acknowledgement": True},
    )
    assert resp.status_code == 422  # pydantic validation failure, wrong phrase


@pytest.mark.asyncio
async def test_authorize_requires_acknowledgement_true(authed_client: AsyncClient):
    project_id = await _create_project(authed_client)
    assessment = await _create_assessment(authed_client, project_id)

    resp = await authed_client.post(
        f"/api/projects/{project_id}/assessments/{assessment['id']}/authorize",
        json={"confirmation_phrase": "I CONFIRM AUTHORIZATION", "acknowledgement": False},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_full_authorize_then_start_flow(authed_client: AsyncClient):
    project_id = await _create_project(authed_client)
    assessment = await _create_assessment(authed_client, project_id)

    auth_resp = await authed_client.post(
        f"/api/projects/{project_id}/assessments/{assessment['id']}/authorize",
        json={"confirmation_phrase": "I CONFIRM AUTHORIZATION", "acknowledgement": True},
    )
    assert auth_resp.status_code == 200
    body = auth_resp.json()
    assert body["authorization_confirmed"] is True
    assert body["status"] == "authorized"

    start_resp = await authed_client.post(
        f"/api/projects/{project_id}/assessments/{assessment['id']}/start"
    )
    assert start_resp.status_code == 200
    assert start_resp.json()["status"] == "queued"


@pytest.mark.asyncio
async def test_cannot_reauthorize_already_authorized_assessment(authed_client: AsyncClient):
    project_id = await _create_project(authed_client)
    assessment = await _create_assessment(authed_client, project_id)

    payload = {"confirmation_phrase": "I CONFIRM AUTHORIZATION", "acknowledgement": True}
    first = await authed_client.post(
        f"/api/projects/{project_id}/assessments/{assessment['id']}/authorize", json=payload
    )
    assert first.status_code == 200

    second = await authed_client.post(
        f"/api/projects/{project_id}/assessments/{assessment['id']}/authorize", json=payload
    )
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_rate_limit_and_concurrency_are_clamped_server_side(authed_client: AsyncClient):
    project_id = await _create_project(authed_client)
    resp = await authed_client.post(
        f"/api/projects/{project_id}/assessments",
        json={
            "name": "Aggressive scan attempt",
            "target": "example.com",
            "assessment_type": "pentest",
            "rate_limit_rps": 9999,
            "concurrency": 9999,
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    # Clamped to the platform ceiling (MAX_SCAN_RATE_LIMIT / MAX_SCAN_CONCURRENCY),
    # never to the attacker-supplied value.
    assert body["rate_limit_rps"] == 20
    assert body["concurrency"] == 25


@pytest.mark.asyncio
async def test_invalid_domain_target_rejected(authed_client: AsyncClient):
    project_id = await _create_project(authed_client)
    resp = await authed_client.post(
        f"/api/projects/{project_id}/assessments",
        json={"name": "bad target", "target": "not a domain!!", "assessment_type": "pentest"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_cannot_access_other_users_project(client: AsyncClient):
    # user A creates a project
    await client.post(
        "/api/auth/register", json={"email": "a@example.com", "password": "password123a"}
    )
    login_a = await client.post(
        "/api/auth/login", json={"email": "a@example.com", "password": "password123a"}
    )
    client.headers["Authorization"] = f"Bearer {login_a.json()['access_token']}"
    project_id = await _create_project(client)

    # user B tries to access it
    await client.post(
        "/api/auth/register", json={"email": "b@example.com", "password": "password123b"}
    )
    login_b = await client.post(
        "/api/auth/login", json={"email": "b@example.com", "password": "password123b"}
    )
    client.headers["Authorization"] = f"Bearer {login_b.json()['access_token']}"

    resp = await client.get(f"/api/projects/{project_id}")
    assert resp.status_code == 404
