import pytest
from httpx import AsyncClient


async def _create_project(client: AsyncClient) -> str:
    resp = await client.post("/api/projects", json={"name": "Scope Check Co"})
    assert resp.status_code == 201
    return resp.json()["id"]


async def _create_assessment(client: AsyncClient, project_id: str) -> dict:
    resp = await client.post(
        f"/api/projects/{project_id}/assessments",
        json={
            "name": "scope test",
            "target": "*.example.com",
            "assessment_type": "bug_bounty",
            "scope_rules": [{"rule_type": "domain_exclude", "value": "admin.example.com"}],
        },
    )
    assert resp.status_code == 201
    return resp.json()


@pytest.mark.asyncio
async def test_scope_check_pattern_match_works_without_authorization(authed_client: AsyncClient):
    project_id = await _create_project(authed_client)
    assessment = await _create_assessment(authed_client, project_id)

    resp = await authed_client.post(
        f"/api/projects/{project_id}/assessments/{assessment['id']}/scope/check",
        json={"host": "api.example.com"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allowed"] is True

    resp2 = await authed_client.post(
        f"/api/projects/{project_id}/assessments/{assessment['id']}/scope/check",
        json={"host": "admin.example.com"},
    )
    assert resp2.json()["allowed"] is False


@pytest.mark.asyncio
async def test_scope_check_resolve_requires_authorization(authed_client: AsyncClient):
    project_id = await _create_project(authed_client)
    assessment = await _create_assessment(authed_client, project_id)

    resp = await authed_client.post(
        f"/api/projects/{project_id}/assessments/{assessment['id']}/scope/check",
        json={"host": "api.example.com", "resolve": True},
    )
    assert resp.status_code == 403
