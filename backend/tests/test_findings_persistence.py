"""
End-to-end tests for persisted findings: ingest → read → report → DB diff.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


async def _project_and_assessment(client: AsyncClient, name: str = "Persist Co") -> tuple[str, str]:
    pr = await client.post("/api/projects", json={"name": name})
    assert pr.status_code == 201
    project_id = pr.json()["id"]
    ar = await client.post(
        f"/api/projects/{project_id}/assessments",
        json={
            "name": f"{name} scan",
            "target": "example.com",
            "assessment_type": "bug_bounty",
            "scope_rules": [],
        },
    )
    assert ar.status_code == 201
    return project_id, ar.json()["id"]


def _finding(title: str, severity: str, cwe: str, endpoint: str, param: str | None = None) -> dict:
    return {
        "title": title,
        "category": "Injection",
        "cwe": cwe,
        "severity": severity,
        "endpoint": endpoint,
        "method": "GET",
        "parameter": param,
        "description": "desc",
        "recommendation": "fix it",
        "consensus_status": "confirmed",
        "agreement_score": 1.0,
        "consensus_confidence": 0.9,
        "participating_models": ["gemini", "deepseek"],
    }


@pytest.mark.asyncio
async def test_ingest_then_list_findings(authed_client: AsyncClient):
    _, assessment_id = await _project_and_assessment(authed_client)

    # Initially empty.
    empty = await authed_client.get(f"/api/assessments/{assessment_id}/findings")
    assert empty.status_code == 200
    assert empty.json() == []

    ingest = await authed_client.post(
        f"/api/assessments/{assessment_id}/findings",
        json={"findings": [_finding("SQLi", "critical", "CWE-89", "https://example.com/p", "q")]},
    )
    assert ingest.status_code == 201

    listed = await authed_client.get(f"/api/assessments/{assessment_id}/findings")
    body = listed.json()
    assert len(body) == 1
    assert body[0]["title"] == "SQLi"
    assert body[0]["severity"] == "critical"
    assert body[0]["model_count"] == 2


@pytest.mark.asyncio
async def test_ingest_is_replace_not_append(authed_client: AsyncClient):
    _, assessment_id = await _project_and_assessment(authed_client)
    await authed_client.post(
        f"/api/assessments/{assessment_id}/findings",
        json={"findings": [_finding("A", "high", "CWE-79", "https://example.com/a")]},
    )
    await authed_client.post(
        f"/api/assessments/{assessment_id}/findings",
        json={"findings": [_finding("B", "low", "CWE-601", "https://example.com/b")]},
    )
    listed = (await authed_client.get(f"/api/assessments/{assessment_id}/findings")).json()
    assert [f["title"] for f in listed] == ["B"]


@pytest.mark.asyncio
async def test_report_reflects_persisted_findings(authed_client: AsyncClient):
    _, assessment_id = await _project_and_assessment(authed_client)
    await authed_client.post(
        f"/api/assessments/{assessment_id}/findings",
        json={"findings": [_finding("SQLi in search", "critical", "CWE-89", "https://example.com/s", "q")]},
    )
    report = await authed_client.get(f"/api/reports/assessments/{assessment_id}")
    assert report.status_code == 200
    assert "SQLi in search" in report.text
    # The empty-state text must be gone now that a finding exists.
    assert "No vulnerabilities were confirmed" not in report.text


@pytest.mark.asyncio
async def test_db_diff_between_two_assessments(authed_client: AsyncClient):
    _, baseline_id = await _project_and_assessment(authed_client, "Baseline Co")
    _, current_id = await _project_and_assessment(authed_client, "Current Co")

    # Baseline: XSS + open redirect. Current: XSS (still open) + SQLi (new).
    await authed_client.post(
        f"/api/assessments/{baseline_id}/findings",
        json={"findings": [
            _finding("XSS", "high", "CWE-79", "https://example.com/x", "q"),
            _finding("Open redirect", "low", "CWE-601", "https://example.com/login", "next"),
        ]},
    )
    await authed_client.post(
        f"/api/assessments/{current_id}/findings",
        json={"findings": [
            _finding("XSS", "high", "CWE-79", "https://example.com/x", "q"),
            _finding("SQLi", "critical", "CWE-89", "https://example.com/p", "id"),
        ]},
    )

    diff = await authed_client.get(
        "/api/reports/diff/assessments",
        params={"baseline": baseline_id, "current": current_id},
    )
    assert diff.status_code == 200
    text = diff.text
    assert "SCAN COMPARISON" in text
    # 1 new (SQLi), 1 fixed (open redirect), 1 still-open (XSS) → Mixed trend.
    assert "Mixed" in text


@pytest.mark.asyncio
async def test_ingest_rejects_bad_severity(authed_client: AsyncClient):
    _, assessment_id = await _project_and_assessment(authed_client)
    resp = await authed_client.post(
        f"/api/assessments/{assessment_id}/findings",
        json={"findings": [_finding("X", "catastrophic", "CWE-1", "https://example.com/x")]},
    )
    assert resp.status_code == 422
