"""Tests for the report generation module and endpoints."""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.reports import (
    ReportData,
    build_report_html,
    build_report_pdf,
    build_sample_report,
)
from app.reports.schemas import ReportFinding, Severity


def test_sample_report_builds():
    data = build_sample_report()
    assert data.target == "example.com"
    assert len(data.findings) >= 5


def test_severity_counts_and_risk_score():
    data = build_sample_report()
    counts = data.severity_counts()
    assert counts["critical"] == 1
    assert sum(counts.values()) == len(data.findings)
    # One critical alone already caps the weighted score meaningfully high.
    assert data.risk_score() > 0
    assert data.risk_rating() in {"Critical", "High", "Medium", "Low", "Informational"}


def test_sorted_findings_are_descending_by_severity():
    data = build_sample_report()
    ranks = [f.severity.rank for f in data.sorted_findings()]
    assert ranks == sorted(ranks, reverse=True)


def test_empty_report_renders_cleanly():
    data = ReportData(target="example.org", assessment_name="Empty")
    html = build_report_html(data)
    assert "No vulnerabilities were confirmed" in html
    assert data.risk_rating() == "Informational"


def test_html_contains_key_sections_and_escapes_input():
    data = ReportData(
        target="example.com",
        assessment_name="XSS <test>",
        findings=[
            ReportFinding(
                title="<script>alert(1)</script>",
                severity=Severity.HIGH,
                category="XSS",
                endpoint="https://example.com/x",
                description="desc",
                recommendation="fix it",
            )
        ],
    )
    html = build_report_html(data)
    assert "Executive Summary" in html
    assert "Findings" in html
    assert "Attack Surface" in html
    # The raw script tag must be escaped, never emitted verbatim.
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_pdf_generation_produces_valid_pdf_bytes():
    pdf = build_report_pdf(build_sample_report())
    assert pdf[:5] == b"%PDF-"
    assert len(pdf) > 2000  # a real multi-finding report is not trivially small


@pytest.mark.asyncio
async def test_sample_endpoint_html(client: AsyncClient):
    resp = await client.get("/api/reports/sample")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "example.com" in resp.text


@pytest.mark.asyncio
async def test_sample_endpoint_pdf(client: AsyncClient):
    resp = await client.get("/api/reports/sample", params={"format": "pdf"})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:5] == b"%PDF-"


@pytest.mark.asyncio
async def test_assessment_report_requires_auth(client: AsyncClient):
    import uuid

    resp = await client.get(f"/api/reports/assessments/{uuid.uuid4()}")
    assert resp.status_code in (401, 403)
