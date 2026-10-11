"""Tests for the report generation module and endpoints."""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.reports import (
    ReportData,
    build_report_html,
    build_report_pdf,
    build_sample_report,
    build_sarif,
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


def test_sarif_structure_and_mappings():
    sarif = build_sarif(build_sample_report())
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "SentinelAI"

    results = run["results"]
    assert len(results) == len(build_sample_report().findings)
    # Results are severity-sorted: the critical SQLi is first and maps to error.
    assert results[0]["ruleId"] == "CWE-89"
    assert results[0]["level"] == "error"
    assert results[0]["properties"]["security-severity"] == "9.5"
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("http")

    # Every result references a declared rule, and levels are SARIF-valid.
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in results:
        assert res["ruleId"] in rule_ids
        assert res["level"] in {"error", "warning", "note"}


@pytest.mark.asyncio
async def test_sample_endpoint_sarif(client: AsyncClient):
    resp = await client.get("/api/reports/sample", params={"format": "sarif"})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/sarif+json"
    body = resp.json()
    assert body["version"] == "2.1.0"
    assert body["runs"][0]["results"]


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


def test_generate_sarif_script_sample_mode(tmp_path, monkeypatch):
    import importlib.util
    from pathlib import Path

    for var in ("SENTINEL_API_URL", "SENTINEL_TOKEN", "SENTINEL_ASSESSMENT_ID"):
        monkeypatch.delenv(var, raising=False)

    script = Path(__file__).resolve().parent.parent / "scripts" / "generate_sarif.py"
    spec = importlib.util.spec_from_file_location("generate_sarif", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    out = tmp_path / "results.sarif"
    monkeypatch.setattr("sys.argv", ["generate_sarif.py", str(out)])
    assert mod.main() == 0

    import json

    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"]


@pytest.mark.asyncio
async def test_assessment_report_requires_auth(client: AsyncClient):
    import uuid

    resp = await client.get(f"/api/reports/assessments/{uuid.uuid4()}")
    assert resp.status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Scan-to-scan diff
# --------------------------------------------------------------------------- #
def test_diff_buckets_new_fixed_still_open():
    from app.reports import (
        build_sample_baseline_report,
        build_sample_report,
        diff_reports,
    )

    diff = diff_reports(build_sample_baseline_report(), build_sample_report())
    counts = diff.counts()
    assert counts == {"new": 2, "fixed": 2, "still_open": 4}
    assert diff.trend() == "Mixed"

    new_titles = {f.title for f in diff.new}
    assert "SQL Injection in product search" in new_titles
    fixed_titles = {f.title for f in diff.fixed}
    assert "Cross-Site Request Forgery on email change" in fixed_titles

    # The XSS stayed open but changed severity between scans.
    xss = next(c for c in diff.still_open if "Cross-Site Scripting" in c.finding.title)
    assert xss.severity_changed is True


def test_diff_identical_reports_is_no_change():
    from app.reports import build_sample_report, diff_reports

    diff = diff_reports(build_sample_report(), build_sample_report())
    assert diff.counts() == {"new": 0, "fixed": 0, "still_open": len(build_sample_report().findings)}
    assert diff.trend() == "No change"


def test_diff_loads_from_sarif_round_trip():
    """Export current to SARIF, load it back, diff against baseline."""
    from app.reports import (
        build_sample_baseline_report,
        build_sample_report,
        build_sarif,
        diff_reports,
        load_report_data,
    )

    current_sarif = build_sarif(build_sample_report())
    loaded = load_report_data(current_sarif)
    diff = diff_reports(build_sample_baseline_report(), loaded)
    # Same bucket sizes as the native-object diff — proves SARIF keys line up.
    assert diff.counts() == {"new": 2, "fixed": 2, "still_open": 4}


def test_load_report_rejects_unknown_format():
    from app.reports import ReportLoadError, load_report_data

    with pytest.raises(ReportLoadError):
        load_report_data({"not": "a report"})


@pytest.mark.asyncio
async def test_sample_diff_endpoint_html(client: AsyncClient):
    resp = await client.get("/api/reports/diff/sample")
    assert resp.status_code == 200
    assert "SCAN COMPARISON" in resp.text


@pytest.mark.asyncio
async def test_compare_endpoint_with_uploaded_json(client: AsyncClient):
    import json as _json

    from app.reports import build_sample_baseline_report, build_sample_report

    baseline = _json.dumps(build_sample_baseline_report().model_dump(mode="json"))
    current = _json.dumps(build_sample_report().model_dump(mode="json"))

    resp = await client.post(
        "/api/reports/diff",
        files={
            "baseline": ("baseline.json", baseline, "application/json"),
            "current": ("current.json", current, "application/json"),
        },
    )
    assert resp.status_code == 200
    assert "Mixed" in resp.text


@pytest.mark.asyncio
async def test_compare_endpoint_rejects_bad_json(client: AsyncClient):
    resp = await client.post(
        "/api/reports/diff",
        files={
            "baseline": ("b.json", "not json{", "application/json"),
            "current": ("c.json", "{}", "application/json"),
        },
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_json_export_format(client: AsyncClient):
    resp = await client.get("/api/reports/sample", params={"format": "json"})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json()["target"] == "example.com"
