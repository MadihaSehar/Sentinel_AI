"""
Report endpoints — render an assessment (or the bundled sample) as a
polished, self-contained HTML document or a downloadable PDF.

    GET /api/reports/sample?format=html|pdf          (public demo)
    GET /api/reports/assessments/{id}?format=html|pdf (authenticated)
"""
from __future__ import annotations

import uuid
from enum import Enum

import json

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile, status
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.assessment import Assessment
from app.models.user import User
from app.reports import (
    PDFGenerationError,
    ReportData,
    ReportLoadError,
    build_diff_html,
    build_diff_pdf,
    build_report_html,
    build_report_pdf,
    build_sample_baseline_report,
    build_sample_report,
    build_sarif,
    diff_reports,
    load_report_data,
)
from app.services import assessment_service

router = APIRouter(prefix="/reports", tags=["reports"])


class ReportFormat(str, Enum):
    HTML = "html"
    PDF = "pdf"
    SARIF = "sarif"
    JSON = "json"


class DiffFormat(str, Enum):
    HTML = "html"
    PDF = "pdf"


def _slug(value: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "-" for c in value).strip("-") or "report"


def _render(data: ReportData, fmt: ReportFormat) -> Response:
    if fmt is ReportFormat.PDF:
        try:
            pdf = build_report_pdf(data)
        except PDFGenerationError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
            ) from exc
        filename = f"sentinelai-report-{_slug(data.target)}.pdf"
        return Response(
            content=pdf,
            media_type="application/pdf",
            headers={"Content-Disposition": f'inline; filename="{filename}"'},
        )
    if fmt is ReportFormat.SARIF:
        filename = f"sentinelai-{_slug(data.target)}.sarif"
        return Response(
            content=json.dumps(build_sarif(data), indent=2),
            media_type="application/sarif+json",
            headers={"Content-Disposition": f'inline; filename="{filename}"'},
        )
    if fmt is ReportFormat.JSON:
        # SentinelAI's own loss-less snapshot — the ideal baseline file to
        # feed back into the scan-to-scan diff later.
        filename = f"sentinelai-{_slug(data.target)}.json"
        return Response(
            content=json.dumps(data.model_dump(mode="json"), indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'inline; filename="{filename}"'},
        )
    return HTMLResponse(content=build_report_html(data))


def _render_diff(diff, fmt: DiffFormat) -> Response:
    if fmt is DiffFormat.PDF:
        try:
            pdf = build_diff_pdf(diff)
        except PDFGenerationError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
            ) from exc
        filename = f"sentinelai-diff-{_slug(diff.current_target)}.pdf"
        return Response(
            content=pdf,
            media_type="application/pdf",
            headers={"Content-Disposition": f'inline; filename="{filename}"'},
        )
    return HTMLResponse(content=build_diff_html(diff))


async def _load_uploaded_report(upload: UploadFile, label: str) -> ReportData:
    raw = await upload.read()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{label} file is not valid JSON: {exc}",
        ) from exc
    try:
        return load_report_data(data)
    except ReportLoadError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{label}: {exc}") from exc


def _assessment_to_report_data(assessment: Assessment) -> ReportData:
    """
    Build a report snapshot from a persisted assessment. Findings/assets are
    populated here as the vulnerability pipeline persists them; until then the
    report renders the attack-surface and methodology sections with an empty
    findings list (an honest "nothing confirmed yet" report).
    """
    return ReportData(
        target=assessment.target,
        assessment_name=assessment.name,
        assessment_type=getattr(assessment.assessment_type, "value", str(assessment.assessment_type)),
        authorization_statement=(
            "Authorization confirmed" if assessment.authorization_confirmed else None
        ),
    )


@router.get("/sample")
async def sample_report(format: ReportFormat = ReportFormat.HTML) -> Response:
    """Render the bundled demo report — no authentication required."""
    return _render(build_sample_report(), format)


@router.get("/assessments/{assessment_id}")
async def assessment_report(
    assessment_id: uuid.UUID,
    format: ReportFormat = ReportFormat.HTML,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Render a report for one of the caller's own assessments."""
    assessment = await assessment_service.get_assessment_or_404(db, assessment_id, current_user)
    return _render(_assessment_to_report_data(assessment), format)


@router.get("/diff/sample")
async def sample_diff(format: DiffFormat = DiffFormat.HTML) -> Response:
    """Demo scan-to-scan diff (previous vs current sample) — no auth."""
    diff = diff_reports(build_sample_baseline_report(), build_sample_report())
    return _render_diff(diff, format)


@router.post("/diff")
async def compare_reports(
    baseline: UploadFile = File(..., description="Older scan (SentinelAI JSON or SARIF)"),
    current: UploadFile = File(..., description="Newer scan (SentinelAI JSON or SARIF)"),
    format: DiffFormat = DiffFormat.HTML,
) -> Response:
    """
    Compare two exported scan files and return a New / Fixed / Still-open
    diff report. Each file may be a SentinelAI report JSON (?format=json
    export) or a SARIF file (?format=sarif export).
    """
    base_data = await _load_uploaded_report(baseline, "baseline")
    curr_data = await _load_uploaded_report(current, "current")
    return _render_diff(diff_reports(base_data, curr_data), format)
