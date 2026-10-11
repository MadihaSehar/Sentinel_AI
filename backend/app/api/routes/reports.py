"""
Report endpoints — render an assessment (or the bundled sample) as a
polished, self-contained HTML document or a downloadable PDF.

    GET /api/reports/sample?format=html|pdf          (public demo)
    GET /api/reports/assessments/{id}?format=html|pdf (authenticated)
"""
from __future__ import annotations

import uuid
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.assessment import Assessment
from app.models.user import User
from app.reports import (
    PDFGenerationError,
    ReportData,
    build_report_html,
    build_report_pdf,
    build_sample_report,
)
from app.services import assessment_service

router = APIRouter(prefix="/reports", tags=["reports"])


class ReportFormat(str, Enum):
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
    return HTMLResponse(content=build_report_html(data))


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
