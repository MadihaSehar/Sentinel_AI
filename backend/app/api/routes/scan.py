import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.assessment import Assessment, AssessmentStatus
from app.models.finding import Finding
from app.services import assessment_service, findings_service
from app.schemas.finding_ingest import FindingIngestRequest
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

router = APIRouter(prefix="/assessments", tags=["scan"])


def _finding_to_response(f: Finding) -> "FindingResponse":
    return FindingResponse(
        id=str(f.id),
        title=f.title,
        category=f.category,
        cwe=f.cwe,
        owasp=f.owasp,
        severity=f.severity,
        confidence=f.consensus_confidence or 0.0,
        endpoint=f.endpoint,
        method=f.method,
        parameter=f.parameter,
        evidence=list(f.evidence or []),
        affected_assets=list(f.affected_assets or []),
        recommendation=f.recommendation or "",
        references=list(f.references or []),
        consensus_status=f.consensus_status,
        agreement_score=f.agreement_score or 0.0,
        model_count=len(f.participating_models or []),
        created_at=f.created_at.isoformat() if f.created_at else "",
    )


class PipelineStageResponse(BaseModel):
    name: str
    label: str
    status: str  # pending | running | done | skipped | error
    progress_percent: Optional[int] = None


class AssetResponse(BaseModel):
    id: str
    hostname: str
    ip_addresses: list[str] = []
    technologies: list[str] = []
    open_ports: list[int] = []
    http_status: Optional[int] = None
    discovered_at: str


class FindingResponse(BaseModel):
    # `model_count` would otherwise collide with Pydantic's protected
    # ``model_`` namespace and emit a warning; we don't use that namespace.
    model_config = {"protected_namespaces": ()}

    id: str
    title: str
    category: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    severity: str
    confidence: float
    endpoint: str
    method: str
    parameter: Optional[str] = None
    evidence: list[str] = []
    affected_assets: list[str] = []
    recommendation: str
    references: list[str] = []
    consensus_status: str = "REQUIRES_MANUAL_REVIEW"
    agreement_score: float = 0.0
    model_count: int = 0
    created_at: str


class ToolRunResponse(BaseModel):
    id: str
    tool_name: str
    target: str
    status: str
    started_at: str
    finished_at: Optional[str] = None
    result_count: Optional[int] = None


class AIDecisionResponse(BaseModel):
    id: str
    action: str
    target: str
    reason: str
    priority: str
    confidence: float
    created_at: str


# Pipeline stages for a default assessment
DEFAULT_STAGES = [
    PipelineStageResponse(name="recon", label="Recon", status="pending"),
    PipelineStageResponse(name="dns", label="DNS", status="pending"),
    PipelineStageResponse(name="http_discovery", label="HTTP Discovery", status="pending"),
    PipelineStageResponse(name="port_discovery", label="Port Discovery", status="pending"),
    PipelineStageResponse(name="crawler", label="Crawler", status="pending"),
    PipelineStageResponse(name="directory_scan", label="Directory Scan", status="pending"),
    PipelineStageResponse(name="nuclei", label="Nuclei", status="pending"),
    PipelineStageResponse(name="ai_analysis", label="AI Analysis", status="pending"),
    PipelineStageResponse(name="report", label="Report", status="pending"),
]


@router.get("/{assessment_id}/stages", response_model=list[PipelineStageResponse])
async def get_pipeline_stages(
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get pipeline stages for an assessment. Returns default stages structure."""
    await assessment_service.get_assessment_or_404(db, assessment_id, current_user)
    return DEFAULT_STAGES


@router.get("/{assessment_id}/assets", response_model=list[AssetResponse])
async def get_assets(
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get discovered assets for an assessment."""
    await assessment_service.get_assessment_or_404(db, assessment_id, current_user)
    return []  # populated by recon pipeline during actual scans


@router.get("/{assessment_id}/findings", response_model=list[FindingResponse])
async def get_findings(
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get persisted vulnerability findings for an assessment."""
    await assessment_service.get_assessment_or_404(db, assessment_id, current_user)
    rows = await findings_service.list_findings(db, assessment_id)
    return [_finding_to_response(f) for f in rows]


@router.post(
    "/{assessment_id}/findings",
    response_model=list[FindingResponse],
    status_code=status.HTTP_201_CREATED,
)
async def ingest_findings(
    assessment_id: uuid.UUID,
    payload: FindingIngestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Persist (replace) the findings for an assessment. This is the write path
    the vulnerability pipeline uses once candidates are scored; it is also how
    results are imported. Replace semantics keep a re-scan from duplicating.
    """
    await assessment_service.get_assessment_or_404(db, assessment_id, current_user)
    rows = await findings_service.set_findings(db, assessment_id, payload.findings)
    return [_finding_to_response(f) for f in rows]


@router.get("/{assessment_id}/tool-runs", response_model=list[ToolRunResponse])
async def get_tool_runs(
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get tool execution history for an assessment."""
    await assessment_service.get_assessment_or_404(db, assessment_id, current_user)
    return []


@router.get("/{assessment_id}/ai-analysis", response_model=list[AIDecisionResponse])
async def get_ai_analysis(
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get AI analysis decisions for an assessment."""
    await assessment_service.get_assessment_or_404(db, assessment_id, current_user)
    return []
