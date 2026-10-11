import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.assessment import Assessment, AssessmentStatus
from app.services import assessment_service
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

router = APIRouter(prefix="/assessments", tags=["scan"])


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
    """Get vulnerability findings for an assessment."""
    await assessment_service.get_assessment_or_404(db, assessment_id, current_user)
    return []  # populated by vulnerability pipeline + analyzers


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
