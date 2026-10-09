import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.assessment import Assessment, AssessmentStatus
from app.models.user import User
from app.schemas.assessment import AssessmentCreate, AssessmentRead, AuthorizationConfirmRequest
from app.schemas.scope import ScopeCheckRequest, ScopeCheckResponse
from app.services import assessment_service
from app.services.project_service import get_owned_project_or_404
from app.services.scope_enforcement import scope_enforcer

router = APIRouter(prefix="/projects/{project_id}/assessments", tags=["assessments"])


@router.post("", response_model=AssessmentRead, status_code=status.HTTP_201_CREATED)
async def create_assessment(
    project_id: uuid.UUID,
    payload: AssessmentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Assessment:
    await get_owned_project_or_404(db, project_id, current_user)  # 404s if not owner
    return await assessment_service.create_assessment(
        db, project_id=project_id, payload=payload, current_user=current_user
    )


@router.get("", response_model=list[AssessmentRead])
async def list_assessments(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[Assessment]:
    await get_owned_project_or_404(db, project_id, current_user)
    return await assessment_service.list_assessments(db, project_id=project_id, current_user=current_user)


@router.get("/{assessment_id}", response_model=AssessmentRead)
async def get_assessment(
    project_id: uuid.UUID,
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Assessment:
    return await assessment_service.get_assessment_or_404(db, assessment_id, current_user)


@router.post("/{assessment_id}/authorize", response_model=AssessmentRead)
async def authorize_assessment(
    project_id: uuid.UUID,
    assessment_id: uuid.UUID,
    payload: AuthorizationConfirmRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Assessment:
    """
    The ONLY endpoint that can move an assessment out of DRAFT. Requires an
    exact confirmation phrase plus an explicit acknowledgement boolean —
    see AuthorizationConfirmRequest. This is the authorization gate
    referenced throughout the architecture: no scan, recon, or tool
    execution code path (added in later phases) will be reachable for an
    assessment whose status is still DRAFT.
    """
    return await assessment_service.authorize_assessment(
        db, assessment_id=assessment_id, payload=payload, current_user=current_user
    )


@router.post("/{assessment_id}/start", response_model=AssessmentRead)
async def start_assessment(
    project_id: uuid.UUID,
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Assessment:
    """
    Phase 1 stub: flips status to QUEUED and writes an audit log entry.
    No tool execution is implemented yet — that begins in Phase 3
    (Recon) via the Celery worker and Tool Registry, which will itself
    re-check authorization_confirmed before running anything.
    """
    assessment = await assessment_service.get_assessment_or_404(db, assessment_id, current_user)
    if not assessment.authorization_confirmed or assessment.status != AssessmentStatus.AUTHORIZED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Assessment must be authorized (status=AUTHORIZED) before it can be started",
        )
    assessment.status = AssessmentStatus.QUEUED
    await db.commit()
    await db.refresh(assessment)
    return assessment


@router.post("/{assessment_id}/stop", response_model=AssessmentRead)
async def stop_assessment(
    project_id: uuid.UUID,
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Assessment:
    assessment = await assessment_service.get_assessment_or_404(db, assessment_id, current_user)
    assessment.status = AssessmentStatus.STOPPED
    await db.commit()
    await db.refresh(assessment)
    return assessment


@router.post("/{assessment_id}/scope/check", response_model=ScopeCheckResponse)
async def check_scope(
    project_id: uuid.UUID,
    assessment_id: uuid.UUID,
    payload: ScopeCheckRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScopeCheckResponse:
    """
    Lets a researcher validate their scope configuration directly — e.g.
    "is admin.example.com really excluded?" — before relying on it. Pure
    domain/CIDR pattern matching (resolve=false, the default) requires no
    authorization and performs no network I/O, so it's safe to use from
    DRAFT onward while still designing scope. Passing resolve=true performs
    a real DNS lookup against the host, so it requires the assessment to
    already be authorized — the same rule every future scanning tool will
    be held to via NetworkGate.
    """
    assessment = await assessment_service.get_assessment_or_404(db, assessment_id, current_user)

    if payload.resolve and not assessment.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="resolve=true performs a real DNS lookup against the target and requires "
            "the assessment to be authorized first",
        )

    decision = await scope_enforcer.check_host(assessment, payload.host, resolve=payload.resolve)
    return ScopeCheckResponse(
        host=payload.host,
        allowed=decision.allowed,
        reason=decision.reason,
        matched_rule=decision.matched_rule,
        resolved_ips=decision.resolved_ips,
    )
