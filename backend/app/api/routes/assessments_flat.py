"""Flat assessment endpoints (no project_id in URL) for the dashboard.

These are a thin convenience layer over the project-scoped
``/projects/{id}/assessments`` API. They let the dashboard drive the whole
create → authorize → start flow from one form without first picking a
project. The authorization gate is NOT bypassed here: the assessment is only
authorized when the form's explicit confirmation checkbox is set, and a scan
still cannot start until the assessment reaches AUTHORIZED. The same
service-layer functions (and therefore the same audit-log entries and scope
rules) back both the flat and the project-scoped routes.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.assessment import Assessment, AssessmentStatus, AssessmentType
from app.models.project import Project
from app.models.scope_rule import ScopeRuleType
from app.models.user import User
from app.orchestrator.scan_orchestrator import launch_scan
from app.schemas.assessment import (
    AssessmentCreate,
    AssessmentRead,
    AuthorizationConfirmRequest,
    ScopeRuleCreate,
)
from app.schemas.assessment_flat import FlatAssessmentCreate
from app.services import assessment_service

router = APIRouter(prefix="/assessments", tags=["assessments-flat"])

_DEFAULT_PROJECT_NAME = "Dashboard"

# Maps the UI's display labels (and already-normalized values) to the
# AssessmentType enum. Anything unrecognized is rejected.
_ASSESSMENT_TYPE_ALIASES = {
    "bug bounty": AssessmentType.BUG_BOUNTY,
    "bug_bounty": AssessmentType.BUG_BOUNTY,
    "pentest": AssessmentType.PENTEST,
    "ctf": AssessmentType.CTF,
    "lab": AssessmentType.LAB,
}


def _normalize_assessment_type(value: str) -> AssessmentType:
    key = (value or "").strip().lower()
    if key not in _ASSESSMENT_TYPE_ALIASES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown assessmentType '{value}'. "
            "Expected one of: Bug Bounty, Pentest, CTF, Lab.",
        )
    return _ASSESSMENT_TYPE_ALIASES[key]


async def _get_or_create_default_project(db: AsyncSession, current_user: User) -> Project:
    """
    The dashboard doesn't model projects, so flat-created assessments land in
    a single per-user 'Dashboard' project. Created on first use.
    """
    result = await db.execute(
        select(Project).where(
            Project.owner_id == current_user.id, Project.name == _DEFAULT_PROJECT_NAME
        )
    )
    project = result.scalars().first()
    if project is not None:
        return project

    project = Project(
        owner_id=current_user.id,
        name=_DEFAULT_PROJECT_NAME,
        description="Assessments created from the SentinelAI dashboard.",
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return project


def _scope_rules_from_flat(payload: FlatAssessmentCreate) -> list[ScopeRuleCreate]:
    rules: list[ScopeRuleCreate] = []
    for domain in payload.scope.allowedDomains:
        if domain.strip():
            rules.append(ScopeRuleCreate(rule_type=ScopeRuleType.DOMAIN_INCLUDE, value=domain))
    for cidr in payload.scope.allowedCidrs:
        if cidr.strip():
            rules.append(ScopeRuleCreate(rule_type=ScopeRuleType.CIDR_INCLUDE, value=cidr))
    for domain in payload.scope.excludedDomains:
        if domain.strip():
            rules.append(ScopeRuleCreate(rule_type=ScopeRuleType.DOMAIN_EXCLUDE, value=domain))
    for cidr in payload.scope.excludedCidrs:
        if cidr.strip():
            rules.append(ScopeRuleCreate(rule_type=ScopeRuleType.CIDR_EXCLUDE, value=cidr))
    return rules


@router.get("", response_model=list[AssessmentRead])
async def list_all_assessments(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all assessments across all projects owned by the current user."""
    result = await db.execute(
        select(Assessment)
        .join(Assessment.project)
        .where(Assessment.project.has(owner_id=current_user.id))
        .options(selectinload(Assessment.scope_rules))
    )
    return list(result.scalars().unique().all())


@router.post("", response_model=AssessmentRead, status_code=status.HTTP_201_CREATED)
async def create_assessment_flat(
    payload: FlatAssessmentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Create an assessment from the dashboard's single form.

    If ``scope.authorizationConfirmed`` is true, the assessment is also
    authorized in the same call (the form's explicit checkbox is the
    deliberate authorization step the typed-phrase endpoint enforces for raw
    API clients). Otherwise it is left in DRAFT and must be authorized before
    it can be started.
    """
    project = await _get_or_create_default_project(db, current_user)

    assessment_type = _normalize_assessment_type(payload.assessmentType)
    name = (payload.name or f"{payload.target} — {assessment_type.value}").strip()

    create_model = AssessmentCreate(
        name=name,
        target=payload.target,
        assessment_type=assessment_type,
        scope_rules=_scope_rules_from_flat(payload),
        rate_limit_rps=payload.scope.rateLimitPerSecond,
        concurrency=payload.scope.concurrency,
    )

    assessment = await assessment_service.create_assessment(
        db, project_id=project.id, payload=create_model, current_user=current_user
    )

    if payload.scope.authorizationConfirmed:
        await assessment_service.authorize_assessment(
            db,
            assessment_id=assessment.id,
            payload=AuthorizationConfirmRequest(
                confirmation_phrase="I CONFIRM AUTHORIZATION", acknowledgement=True
            ),
            current_user=current_user,
        )
        # Re-fetch so scope_rules is eagerly loaded for the response model
        # (authorize_assessment's refresh doesn't populate the relationship).
        assessment = await assessment_service.get_assessment_or_404(
            db, assessment.id, current_user
        )

    return assessment


@router.post("/{assessment_id}/start", response_model=AssessmentRead)
async def start_assessment_flat(
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Queue an authorized assessment and kick off the live scan pipeline.

    Mirrors the project-scoped start endpoint: it refuses to start anything
    that isn't AUTHORIZED, then dispatches the orchestrator (in-process, or to
    the Celery worker when USE_CELERY is set), which streams stage/progress
    events over the assessment's WebSocket.
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

    launch_scan(assessment_id)
    return assessment


@router.post("/{assessment_id}/stop", response_model=AssessmentRead)
async def stop_assessment_flat(
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Mark an assessment as user-cancelled."""
    assessment = await assessment_service.get_assessment_or_404(db, assessment_id, current_user)
    assessment.status = AssessmentStatus.STOPPED
    await db.commit()
    await db.refresh(assessment)
    return assessment


@router.get("/{assessment_id}", response_model=AssessmentRead)
async def get_assessment(
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single assessment by ID."""
    return await assessment_service.get_assessment_or_404(db, assessment_id, current_user)
