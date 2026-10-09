"""
Assessment service layer.

Design decision: route handlers stay thin (HTTP concerns only); anything
with actual business logic — especially the authorization gate — lives
here so it can be unit-tested without spinning up FastAPI, and so there is
exactly one code path that can flip an assessment into an authorized,
runnable state.
"""
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.assessment import Assessment, AssessmentStatus
from app.models.audit_log import AuditLog
from app.models.scope_rule import ScopeRule, ScopeRuleType
from app.models.user import User
from app.schemas.assessment import AssessmentCreate, AuthorizationConfirmRequest


async def _write_audit_log(
    db: AsyncSession, *, user_id: uuid.UUID, assessment_id: uuid.UUID, action: str, description: str
) -> None:
    db.add(
        AuditLog(
            user_id=user_id,
            assessment_id=assessment_id,
            action=action,
            description=description,
        )
    )


async def create_assessment(
    db: AsyncSession, *, project_id: uuid.UUID, payload: AssessmentCreate, current_user: User
) -> Assessment:
    assessment = Assessment(
        project_id=project_id,
        name=payload.name,
        target=payload.target,
        assessment_type=payload.assessment_type,
        status=AssessmentStatus.DRAFT,
        authorization_confirmed=False,
        rate_limit_rps=payload.rate_limit_rps,
        concurrency=payload.concurrency,
    )
    db.add(assessment)
    await db.flush()  # populate assessment.id before attaching scope rules

    # The target itself is always an implicit include rule — a user cannot
    # define scope rules that somehow omit their own stated target.
    rule_values_seen: set[tuple[ScopeRuleType, str]] = set()

    def _add_rule(rule_type: ScopeRuleType, value: str) -> None:
        key = (rule_type, value)
        if key in rule_values_seen:
            return
        rule_values_seen.add(key)
        db.add(ScopeRule(assessment_id=assessment.id, rule_type=rule_type, value=value))

    _add_rule(ScopeRuleType.DOMAIN_INCLUDE, payload.target)
    for rule in payload.scope_rules:
        _add_rule(rule.rule_type, rule.value)

    await _write_audit_log(
        db,
        user_id=current_user.id,
        assessment_id=assessment.id,
        action="assessment.create",
        description=f"Created assessment '{assessment.name}' for target '{assessment.target}' "
        f"({len(rule_values_seen)} scope rules)",
    )

    await db.commit()
    return await get_assessment_or_404(db, assessment.id, current_user)


async def get_assessment_or_404(
    db: AsyncSession, assessment_id: uuid.UUID, current_user: User
) -> Assessment:
    result = await db.execute(
        select(Assessment)
        .join(Assessment.project)
        .where(Assessment.id == assessment_id, Assessment.project.has(owner_id=current_user.id))
        .options(selectinload(Assessment.scope_rules))
    )
    assessment = result.scalar_one_or_none()
    if assessment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")
    return assessment


async def authorize_assessment(
    db: AsyncSession,
    *,
    assessment_id: uuid.UUID,
    payload: AuthorizationConfirmRequest,
    current_user: User,
) -> Assessment:
    assessment = await get_assessment_or_404(db, assessment_id, current_user)

    if assessment.status != AssessmentStatus.DRAFT:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Assessment is already in status '{assessment.status.value}'; "
            "authorization can only be confirmed from DRAFT",
        )

    assessment.authorization_confirmed = True
    assessment.authorization_confirmed_by = current_user.id
    assessment.authorization_confirmed_at = datetime.now(timezone.utc)
    assessment.status = AssessmentStatus.AUTHORIZED

    await _write_audit_log(
        db,
        user_id=current_user.id,
        assessment_id=assessment.id,
        action="assessment.authorize",
        description=f"Authorization confirmed by user {current_user.email} for target "
        f"'{assessment.target}'",
    )

    await db.commit()
    await db.refresh(assessment)
    return assessment


async def list_assessments(
    db: AsyncSession, *, project_id: uuid.UUID, current_user: User
) -> list[Assessment]:
    result = await db.execute(
        select(Assessment)
        .join(Assessment.project)
        .where(Assessment.project_id == project_id, Assessment.project.has(owner_id=current_user.id))
        .options(selectinload(Assessment.scope_rules))
    )
    return list(result.scalars().unique().all())
