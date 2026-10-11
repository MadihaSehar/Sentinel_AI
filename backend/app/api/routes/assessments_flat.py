"""Flat assessment endpoints (no project_id in URL) for the dashboard."""
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.assessment import Assessment
from app.models.project import Project
from app.models.user import User
from app.schemas.assessment import AssessmentRead

router = APIRouter(prefix="/assessments", tags=["assessments-flat"])


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


@router.get("/{assessment_id}", response_model=AssessmentRead)
async def get_assessment(
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single assessment by ID."""
    from app.services import assessment_service
    return await assessment_service.get_assessment_or_404(db, assessment_id, current_user)
