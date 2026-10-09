import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.project import Project
from app.models.user import User
from app.schemas.project import ProjectCreate, ProjectRead

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
async def create_project(
    payload: ProjectCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Project:
    project = Project(owner_id=current_user.id, **payload.model_dump())
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return project


@router.get("", response_model=list[ProjectRead])
async def list_projects(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[Project]:
    result = await db.execute(select(Project).where(Project.owner_id == current_user.id))
    return list(result.scalars().all())


@router.get("/{project_id}", response_model=ProjectRead)
async def get_project(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Project:
    project = await _get_owned_project_or_404(project_id, db, current_user)
    return project


async def _get_owned_project_or_404(
    project_id: uuid.UUID, db: AsyncSession, current_user: User
) -> Project:
    result = await db.execute(
        select(Project).where(Project.id == project_id, Project.owner_id == current_user.id)
    )
    project = result.scalar_one_or_none()
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project
