import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


class Project(Base):
    """
    A Project is a container for one or more Assessments against the same
    client/engagement. Authorization documentation lives at this level so
    it is attached once and inherited by every assessment underneath it.
    """
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"))

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Free-text record of how authorization was granted (e.g. bug bounty
    # program URL, signed pentest agreement reference, lab environment note).
    # This does NOT grant authorization by itself — see ScopeRule / the
    # Assessment.authorization_confirmed gate for actual enforcement.
    authorization_reference: Mapped[str] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    owner: Mapped["User"] = relationship(back_populates="projects")
    assessments: Mapped[list["Assessment"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
