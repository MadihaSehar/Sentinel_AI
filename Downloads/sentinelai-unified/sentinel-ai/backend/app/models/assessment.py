import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, func, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


class AssessmentType(str, enum.Enum):
    BUG_BOUNTY = "bug_bounty"
    PENTEST = "pentest"
    CTF = "ctf"
    LAB = "lab"


class AssessmentStatus(str, enum.Enum):
    DRAFT = "draft"                 # created, not yet authorized to run
    AUTHORIZED = "authorized"        # authorization confirmed, not started
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"             # user-cancelled


class Assessment(Base):
    """
    An Assessment is one scan engagement. It is the unit that:
      - holds the authorization gate (`authorization_confirmed`)
      - holds rate-limit / concurrency / time-window governance
      - owns its ScopeRules
      - will own all discovered assets / findings in later phases

    Design decision — the authorization gate: `authorization_confirmed`
    must be explicitly set True (via a dedicated endpoint, not a generic
    PATCH) before status can move out of DRAFT. No tool execution code
    path is reachable for an assessment that isn't AUTHORIZED or later.
    This is enforced in the service layer, not just at the UI.
    """
    __tablename__ = "assessments"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)  # primary domain/app
    assessment_type: Mapped[AssessmentType] = mapped_column(Enum(AssessmentType), nullable=False)
    status: Mapped[AssessmentStatus] = mapped_column(
        Enum(AssessmentStatus), default=AssessmentStatus.DRAFT, nullable=False
    )

    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorization_confirmed_by: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id"), nullable=True
    )
    authorization_confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    # Governance — clamped server-side to Settings.MAX_SCAN_RATE_LIMIT /
    # MAX_SCAN_CONCURRENCY in the schema validator, never trusted as-is.
    rate_limit_rps: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    concurrency: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    user_agent: Mapped[str] = mapped_column(String(255), default="SentinelAI/1.0 (+authorized-assessment)")

    scan_window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    scan_window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    project: Mapped["Project"] = relationship(back_populates="assessments")
    scope_rules: Mapped[list["ScopeRule"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
