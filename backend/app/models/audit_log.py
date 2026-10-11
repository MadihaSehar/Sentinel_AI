import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class AuditLog(Base):
    """
    Append-only audit trail. Written for every authorization change,
    assessment lifecycle transition, and (in later phases) every tool
    execution and finding creation. Never stores secrets — only
    identifiers and a short human-readable description.
    """
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"), nullable=True)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("assessments.id"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g. "assessment.authorize"
    description: Mapped[str] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
