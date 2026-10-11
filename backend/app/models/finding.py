"""
Persisted vulnerability finding.

One row per finding attached to an assessment. This is the durable record
the vulnerability pipeline writes once a candidate has been scored/consensus-
reviewed, and the single source the findings API, reports and scan-to-scan
diff read from.

Column types stay portable (generic ``Uuid`` + ``JSON``) so the same schema
runs on Postgres in production and SQLite in tests.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owasp: Mapped[str | None] = mapped_column(String(100), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="needs_review", nullable=False)

    endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str] = mapped_column(String(10), default="GET", nullable=False)
    parameter: Mapped[str | None] = mapped_column(String(255), nullable=True)

    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    recommendation: Mapped[str] = mapped_column(Text, default="")
    # `references` is a SQL reserved word, so store under a safe column name.
    references: Mapped[list] = mapped_column("reference_urls", JSON, default=list)
    affected_assets: Mapped[list] = mapped_column(JSON, default=list)

    # AI consensus metadata.
    consensus_status: Mapped[str] = mapped_column(
        String(32), default="requires_manual_review", nullable=False
    )
    agreement_score: Mapped[float] = mapped_column(Float, default=0.0)
    consensus_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    participating_models: Mapped[list] = mapped_column(JSON, default=list)

    analyzer_name: Mapped[str | None] = mapped_column(String(100), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
