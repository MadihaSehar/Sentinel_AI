import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


class ScopeRuleType(str, enum.Enum):
    DOMAIN_INCLUDE = "domain_include"       # e.g. "*.example.com"
    DOMAIN_EXCLUDE = "domain_exclude"       # e.g. "admin.example.com"
    CIDR_INCLUDE = "cidr_include"           # e.g. "203.0.113.0/24"
    CIDR_EXCLUDE = "cidr_exclude"           # e.g. "10.0.0.0/8"


class ScopeRule(Base):
    """
    One row = one allow/deny rule for a single Assessment.

    Design decision: scope is modeled as an explicit list of include/exclude
    rules rather than a single "target" string, because real engagements
    almost always have carve-outs (e.g. "*.example.com" in scope but
    "admin.example.com" and all of 10.0.0.0/8 explicitly out of scope).
    Every rule belongs to exactly one assessment — scope is never implicit
    or inherited silently across assessments, since stale scope is a
    classic cause of out-of-scope testing.

    This table is consulted by the (future, Phase 2) ScopeEnforcer before
    any network operation is permitted to run. It has no enforcement logic
    itself — it's pure data. Enforcement is implemented once, centrally,
    not re-checked ad hoc in each scanner.
    """
    __tablename__ = "scope_rules"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )

    rule_type: Mapped[ScopeRuleType] = mapped_column(Enum(ScopeRuleType), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    assessment: Mapped["Assessment"] = relationship(back_populates="scope_rules")
