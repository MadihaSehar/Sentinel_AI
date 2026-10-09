"""
SentinelAI - Phase 6: Response Intelligence Engine
SQLAlchemy models for request/response storage (Section 16).

Tables: requests, responses, response_comparisons, security_indicators
All primary keys are UUIDs, per spec.
"""

from __future__ import annotations

import uuid

from sqlalchemy import (
    JSON,
    Boolean,
    CHAR,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    TypeDecorator,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, relationship


class GUID(TypeDecorator):
    """Platform-independent UUID type.

    Uses PostgreSQL's native UUID type in production, and falls back to a
    CHAR(36) column (storing the hex string) elsewhere -- e.g. SQLite,
    which is used for fast unit tests (see tests/conftest.py). This keeps
    the ORM models identical between the production Postgres DB (Section
    16: "Use UUIDs") and the lightweight SQLite test harness.
    """

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if dialect.name == "postgresql":
            return str(value)
        if not isinstance(value, uuid.UUID):
            return str(uuid.UUID(str(value)))
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(value)


class Base(DeclarativeBase):
    pass


def _uuid_col(primary_key: bool = False, fk: str | None = None):
    kwargs = dict(default=uuid.uuid4)
    if fk:
        return Column(GUID(), ForeignKey(fk), nullable=False)
    return Column(GUID(), primary_key=primary_key, **kwargs)


class RequestRecord(Base):
    __tablename__ = "requests"

    id = _uuid_col(primary_key=True)
    assessment_id = Column(GUID(), nullable=False, index=True)
    tool_run_id = Column(GUID(), nullable=True, index=True)
    method = Column(String(10), nullable=False)
    url = Column(Text, nullable=False)
    path = Column(Text, nullable=False)
    query_params = Column(JSON, default=dict)
    body_params = Column(JSON, default=dict)
    headers = Column(JSON, default=dict)
    cookies = Column(JSON, default=dict)
    raw_body = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    response = relationship(
        "ResponseRecord", back_populates="request", uselist=False,
        cascade="all, delete-orphan",
    )


class ResponseRecord(Base):
    __tablename__ = "responses"

    id = _uuid_col(primary_key=True)
    request_id = Column(
        GUID(), ForeignKey("requests.id"), nullable=False, unique=True, index=True
    )
    status_code = Column(Integer, nullable=False)
    headers = Column(JSON, default=dict)
    cookies = Column(JSON, default=dict)
    content_type = Column(String(255), nullable=True)
    body = Column(Text, default="")
    body_hash = Column(String(64), nullable=True, index=True)
    size_bytes = Column(Integer, default=0)
    elapsed_ms = Column(Float, default=0.0)
    redirect_chain = Column(JSON, default=list)
    auth_state = Column(String(32), default="unknown")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    request = relationship("RequestRecord", back_populates="response")


class ResponseComparisonRecord(Base):
    __tablename__ = "response_comparisons"

    id = _uuid_col(primary_key=True)
    assessment_id = Column(GUID(), nullable=False, index=True)
    baseline_response_id = Column(
        GUID(), ForeignKey("responses.id"), nullable=False
    )
    test_response_id = Column(
        GUID(), ForeignKey("responses.id"), nullable=False
    )
    status_code_match = Column(Boolean, default=False)
    status_code_delta = Column(Integer, default=0)
    length_delta = Column(Integer, default=0)
    length_ratio = Column(Float, default=0.0)
    text_similarity = Column(Float, default=0.0)
    structural_similarity = Column(Float, default=0.0)
    timing_delta_ms = Column(Float, default=0.0)
    timing_significant = Column(Boolean, default=False)
    header_diff = Column(JSON, default=dict)
    dom_diff = Column(JSON, default=dict)
    error_signature_match = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SecurityIndicatorRecord(Base):
    __tablename__ = "security_indicators"

    id = _uuid_col(primary_key=True)
    assessment_id = Column(GUID(), nullable=False, index=True)
    response_id = Column(GUID(), ForeignKey("responses.id"), nullable=False)
    kind = Column(String(64), nullable=False)
    description = Column(Text, nullable=False)
    confidence_hint = Column(Float, default=0.0)
    evidence_refs = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
