"""
Request schema for ingesting findings into an assessment.

This is the shape the vulnerability pipeline (and the import endpoint) use to
persist results. It is intentionally close to the report's ReportFinding so
analyzers' output maps over with minimal translation.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, field_validator

_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class FindingIn(BaseModel):
    title: str
    category: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    severity: str
    status: str = "needs_review"

    endpoint: str
    method: str = "GET"
    parameter: Optional[str] = None

    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    recommendation: str = ""
    references: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)

    consensus_status: str = "requires_manual_review"
    agreement_score: float = Field(0.0, ge=0.0, le=1.0)
    consensus_confidence: float = Field(0.0, ge=0.0, le=1.0)
    participating_models: list[str] = Field(default_factory=list)

    analyzer_name: Optional[str] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in _SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(_SEVERITIES)}")
        return v


class FindingIngestRequest(BaseModel):
    """Replace the assessment's findings with this set (idempotent re-ingest)."""

    findings: list[FindingIn] = Field(default_factory=list)
