"""
SentinelAI - Phase 7: Vulnerability Analyzers
Finding schema (Section 14: Vulnerability Evidence Model).

A FindingCandidate is deliberately NOT the same thing as a confirmed
vulnerability. Section 8 is explicit: "Do not claim a vulnerability
merely because a suspicious string appears. Require evidence." and
Section 13 requires an Evidence / Confidence / Exploitability / Impact
score before anything is treated as real. Analyzers in this phase only
ever produce candidates with status NEEDS_REVIEW -- promotion to
CONFIRMED happens in the (future) AI consensus + human-confirmation
stages, never here.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, enum.Enum):
    NEEDS_REVIEW = "needs_review"
    REQUIRES_MANUAL_REVIEW = "requires_manual_review"  # model/analyzer disagreement
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class VulnerabilityCategory(str, enum.Enum):
    SQL_INJECTION = "sql_injection"
    XSS_REFLECTED = "xss_reflected"
    OPEN_REDIRECT = "open_redirect"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    CLICKJACKING = "clickjacking"
    IDOR = "idor"


# category -> (default CWE, default OWASP Top 10 2021 category)
CATEGORY_MAPPING: dict[VulnerabilityCategory, tuple[str, str]] = {
    VulnerabilityCategory.SQL_INJECTION: ("CWE-89", "A03:2021 - Injection"),
    VulnerabilityCategory.XSS_REFLECTED: ("CWE-79", "A03:2021 - Injection"),
    VulnerabilityCategory.OPEN_REDIRECT: ("CWE-601", "A01:2021 - Broken Access Control"),
    VulnerabilityCategory.SECURITY_MISCONFIGURATION: (
        "CWE-16",
        "A05:2021 - Security Misconfiguration",
    ),
    VulnerabilityCategory.CORS_MISCONFIGURATION: (
        "CWE-942",
        "A05:2021 - Security Misconfiguration",
    ),
    VulnerabilityCategory.CLICKJACKING: ("CWE-1021", "A05:2021 - Security Misconfiguration"),
    VulnerabilityCategory.IDOR: ("CWE-639", "A01:2021 - Broken Access Control"),
}


class EvidenceItem(BaseModel):
    """One piece of supporting evidence. Always traceable back to a
    SecurityIndicator or raw response field -- never free-form assertion."""

    description: str
    source_indicator_kind: Optional[str] = None
    ref: Optional[str] = None  # response id, indicator id, etc.


class RiskScore(BaseModel):
    """Section 13: Evidence / Confidence / Exploitability / Impact / Final."""

    evidence_score: float = Field(ge=0.0, le=1.0)
    confidence_score: float = Field(ge=0.0, le=1.0)
    exploitability_score: float = Field(ge=0.0, le=1.0)
    impact_score: float = Field(ge=0.0, le=1.0)

    @property
    def final_risk_score(self) -> float:
        # Weighted blend: confidence gates everything (a low-confidence
        # finding should never score as high-risk no matter how severe
        # the theoretical impact would be).
        return round(
            (
                0.35 * self.confidence_score
                + 0.25 * self.evidence_score
                + 0.2 * self.exploitability_score
                + 0.2 * self.impact_score
            ),
            4,
        )


class FindingCandidate(BaseModel):
    """Matches Section 14's field list. 'candidate' because nothing here
    has gone through multi-model consensus or human confirmation yet."""

    id: UUID = Field(default_factory=uuid4)
    title: str
    category: VulnerabilityCategory
    cwe: str
    owasp: str
    severity: Severity
    status: FindingStatus = FindingStatus.NEEDS_REVIEW
    risk: RiskScore

    endpoint: str
    method: str
    parameter: Optional[str] = None

    evidence: list[EvidenceItem] = Field(default_factory=list)
    requests: list[UUID] = Field(default_factory=list)
    responses: list[UUID] = Field(default_factory=list)
    screenshots: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)

    recommendation: str
    references: list[str] = Field(default_factory=list)

    analyzer_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def confidence(self) -> float:
        return self.risk.confidence_score
