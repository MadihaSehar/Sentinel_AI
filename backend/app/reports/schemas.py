"""
Data model for a generated security assessment report.

A ``ReportData`` instance is a fully self-contained, render-ready snapshot
of one assessment: it carries everything the HTML/PDF builder needs and
nothing that requires a database lookup. This keeps report rendering pure
and trivially testable, and lets us build a report from live scan data,
from fixtures, or from the bundled sample interchangeably.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    @property
    def cvss_band(self) -> str:
        return {
            "critical": "9.0 – 10.0",
            "high": "7.0 – 8.9",
            "medium": "4.0 – 6.9",
            "low": "0.1 – 3.9",
            "info": "0.0",
        }[self.value]


class ConsensusStatus(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    REQUIRES_MANUAL_REVIEW = "requires_manual_review"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"


class ReportFinding(BaseModel):
    title: str
    severity: Severity
    category: str
    cwe: str | None = None
    owasp: str | None = None
    endpoint: str
    method: str = "GET"
    parameter: str | None = None
    description: str
    evidence: list[str] = Field(default_factory=list)
    recommendation: str
    references: list[str] = Field(default_factory=list)
    # AI consensus metadata
    consensus_status: ConsensusStatus = ConsensusStatus.REQUIRES_MANUAL_REVIEW
    agreement_score: float = 0.0
    consensus_confidence: float = 0.0
    participating_models: list[str] = Field(default_factory=list)


class ReportAsset(BaseModel):
    hostname: str
    ip_addresses: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)


class ReportData(BaseModel):
    # --- Header / provenance ---
    target: str
    assessment_name: str
    assessment_type: str = "bug_bounty"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    authorized_by: str | None = None
    authorization_statement: str | None = None

    # --- Body ---
    findings: list[ReportFinding] = Field(default_factory=list)
    assets: list[ReportAsset] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)

    # --- Methodology (free-form, shown in the appendix) ---
    tools_used: list[str] = Field(default_factory=list)
    scan_duration_seconds: float | None = None

    # ------------------------------------------------------------------ #
    # Derived helpers (used by the renderer)
    # ------------------------------------------------------------------ #
    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def sorted_findings(self) -> list[ReportFinding]:
        """Most severe first, then by AI confidence."""
        return sorted(
            self.findings,
            key=lambda f: (f.severity.rank, f.consensus_confidence),
            reverse=True,
        )

    def risk_score(self) -> int:
        """
        A 0–100 aggregate risk score. Weighted by severity so a single
        critical dominates a pile of lows, and clamped to 100.
        """
        weights = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}
        counts = self.severity_counts()
        raw = sum(weights[sev] * n for sev, n in counts.items())
        return min(100, raw)

    def risk_rating(self) -> str:
        score = self.risk_score()
        if score >= 70:
            return "Critical"
        if score >= 40:
            return "High"
        if score >= 15:
            return "Medium"
        if score > 0:
            return "Low"
        return "Informational"
