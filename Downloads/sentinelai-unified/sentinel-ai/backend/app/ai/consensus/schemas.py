"""
Data contracts for the Multi-Model Consensus Engine.

Each AI provider (Gemini, Grok, DeepSeek, ...) returns one ModelFinding per
piece of evidence it was asked to analyze. The ConsensusEngine combines these
independent ModelFindings into a single ConsensusResult.

These are intentionally strict/typed (Pydantic) because this output feeds
directly into risk scoring and report generation -- we never want a malformed
or partially-hallucinated AI response silently propagating downstream.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Ordinal rank so severities can be compared / averaged."""
        order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]

    @classmethod
    def from_rank(cls, rank: int) -> "Severity":
        order = [cls.INFO, cls.LOW, cls.MEDIUM, cls.HIGH, cls.CRITICAL]
        rank = max(0, min(len(order) - 1, round(rank)))
        return order[rank]


class ConsensusStatus(str, Enum):
    CONFIRMED = "confirmed"                    # strong agreement, high confidence
    LIKELY = "likely"                           # good agreement, moderate confidence
    REQUIRES_MANUAL_REVIEW = "requires_manual_review"  # disagreement or low confidence
    LIKELY_FALSE_POSITIVE = "likely_false_positive"    # strong agreement it's benign


class ModelFinding(BaseModel):
    """
    The normalized output of a single AI provider's analysis of one piece
    of evidence. Matches the structure described in section 11 of the spec.
    """

    model_name: str = Field(..., description="e.g. 'gemini', 'grok', 'deepseek'")
    finding: str = Field(..., description="Short description of what the model concluded")
    is_vulnerable: bool = Field(
        ..., description="Model's binary verdict: does evidence indicate a real vulnerability?"
    )
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning_summary: str = Field(
        ..., max_length=2000, description="Concise summary only -- never raw chain-of-thought"
    )
    evidence: list[str] = Field(default_factory=list)

    @field_validator("confidence")
    @classmethod
    def round_confidence(cls, v: float) -> float:
        return round(v, 4)


class PairwiseDisagreement(BaseModel):
    model_a: str
    model_b: str
    verdict_disagrees: bool
    severity_gap: int
    confidence_gap: float


class ConsensusResult(BaseModel):
    """
    The combined output of all participating models for a single candidate
    finding. This is what gets attached to a Finding / Evidence record and
    ultimately drives the Final Risk Score (section 13).
    """

    status: ConsensusStatus
    is_vulnerable_consensus: bool
    severity: Severity
    consensus_confidence: float = Field(..., ge=0.0, le=1.0)
    agreement_score: float = Field(
        ..., ge=0.0, le=1.0, description="1.0 = perfect agreement across all models"
    )
    participating_models: list[str]
    dissenting_models: list[str] = Field(default_factory=list)
    disagreements: list[PairwiseDisagreement] = Field(default_factory=list)
    model_findings: list[ModelFinding]
    summary: str

    model_config = {"use_enum_values": False}
