"""
SentinelAI - Phase 6: Response Intelligence Engine
Schemas: normalized request/response/features/comparison structures.

These are pure data contracts (Pydantic models). No network or execution
code lives here -- this module only describes shapes that the storage,
similarity, reflection, and DOM-analysis modules operate on.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AuthState(str, enum.Enum):
    UNKNOWN = "unknown"
    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATED = "authenticated"


class HttpMethod(str, enum.Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class NormalizedRequest(BaseModel):
    """A single captured HTTP request, already executed by a registered
    SecurityTool (never constructed ad-hoc by an LLM)."""

    id: UUID = Field(default_factory=uuid4)
    assessment_id: UUID
    method: HttpMethod
    url: str
    path: str
    query_params: dict[str, str] = Field(default_factory=dict)
    body_params: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    raw_body: Optional[str] = None
    tool_run_id: Optional[UUID] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class NormalizedResponse(BaseModel):
    """A single captured HTTP response paired 1:1 with a NormalizedRequest."""

    id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    content_type: Optional[str] = None
    body: str = ""
    body_hash: Optional[str] = None
    size_bytes: int = 0
    elapsed_ms: float = 0.0
    redirect_chain: list[str] = Field(default_factory=list)
    auth_state: AuthState = AuthState.UNKNOWN
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReflectionPoint(BaseModel):
    """One location where attacker-influenced input reappeared in a
    response. Produced by reflection.py -- never fabricated."""

    parameter: str
    marker: str
    context: str  # e.g. "html_body", "html_attribute", "js_string", "header", "json_value"
    position: int
    surrounding: str  # small snippet around the reflection for evidence
    encoded: bool = False
    html_escaped: bool = False


class DomDiff(BaseModel):
    """Structural difference between a baseline DOM and a test DOM."""

    nodes_added: int = 0
    nodes_removed: int = 0
    nodes_changed: int = 0
    new_script_tags: int = 0
    new_event_handlers: list[str] = Field(default_factory=list)
    added_elements_sample: list[str] = Field(default_factory=list)
    removed_elements_sample: list[str] = Field(default_factory=list)


class ResponseComparison(BaseModel):
    """Deterministic baseline-vs-test comparison. This is the evidence
    the AI Orchestrator consumes -- it must never substitute for this."""

    baseline_response_id: UUID
    test_response_id: UUID
    status_code_match: bool
    status_code_delta: int
    length_delta: int
    length_ratio: float
    text_similarity: float  # 0.0 (totally different) - 1.0 (identical)
    structural_similarity: float
    timing_delta_ms: float
    timing_significant: bool
    header_diff: dict[str, Any] = Field(default_factory=dict)
    dom_diff: Optional[DomDiff] = None
    error_signature_match: Optional[str] = None


class SecurityIndicator(BaseModel):
    """A single, narrowly-scoped observation (NOT a finding/vulnerability
    claim). Multiple indicators are later aggregated by the false-positive
    engine and AI consensus layer before anything becomes a Finding."""

    kind: str  # e.g. "reflection", "error_signature", "timing_anomaly", "status_anomaly"
    description: str
    confidence_hint: float = Field(ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(default_factory=list)


class AnalyzedExchange(BaseModel):
    """The full normalized structure described in Section 9 of the spec:
    { request, response, features, comparison, security_indicators }."""

    request: NormalizedRequest
    response: NormalizedResponse
    features: dict[str, Any] = Field(default_factory=dict)
    comparison: Optional[ResponseComparison] = None
    security_indicators: list[SecurityIndicator] = Field(default_factory=list)
