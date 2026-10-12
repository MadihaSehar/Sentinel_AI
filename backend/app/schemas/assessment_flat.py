"""
Flat (project-less) request schemas for the dashboard.

The dashboard presents a single "New Assessment" form rather than the
project → assessment → authorize → start flow the REST API models
explicitly. These schemas let the dashboard POST that one form; the flat
route translates them into the same project-scoped service calls, so the
authorization gate and scope rules are enforced identically. Nothing here
weakens that gate: an assessment is still only authorized when
``scope.authorizationConfirmed`` is explicitly true (the form's checkbox),
and a scan still cannot start until the assessment is AUTHORIZED.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from app.core.config import get_settings

settings = get_settings()


class FlatScope(BaseModel):
    """Scope + governance as the dashboard form submits it (camelCase)."""

    allowedDomains: list[str] = Field(default_factory=list)
    allowedCidrs: list[str] = Field(default_factory=list)
    excludedDomains: list[str] = Field(default_factory=list)
    excludedCidrs: list[str] = Field(default_factory=list)
    rateLimitPerSecond: int = Field(default=settings.DEFAULT_SCAN_RATE_LIMIT, ge=1)
    concurrency: int = Field(default=settings.DEFAULT_SCAN_CONCURRENCY, ge=1)
    authorizationConfirmed: bool = False


class FlatAssessmentCreate(BaseModel):
    """The dashboard's single-form create payload."""

    target: str
    # Accepts the UI labels ("Bug Bounty", "Pentest", "CTF", "Lab") or the
    # raw enum values ("bug_bounty", ...); normalized in the route.
    assessmentType: str
    name: str | None = None
    scope: FlatScope = Field(default_factory=FlatScope)
