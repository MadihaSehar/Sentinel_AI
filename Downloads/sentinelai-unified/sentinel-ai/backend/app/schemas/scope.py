"""
Schemas for the Scope & Authorization configuration.

These models describe *what a user is allowed to test* before any
assessment is allowed to start. Nothing here executes anything — this
module is pure data validation. Enforcement happens in
app/core/scope_engine.py, which consumes a validated ScopeConfig.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AssessmentType(str, Enum):
    BUG_BOUNTY = "bug_bounty"
    PENTEST = "pentest"
    CTF = "ctf"
    LAB = "lab"


class AuthorizationStatus(str, Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    REVOKED = "revoked"
    EXPIRED = "expired"


# ---------------------------------------------------------------------------
# Domain / CIDR validation helpers
# ---------------------------------------------------------------------------

# Allows exact hosts (example.com) and single-level wildcard subdomain
# patterns (*.example.com). Does NOT allow "*.com" or bare "*".
_WILDCARD_DOMAIN_RE = re.compile(
    r"^(\*\.)?(?=.{1,253}$)[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)

_PUBLIC_SUFFIX_DENYLIST = {
    # Prevents someone accidentally (or deliberately) scoping the entire
    # internet via a dangerously broad wildcard.
    "*.com",
    "*.net",
    "*.org",
    "*.io",
    "*.gov",
    "*.edu",
    "*",
}


def _validate_domain_pattern(value: str) -> str:
    value = value.strip().lower()
    if value in _PUBLIC_SUFFIX_DENYLIST:
        raise ValueError(
            f"Domain pattern '{value}' is too broad and is not permitted as a scope rule."
        )
    if not _WILDCARD_DOMAIN_RE.match(value):
        raise ValueError(f"'{value}' is not a valid domain or wildcard-subdomain pattern.")
    # Reject wildcard-of-wildcard or multi-level wildcards like *.*.example.com
    if value.count("*") > 1:
        raise ValueError(f"'{value}' contains more than one wildcard; only '*.domain.tld' is allowed.")
    return value


def _validate_cidr(value: str) -> str:
    value = value.strip()
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"'{value}' is not a valid IP or CIDR range.") from exc

    # Block scoping the entire internet / default routes outright.
    if network.prefixlen == 0:
        raise ValueError(f"'{value}' covers an entire address space and is not permitted.")
    return str(network)


# ---------------------------------------------------------------------------
# Rule models
# ---------------------------------------------------------------------------


class DomainRule(BaseModel):
    pattern: str = Field(..., description="e.g. 'example.com' or '*.example.com'")

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, v: str) -> str:
        return _validate_domain_pattern(v)

    def matches(self, hostname: str) -> bool:
        hostname = hostname.strip().lower().rstrip(".")
        if self.pattern.startswith("*."):
            suffix = self.pattern[1:]  # ".example.com"
            return hostname.endswith(suffix) or hostname == self.pattern[2:]
        return hostname == self.pattern


class CIDRRule(BaseModel):
    cidr: str = Field(..., description="e.g. '10.0.0.0/8' or '192.168.1.10/32'")

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        return _validate_cidr(v)

    def matches(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            net = ipaddress.ip_network(self.cidr)
        except ValueError:
            return False
        return addr in net


class RateLimitConfig(BaseModel):
    requests_per_second: float = Field(5.0, gt=0, le=100)
    concurrency: int = Field(10, gt=0, le=200)
    scan_timeout_seconds: int = Field(3600, gt=0, le=86400 * 3)


class ScopeWindow(BaseModel):
    """Optional time window during which the assessment is permitted to run."""

    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None

    @model_validator(mode="after")
    def validate_window(self) -> "ScopeWindow":
        if self.starts_at and self.ends_at and self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be after starts_at")
        return self

    def is_active(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        if self.starts_at and now < self.starts_at:
            return False
        if self.ends_at and now > self.ends_at:
            return False
        return True


class AuthorizationRecord(BaseModel):
    """
    Explicit human sign-off that this assessment is authorized.
    An assessment cannot transition to RUNNING without this being CONFIRMED.
    """

    status: AuthorizationStatus = AuthorizationStatus.PENDING
    confirmed_by: Optional[str] = Field(None, description="user identifier who confirmed authorization")
    confirmed_at: Optional[datetime] = None
    statement: Optional[str] = Field(
        None,
        description="Free-text attestation, e.g. 'Authorized under BugCrowd program #1234' "
        "or 'I own this lab environment'.",
    )

    def is_confirmed(self, now: Optional[datetime] = None) -> bool:
        return self.status == AuthorizationStatus.CONFIRMED


class ScopeConfig(BaseModel):
    """
    The full, validated scope configuration for one assessment.
    This is the single source of truth consumed by the Scope Enforcement Layer.
    """

    id: UUID = Field(default_factory=uuid4)
    assessment_type: AssessmentType

    included_domains: list[DomainRule] = Field(default_factory=list)
    included_cidrs: list[CIDRRule] = Field(default_factory=list)

    excluded_domains: list[DomainRule] = Field(default_factory=list)
    excluded_cidrs: list[CIDRRule] = Field(default_factory=list)

    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    window: ScopeWindow = Field(default_factory=ScopeWindow)
    authorization: AuthorizationRecord = Field(default_factory=AuthorizationRecord)

    user_agent: str = Field(default="SentinelAI/1.0 (+authorized-assessment)")

    @model_validator(mode="after")
    def require_at_least_one_target(self) -> "ScopeConfig":
        if not self.included_domains and not self.included_cidrs:
            raise ValueError("At least one included domain or CIDR must be specified.")
        return self
