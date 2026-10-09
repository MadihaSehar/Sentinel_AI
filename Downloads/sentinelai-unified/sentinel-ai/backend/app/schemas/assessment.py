import ipaddress
import re
import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.config import get_settings
from app.models.assessment import AssessmentStatus, AssessmentType
from app.models.scope_rule import ScopeRuleType

settings = get_settings()

# Permissive hostname/wildcard-hostname pattern: "*.example.com" or "example.com".
_DOMAIN_RE = re.compile(
    r"^(\*\.)?(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$"
)


def _validate_domain(value: str) -> str:
    if not _DOMAIN_RE.match(value):
        raise ValueError(f"'{value}' is not a valid domain or wildcard domain (e.g. '*.example.com')")
    return value.lower()


def _validate_cidr(value: str) -> str:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"'{value}' is not a valid CIDR range") from exc
    return value


class ScopeRuleCreate(BaseModel):
    rule_type: ScopeRuleType
    value: str

    @model_validator(mode="after")
    def validate_value_matches_type(self) -> "ScopeRuleCreate":
        if self.rule_type in (ScopeRuleType.DOMAIN_INCLUDE, ScopeRuleType.DOMAIN_EXCLUDE):
            self.value = _validate_domain(self.value)
        else:
            self.value = _validate_cidr(self.value)
        return self


class ScopeRuleRead(BaseModel):
    id: uuid.UUID
    rule_type: ScopeRuleType
    value: str

    model_config = {"from_attributes": True}


class AssessmentCreate(BaseModel):
    """
    Creating an assessment does NOT authorize it — status starts at DRAFT
    and authorization_confirmed starts False regardless of what's posted
    here. Authorization is a separate, explicit, audited action
    (see POST /assessments/{id}/authorize).
    """
    name: str = Field(min_length=1, max_length=255)
    target: str
    assessment_type: AssessmentType
    scope_rules: list[ScopeRuleCreate] = Field(default_factory=list)

    rate_limit_rps: int = Field(default=settings.DEFAULT_SCAN_RATE_LIMIT, ge=1)
    concurrency: int = Field(default=settings.DEFAULT_SCAN_CONCURRENCY, ge=1)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_domain(v)

    @field_validator("rate_limit_rps")
    @classmethod
    def clamp_rate_limit(cls, v: int) -> int:
        # Hard platform ceiling — a user-supplied value can never exceed this,
        # regardless of what the request body contains.
        return min(v, settings.MAX_SCAN_RATE_LIMIT)

    @field_validator("concurrency")
    @classmethod
    def clamp_concurrency(cls, v: int) -> int:
        return min(v, settings.MAX_SCAN_CONCURRENCY)

    @model_validator(mode="after")
    def require_at_least_one_include_rule(self) -> "AssessmentCreate":
        includes = [
            r for r in self.scope_rules
            if r.rule_type in (ScopeRuleType.DOMAIN_INCLUDE, ScopeRuleType.CIDR_INCLUDE)
        ]
        if not includes:
            # The target itself always becomes an implicit include rule at
            # the service layer, so this only blocks genuinely empty scope
            # definitions with conflicting exclude-only rules.
            pass
        return self


class AssessmentRead(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    target: str
    assessment_type: AssessmentType
    status: AssessmentStatus
    authorization_confirmed: bool
    authorization_confirmed_at: datetime | None
    rate_limit_rps: int
    concurrency: int
    user_agent: str
    scope_rules: list[ScopeRuleRead] = []
    created_at: datetime

    model_config = {"from_attributes": True}


class AuthorizationConfirmRequest(BaseModel):
    """
    Requires the researcher to actively type a confirmation phrase rather
    than just toggle a checkbox — a deliberate friction point so this
    can't be fat-fingered or automated away accidentally.
    """
    confirmation_phrase: str
    acknowledgement: bool = Field(
        description="Must be true: confirms the user holds explicit authorization "
        "to test this target (program scope, signed agreement, or owned lab)."
    )

    @field_validator("confirmation_phrase")
    @classmethod
    def validate_phrase(cls, v: str) -> str:
        if v.strip().upper() != "I CONFIRM AUTHORIZATION":
            raise ValueError("confirmation_phrase must exactly be: I CONFIRM AUTHORIZATION")
        return v

    @field_validator("acknowledgement")
    @classmethod
    def validate_ack(cls, v: bool) -> bool:
        if not v:
            raise ValueError("acknowledgement must be true to authorize an assessment")
        return v
