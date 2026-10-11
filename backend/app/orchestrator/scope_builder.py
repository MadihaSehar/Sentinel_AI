"""
Translate a persisted ``Assessment`` (+ its scope rules) into the
``ScopeConfig`` / ``ScopeEngine`` the scanning pipelines consume.

The DB stores scope as flat rows; the engine wants a validated ScopeConfig.
This is the single translation point, so the engine the pipelines run under
exactly reflects what the user authorized.
"""
from __future__ import annotations

from app.core.scope_engine import ScopeEngine
from app.models.assessment import Assessment
from app.models.scope_rule import ScopeRuleType
from app.schemas.scope import (
    AssessmentType,
    AuthorizationRecord,
    AuthorizationStatus,
    CIDRRule,
    DomainRule,
    RateLimitConfig,
    ScopeConfig,
)


def build_scope_config(assessment: Assessment) -> ScopeConfig:
    included_domains: list[DomainRule] = []
    excluded_domains: list[DomainRule] = []
    included_cidrs: list[CIDRRule] = []
    excluded_cidrs: list[CIDRRule] = []

    for rule in assessment.scope_rules:
        if rule.rule_type == ScopeRuleType.DOMAIN_INCLUDE:
            included_domains.append(DomainRule(pattern=rule.value))
        elif rule.rule_type == ScopeRuleType.DOMAIN_EXCLUDE:
            excluded_domains.append(DomainRule(pattern=rule.value))
        elif rule.rule_type == ScopeRuleType.CIDR_INCLUDE:
            included_cidrs.append(CIDRRule(cidr=rule.value))
        elif rule.rule_type == ScopeRuleType.CIDR_EXCLUDE:
            excluded_cidrs.append(CIDRRule(cidr=rule.value))

    # The target itself is always in scope — add it if the rules didn't.
    if not included_domains and not included_cidrs:
        included_domains.append(DomainRule(pattern=assessment.target))

    authorization = AuthorizationRecord(
        status=(
            AuthorizationStatus.CONFIRMED
            if assessment.authorization_confirmed
            else AuthorizationStatus.PENDING
        ),
        statement="Authorized via SentinelAI authorization gate"
        if assessment.authorization_confirmed
        else None,
    )

    return ScopeConfig(
        assessment_type=AssessmentType(
            getattr(assessment.assessment_type, "value", str(assessment.assessment_type))
        ),
        included_domains=included_domains,
        excluded_domains=excluded_domains,
        included_cidrs=included_cidrs,
        excluded_cidrs=excluded_cidrs,
        rate_limit=RateLimitConfig(
            requests_per_second=float(assessment.rate_limit_rps),
            concurrency=int(assessment.concurrency),
        ),
        authorization=authorization,
    )


def build_scope_engine(assessment: Assessment) -> ScopeEngine:
    return ScopeEngine(assessment.id, build_scope_config(assessment))
