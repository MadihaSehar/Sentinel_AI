import pytest
from pydantic import ValidationError

from app.schemas.scope import (
    AssessmentType,
    CIDRRule,
    DomainRule,
    ScopeConfig,
)


def test_valid_domain_rule_matches_subdomains():
    rule = DomainRule(pattern="*.example.com")
    assert rule.matches("api.example.com")
    assert rule.matches("example.com")  # bare apex also matches by our definition
    assert not rule.matches("evilexample.com")
    assert not rule.matches("example.com.evil.net")


def test_exact_domain_rule_does_not_match_subdomains():
    rule = DomainRule(pattern="example.com")
    assert rule.matches("example.com")
    assert not rule.matches("api.example.com")


@pytest.mark.parametrize("bad", ["*.com", "*", "*.*.example.com", "not a domain", ""])
def test_rejects_overbroad_or_invalid_domain_patterns(bad):
    with pytest.raises(ValidationError):
        DomainRule(pattern=bad)


def test_cidr_rule_matches():
    rule = CIDRRule(cidr="10.0.0.0/8")
    assert rule.matches("10.1.2.3")
    assert not rule.matches("11.1.2.3")


def test_cidr_rejects_default_route():
    with pytest.raises(ValidationError):
        CIDRRule(cidr="0.0.0.0/0")


def test_scope_config_requires_at_least_one_target():
    with pytest.raises(ValidationError):
        ScopeConfig(assessment_type=AssessmentType.BUG_BOUNTY)


def test_scope_config_builds_with_valid_domain():
    cfg = ScopeConfig(
        assessment_type=AssessmentType.BUG_BOUNTY,
        included_domains=[{"pattern": "*.example.com"}],
        excluded_domains=[{"pattern": "admin.example.com"}],
    )
    assert cfg.included_domains[0].pattern == "*.example.com"
    assert cfg.rate_limit.requests_per_second == 5.0  # default
