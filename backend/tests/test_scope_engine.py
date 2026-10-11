import asyncio
import time
from uuid import uuid4

import pytest

from app.core.scope_engine import ScopeEngine, ScopeViolation
from app.schemas.scope import (
    AssessmentType,
    AuthorizationRecord,
    AuthorizationStatus,
    RateLimitConfig,
    ScopeConfig,
)


def make_config(**overrides) -> ScopeConfig:
    defaults = dict(
        assessment_type=AssessmentType.BUG_BOUNTY,
        included_domains=[{"pattern": "*.example.com"}],
        excluded_domains=[{"pattern": "admin.example.com"}],
        included_cidrs=[{"cidr": "93.184.0.0/16"}],
        excluded_cidrs=[],
        authorization=AuthorizationRecord(status=AuthorizationStatus.CONFIRMED, confirmed_by="tester"),
        rate_limit=RateLimitConfig(requests_per_second=50, concurrency=5),
    )
    defaults.update(overrides)
    return ScopeConfig(**defaults)


def test_unauthorized_assessment_blocks_everything():
    cfg = make_config(authorization=AuthorizationRecord(status=AuthorizationStatus.PENDING))
    engine = ScopeEngine(uuid4(), cfg)
    decision = engine.is_domain_allowed("api.example.com")
    assert not decision.allowed
    assert "CONFIRMED" in decision.reason


def test_included_subdomain_allowed():
    cfg = make_config()
    engine = ScopeEngine(uuid4(), cfg)
    decision = engine.is_domain_allowed("api.example.com")
    assert decision.allowed


def test_excluded_subdomain_denied_even_if_parent_included():
    cfg = make_config()
    engine = ScopeEngine(uuid4(), cfg)
    decision = engine.is_domain_allowed("admin.example.com")
    assert not decision.allowed
    assert "excluded" in decision.reason


def test_out_of_scope_domain_denied():
    cfg = make_config()
    engine = ScopeEngine(uuid4(), cfg)
    decision = engine.is_domain_allowed("totally-different.com")
    assert not decision.allowed


def test_private_ip_denied_unless_explicitly_included():
    cfg = make_config()
    engine = ScopeEngine(uuid4(), cfg)
    decision = engine.is_ip_allowed("10.0.0.5")
    assert not decision.allowed
    assert "private" in decision.reason or "internal" in decision.reason


def test_private_ip_allowed_when_explicitly_included():
    cfg = make_config(included_cidrs=[{"cidr": "10.0.0.0/8"}])
    engine = ScopeEngine(uuid4(), cfg)
    decision = engine.is_ip_allowed("10.0.0.5")
    assert decision.allowed


def test_guard_raises_on_denied_decision():
    cfg = make_config()
    engine = ScopeEngine(uuid4(), cfg)
    decision = engine.is_domain_allowed("out-of-scope.net")
    with pytest.raises(ScopeViolation):
        engine.guard(decision)


def test_audit_log_records_every_decision():
    cfg = make_config()
    engine = ScopeEngine(uuid4(), cfg)
    engine.is_domain_allowed("api.example.com")
    engine.is_domain_allowed("nope.net")
    assert len(engine.audit_log) == 2


@pytest.mark.asyncio
async def test_rate_limiter_throttles_bursts():
    cfg = make_config(rate_limit=RateLimitConfig(requests_per_second=5, concurrency=10))
    engine = ScopeEngine(uuid4(), cfg)

    start = time.monotonic()
    for _ in range(10):
        await engine.rate_limiter.acquire()
        engine.rate_limiter.release()
    elapsed = time.monotonic() - start

    # 10 requests at 5/sec with a burst capacity of 5 should take at least ~1s
    assert elapsed >= 0.8


@pytest.mark.asyncio
async def test_resolve_and_check_rejects_out_of_scope_domain_without_dns():
    cfg = make_config()
    engine = ScopeEngine(uuid4(), cfg)
    decision = await engine.resolve_and_check("not-in-scope.net")
    assert not decision.allowed
