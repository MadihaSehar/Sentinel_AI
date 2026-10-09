"""
Phase 2 tests. These validate the layer every future scanner inherits:
scope matching (domain + CIDR, include/exclude), SSRF protection for the
platform's own network (always-blocked ranges vs. explicitly-scoped
private ranges), and the NetworkGate admission control (lifecycle status,
scan window, rate limit, concurrency).
"""
import asyncio
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models.assessment import Assessment, AssessmentStatus, AssessmentType
from app.models.scope_rule import ScopeRule, ScopeRuleType
from app.services.scope_enforcement import (
    NetworkGate,
    RateLimiter,
    ScopeEnforcer,
    ScopeViolationError,
)


def make_assessment(
    *,
    status: AssessmentStatus = AssessmentStatus.RUNNING,
    authorization_confirmed: bool = True,
    rate_limit_rps: int = 5,
    concurrency: int = 10,
    scan_window_start=None,
    scan_window_end=None,
    rules: list[tuple[ScopeRuleType, str]] = (),
) -> Assessment:
    assessment = Assessment(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        name="test",
        target="example.com",
        assessment_type=AssessmentType.BUG_BOUNTY,
        status=status,
        authorization_confirmed=authorization_confirmed,
        rate_limit_rps=rate_limit_rps,
        concurrency=concurrency,
        scan_window_start=scan_window_start,
        scan_window_end=scan_window_end,
    )
    assessment.scope_rules = [
        ScopeRule(id=uuid.uuid4(), assessment_id=assessment.id, rule_type=rt, value=v)
        for rt, v in rules
    ]
    return assessment


# --- domain matching ------------------------------------------------------

@pytest.mark.asyncio
async def test_wildcard_matches_subdomain_and_apex():
    enforcer = ScopeEnforcer()
    assessment = make_assessment(rules=[(ScopeRuleType.DOMAIN_INCLUDE, "*.example.com")])

    for host in ("foo.example.com", "a.b.example.com", "example.com"):
        decision = await enforcer.check_host(assessment, host)
        assert decision.allowed, f"{host} should be in scope"


@pytest.mark.asyncio
async def test_host_outside_wildcard_base_rejected():
    enforcer = ScopeEnforcer()
    assessment = make_assessment(rules=[(ScopeRuleType.DOMAIN_INCLUDE, "*.example.com")])

    decision = await enforcer.check_host(assessment, "example.org")
    assert not decision.allowed


@pytest.mark.asyncio
async def test_exact_domain_rule_does_not_match_subdomain():
    enforcer = ScopeEnforcer()
    assessment = make_assessment(rules=[(ScopeRuleType.DOMAIN_INCLUDE, "example.com")])

    decision = await enforcer.check_host(assessment, "sub.example.com")
    assert not decision.allowed


@pytest.mark.asyncio
async def test_exclude_overrides_include():
    enforcer = ScopeEnforcer()
    assessment = make_assessment(
        rules=[
            (ScopeRuleType.DOMAIN_INCLUDE, "*.example.com"),
            (ScopeRuleType.DOMAIN_EXCLUDE, "admin.example.com"),
        ]
    )

    allowed = await enforcer.check_host(assessment, "api.example.com")
    blocked = await enforcer.check_host(assessment, "admin.example.com")

    assert allowed.allowed
    assert not blocked.allowed
    assert "excluded" in blocked.reason


# --- IP literal / CIDR matching -------------------------------------------

@pytest.mark.asyncio
async def test_ip_literal_requires_explicit_cidr_include():
    enforcer = ScopeEnforcer()
    assessment = make_assessment(rules=[(ScopeRuleType.DOMAIN_INCLUDE, "*.example.com")])

    decision = await enforcer.check_host(assessment, "203.0.113.10")
    assert not decision.allowed
    assert "CIDR" in decision.reason


@pytest.mark.asyncio
async def test_ip_literal_matches_cidr_include():
    enforcer = ScopeEnforcer()
    assessment = make_assessment(rules=[(ScopeRuleType.CIDR_INCLUDE, "203.0.113.0/24")])

    decision = await enforcer.check_host(assessment, "203.0.113.10")
    assert decision.allowed


@pytest.mark.asyncio
async def test_cidr_exclude_carves_out_subrange():
    enforcer = ScopeEnforcer()
    assessment = make_assessment(
        rules=[
            (ScopeRuleType.CIDR_INCLUDE, "203.0.113.0/24"),
            (ScopeRuleType.CIDR_EXCLUDE, "203.0.113.128/25"),
        ]
    )

    in_range = await enforcer.check_host(assessment, "203.0.113.10")
    excluded = await enforcer.check_host(assessment, "203.0.113.200")

    assert in_range.allowed
    assert not excluded.allowed


# --- SSRF / always-blocked ranges ------------------------------------------

@pytest.mark.asyncio
async def test_loopback_always_blocked_even_with_cidr_include():
    enforcer = ScopeEnforcer()
    assessment = make_assessment(rules=[(ScopeRuleType.CIDR_INCLUDE, "127.0.0.0/8")])

    decision = await enforcer.check_host(assessment, "127.0.0.1")
    assert not decision.allowed
    assert "loopback" in decision.reason


@pytest.mark.asyncio
async def test_cloud_metadata_ip_always_blocked_even_with_cidr_include():
    enforcer = ScopeEnforcer()
    assessment = make_assessment(rules=[(ScopeRuleType.CIDR_INCLUDE, "169.254.0.0/16")])

    decision = await enforcer.check_host(assessment, "169.254.169.254")
    assert not decision.allowed
    assert "metadata" in decision.reason


@pytest.mark.asyncio
async def test_private_ip_blocked_without_explicit_cidr_include():
    enforcer = ScopeEnforcer()
    # Only a domain rule exists — no CIDR include at all.
    assessment = make_assessment(rules=[(ScopeRuleType.DOMAIN_INCLUDE, "*.example.com")])

    decision = await enforcer.check_host(assessment, "10.0.0.5")
    assert not decision.allowed
    assert "CIDR" in decision.reason


@pytest.mark.asyncio
async def test_private_ip_allowed_with_explicit_cidr_include():
    enforcer = ScopeEnforcer()
    assessment = make_assessment(rules=[(ScopeRuleType.CIDR_INCLUDE, "10.0.0.0/8")])

    decision = await enforcer.check_host(assessment, "10.0.0.5")
    assert decision.allowed


# --- resolve=True: resolved IPs re-checked against the same rules ---------

@pytest.mark.asyncio
async def test_resolve_blocks_domain_that_resolves_to_unscoped_private_ip():
    enforcer = ScopeEnforcer()
    assessment = make_assessment(rules=[(ScopeRuleType.DOMAIN_INCLUDE, "*.example.com")])

    async def fake_resolver(host: str) -> list[str]:
        return ["10.0.0.99"]  # simulates DNS rebinding / internal-pointing record

    decision = await enforcer.check_host(
        assessment, "sneaky.example.com", resolve=True, resolver=fake_resolver
    )
    assert not decision.allowed
    assert "SSRF" in decision.reason


@pytest.mark.asyncio
async def test_resolve_allows_domain_that_resolves_to_public_ip():
    enforcer = ScopeEnforcer()
    assessment = make_assessment(rules=[(ScopeRuleType.DOMAIN_INCLUDE, "*.example.com")])

    # 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — Python's ipaddress correctly
    # flags it as non-routable/private, so a genuinely public, globally
    # routable address is used here instead.
    async def fake_resolver(host: str) -> list[str]:
        return ["93.184.216.34"]

    decision = await enforcer.check_host(
        assessment, "www.example.com", resolve=True, resolver=fake_resolver
    )
    assert decision.allowed
    assert decision.resolved_ips == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_resolve_blocks_domain_that_resolves_to_loopback():
    enforcer = ScopeEnforcer()
    assessment = make_assessment(rules=[(ScopeRuleType.DOMAIN_INCLUDE, "*.example.com")])

    async def fake_resolver(host: str) -> list[str]:
        return ["127.0.0.1"]

    decision = await enforcer.check_host(
        assessment, "evil.example.com", resolve=True, resolver=fake_resolver
    )
    assert not decision.allowed


# --- NetworkGate: lifecycle + scan window ----------------------------------

@pytest.mark.asyncio
async def test_gate_rejects_draft_assessment():
    gate = NetworkGate(ScopeEnforcer(), RateLimiter())
    assessment = make_assessment(
        status=AssessmentStatus.DRAFT,
        authorization_confirmed=False,
        rules=[(ScopeRuleType.DOMAIN_INCLUDE, "*.example.com")],
    )

    with pytest.raises(ScopeViolationError, match="status"):
        async with gate.guard(assessment, "www.example.com", resolve=False):
            pytest.fail("should never reach the body")


@pytest.mark.asyncio
async def test_gate_rejects_authorized_but_not_started():
    # authorized=True but status is still AUTHORIZED, not QUEUED/RUNNING —
    # "authorize" and "start" are separate actions and the gate must
    # require both.
    gate = NetworkGate(ScopeEnforcer(), RateLimiter())
    assessment = make_assessment(
        status=AssessmentStatus.AUTHORIZED,
        authorization_confirmed=True,
        rules=[(ScopeRuleType.DOMAIN_INCLUDE, "*.example.com")],
    )

    with pytest.raises(ScopeViolationError, match="status"):
        async with gate.guard(assessment, "www.example.com", resolve=False):
            pytest.fail("should never reach the body")


@pytest.mark.asyncio
async def test_gate_allows_queued_in_scope_host():
    gate = NetworkGate(ScopeEnforcer(), RateLimiter())
    assessment = make_assessment(
        status=AssessmentStatus.QUEUED,
        rules=[(ScopeRuleType.DOMAIN_INCLUDE, "*.example.com")],
    )

    async with gate.guard(assessment, "www.example.com", resolve=False) as decision:
        assert decision.allowed


@pytest.mark.asyncio
async def test_gate_rejects_out_of_scope_host_even_when_running():
    gate = NetworkGate(ScopeEnforcer(), RateLimiter())
    assessment = make_assessment(
        status=AssessmentStatus.RUNNING,
        rules=[(ScopeRuleType.DOMAIN_INCLUDE, "*.example.com")],
    )

    with pytest.raises(ScopeViolationError):
        async with gate.guard(assessment, "not-in-scope.org", resolve=False):
            pytest.fail("should never reach the body")


@pytest.mark.asyncio
async def test_gate_rejects_outside_scan_window():
    gate = NetworkGate(ScopeEnforcer(), RateLimiter())
    now = datetime.now(timezone.utc)
    assessment = make_assessment(
        status=AssessmentStatus.RUNNING,
        scan_window_start=now + timedelta(hours=1),  # starts in the future
        rules=[(ScopeRuleType.DOMAIN_INCLUDE, "*.example.com")],
    )

    with pytest.raises(ScopeViolationError, match="scan window"):
        async with gate.guard(assessment, "www.example.com", resolve=False):
            pytest.fail("should never reach the body")


# --- RateLimiter: concurrency + interval -----------------------------------

@pytest.mark.asyncio
async def test_rate_limiter_enforces_concurrency_ceiling():
    limiter = RateLimiter()
    assessment_id = uuid.uuid4()
    concurrent_count = 0
    max_observed = 0

    async def worker():
        nonlocal concurrent_count, max_observed
        async with limiter.acquire(assessment_id, rate_limit_rps=1000, concurrency=2):
            concurrent_count += 1
            max_observed = max(max_observed, concurrent_count)
            await asyncio.sleep(0.05)
            concurrent_count -= 1

    await asyncio.gather(*(worker() for _ in range(6)))
    assert max_observed <= 2


@pytest.mark.asyncio
async def test_rate_limiter_enforces_minimum_interval():
    limiter = RateLimiter()
    assessment_id = uuid.uuid4()

    start = time.monotonic()
    for _ in range(3):
        async with limiter.acquire(assessment_id, rate_limit_rps=10, concurrency=10):
            pass
    elapsed = time.monotonic() - start

    # 3 acquisitions at 10 rps => at least 2 intervals of 0.1s between them
    assert elapsed >= 0.18
