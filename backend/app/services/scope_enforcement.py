"""
Scope Enforcement Layer (Phase 2).

This is the component every future network-touching module — recon tools
in Phase 3, discovery/fuzzing in Phase 4, Nuclei in Phase 5, and so on —
must call before performing any operation against a host. It is built
once, here, and imported everywhere else; no scanner re-implements scope
checks itself.

Two independent checks compose into one decision:
  1. ScopeEnforcer.check_host — is this host covered by the assessment's
     scope_rules, and (optionally) does it resolve to an address that's
     safe to touch?
  2. NetworkGate.guard — wraps (1) plus assessment lifecycle status, scan
     window, and rate-limit/concurrency admission control, as a single
     async context manager a caller holds for the duration of one
     network operation.
"""
from __future__ import annotations

import asyncio
import ipaddress
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional

from app.core.network_safety import classify_always_blocked, is_private_range, is_valid_ip
from app.models.assessment import Assessment, AssessmentStatus
from app.models.scope_rule import ScopeRuleType

Resolver = Callable[[str], Awaitable[list[str]]]


# --- matching helpers ---------------------------------------------------

def _domain_matches(rule_value: str, host: str) -> bool:
    """
    "*.example.com" matches any subdomain ("a.example.com",
    "a.b.example.com") AND the bare base domain ("example.com") itself —
    this mirrors how bug-bounty programs conventionally write scope
    ("*.example.com" is understood to include the apex). An exact rule
    with no wildcard matches only that literal host.
    """
    rule_value = rule_value.lower().rstrip(".")
    host = host.lower().rstrip(".")
    if rule_value.startswith("*."):
        base = rule_value[2:]
        return host == base or host.endswith("." + base)
    return host == rule_value


def _cidr_matches(rule_value: str, ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(rule_value, strict=False)
    except ValueError:
        return False


async def _default_resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None)
    return sorted({info[4][0] for info in infos})


# --- decision result ------------------------------------------------------

@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    matched_rule: Optional[str] = None
    resolved_ips: list[str] = field(default_factory=list)


class ScopeEnforcer:
    async def check_host(
        self,
        assessment: Assessment,
        host: str,
        *,
        resolve: bool = False,
        resolver: Optional[Resolver] = None,
    ) -> ScopeDecision:
        rules = assessment.scope_rules
        domain_includes = [r.value for r in rules if r.rule_type == ScopeRuleType.DOMAIN_INCLUDE]
        domain_excludes = [r.value for r in rules if r.rule_type == ScopeRuleType.DOMAIN_EXCLUDE]
        cidr_includes = [r.value for r in rules if r.rule_type == ScopeRuleType.CIDR_INCLUDE]
        cidr_excludes = [r.value for r in rules if r.rule_type == ScopeRuleType.CIDR_EXCLUDE]

        host_norm = host.strip().lower().rstrip(".")

        if is_valid_ip(host_norm):
            return self._check_ip_literal(host_norm, cidr_includes, cidr_excludes)

        for rule in domain_excludes:
            if _domain_matches(rule, host_norm):
                return ScopeDecision(False, f"host explicitly excluded by domain rule '{rule}'", rule)

        matched_domain_rule = next(
            (r for r in domain_includes if _domain_matches(r, host_norm)), None
        )
        if matched_domain_rule is None:
            return ScopeDecision(False, "host is not covered by any domain include rule", None)

        if not resolve:
            return ScopeDecision(
                True, f"matched domain include rule '{matched_domain_rule}'", matched_domain_rule
            )

        resolve_fn = resolver or _default_resolve
        try:
            ips = await resolve_fn(host_norm)
        except Exception as exc:  # noqa: BLE001 — surfaced as a scope decision, not raised
            return ScopeDecision(False, f"DNS resolution failed: {exc}", matched_domain_rule)

        if not ips:
            return ScopeDecision(False, "DNS resolution returned no addresses", matched_domain_rule)

        for ip in ips:
            block_reason = classify_always_blocked(ip)
            if block_reason:
                return ScopeDecision(
                    False, f"resolved address {ip} blocked: {block_reason}", matched_domain_rule, ips
                )
            for rule in cidr_excludes:
                if _cidr_matches(rule, ip):
                    return ScopeDecision(
                        False,
                        f"resolved address {ip} explicitly excluded by CIDR rule '{rule}'",
                        rule,
                        ips,
                    )
            if is_private_range(ip) and not any(_cidr_matches(r, ip) for r in cidr_includes):
                return ScopeDecision(
                    False,
                    f"resolved address {ip} is a private-network address not explicitly "
                    "covered by a CIDR include rule — refusing to prevent SSRF against "
                    "internal networks",
                    matched_domain_rule,
                    ips,
                )

        return ScopeDecision(
            True,
            f"matched domain include rule '{matched_domain_rule}'; resolved addresses clear",
            matched_domain_rule,
            ips,
        )

    def _check_ip_literal(
        self, ip_str: str, cidr_includes: list[str], cidr_excludes: list[str]
    ) -> ScopeDecision:
        block_reason = classify_always_blocked(ip_str)
        if block_reason:
            return ScopeDecision(False, f"blocked: {block_reason}")

        for rule in cidr_excludes:
            if _cidr_matches(rule, ip_str):
                return ScopeDecision(False, f"explicitly excluded by CIDR rule '{rule}'", rule)

        matched = next((r for r in cidr_includes if _cidr_matches(r, ip_str)), None)
        if matched is None:
            return ScopeDecision(False, "address is not covered by any CIDR include rule", None)

        return ScopeDecision(True, f"matched CIDR include rule '{matched}'", matched)


# --- admission control: lifecycle status + scan window + rate/concurrency ---

class ScopeViolationError(Exception):
    """Raised by NetworkGate.guard when a network operation is not permitted."""


# Only these statuses represent an assessment the researcher has actively
# started. AUTHORIZED alone (authorized but not yet started) deliberately
# does NOT pass the gate — "authorize" and "start" are two separate,
# audited actions, and a tool should never run just because authorization
# exists if the researcher hasn't actually clicked start.
RUNNABLE_STATUSES = frozenset({AssessmentStatus.QUEUED, AssessmentStatus.RUNNING})


def _within_scan_window(assessment: Assessment) -> bool:
    now = datetime.now(timezone.utc)
    if assessment.scan_window_start and now < assessment.scan_window_start:
        return False
    if assessment.scan_window_end and now > assessment.scan_window_end:
        return False
    return True


@dataclass
class _AssessmentLimiterState:
    semaphore: asyncio.Semaphore
    min_interval: float
    lock: asyncio.Lock
    last_request_at: float = 0.0


class RateLimiter:
    """
    In-memory, single-process token-interval + concurrency limiter, keyed
    per assessment. This is intentionally simple for Phase 2: Phase 3
    introduces Celery workers, at which point this becomes a Redis-backed
    limiter so the limit holds across multiple worker processes — the
    `acquire()` call signature is designed to stay the same so that swap
    is transparent to every caller (NetworkGate and, later, each Tool).
    """

    def __init__(self) -> None:
        self._states: dict[uuid.UUID, _AssessmentLimiterState] = {}
        self._registry_lock = asyncio.Lock()

    async def _get_state(
        self, assessment_id: uuid.UUID, rate_limit_rps: int, concurrency: int
    ) -> _AssessmentLimiterState:
        async with self._registry_lock:
            state = self._states.get(assessment_id)
            if state is None:
                state = _AssessmentLimiterState(
                    semaphore=asyncio.Semaphore(max(concurrency, 1)),
                    min_interval=1.0 / max(rate_limit_rps, 1),
                    lock=asyncio.Lock(),
                )
                self._states[assessment_id] = state
            return state

    def reset(self, assessment_id: uuid.UUID) -> None:
        """Used by tests, and by the (future) assessment-stop handler to
        release limiter state once an assessment ends."""
        self._states.pop(assessment_id, None)

    @asynccontextmanager
    async def acquire(self, assessment_id: uuid.UUID, rate_limit_rps: int, concurrency: int):
        state = await self._get_state(assessment_id, rate_limit_rps, concurrency)
        async with state.semaphore:
            async with state.lock:
                wait = state.min_interval - (time.monotonic() - state.last_request_at)
                if wait > 0:
                    await asyncio.sleep(wait)
                state.last_request_at = time.monotonic()
            yield


class NetworkGate:
    """
    The single entry point every future tool/scanner call must go through.
    Usage (Phase 3+):

        async with network_gate.guard(assessment, "sub.example.com") as decision:
            ... perform the actual bounded network operation ...

    Raises ScopeViolationError before any network I/O happens if the
    assessment isn't in a runnable state, is outside its scan window, or
    the host fails scope/SSRF checks. Only once all of that passes does it
    acquire a rate-limit/concurrency slot and yield.
    """

    def __init__(self, enforcer: ScopeEnforcer, limiter: RateLimiter) -> None:
        self._enforcer = enforcer
        self._limiter = limiter

    @asynccontextmanager
    async def guard(
        self,
        assessment: Assessment,
        host: str,
        *,
        resolve: bool = True,
        resolver: Optional[Resolver] = None,
    ):
        if assessment.status not in RUNNABLE_STATUSES:
            raise ScopeViolationError(
                f"assessment status is '{assessment.status.value}' — network operations are "
                f"only permitted while QUEUED or RUNNING (authorize, then start, the assessment)"
            )
        if not assessment.authorization_confirmed:
            # Defense in depth: status alone should never reach RUNNABLE
            # without this also being true, but we check both explicitly
            # since this is the one invariant the whole platform leans on.
            raise ScopeViolationError("assessment authorization is not confirmed")
        if not _within_scan_window(assessment):
            raise ScopeViolationError("current time is outside the assessment's configured scan window")

        decision = await self._enforcer.check_host(assessment, host, resolve=resolve, resolver=resolver)
        if not decision.allowed:
            raise ScopeViolationError(decision.reason)

        async with self._limiter.acquire(assessment.id, assessment.rate_limit_rps, assessment.concurrency):
            yield decision


# Module-level singletons — one enforcer/limiter/gate per process, shared
# by every route and (from Phase 3 on) every tool invocation.
scope_enforcer = ScopeEnforcer()
rate_limiter = RateLimiter()
network_gate = NetworkGate(scope_enforcer, rate_limiter)
