"""
Scope Enforcement Layer.

This is the single choke point that every reconnaissance/scanning/tool
action in SentinelAI must pass through before it is allowed to touch a
target. No scanner, analyzer, or AI-driven action may bypass this module.

Design goals:
- Fail closed: anything ambiguous or unauthorized is denied.
- Deterministic: no AI involvement in the decision to allow/deny traffic.
- Auditable: every decision is logged with a reason.
- Rate-limited: a token-bucket limiter is enforced per assessment.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from app.schemas.scope import ScopeConfig

logger = logging.getLogger("sentinel.scope_engine")


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    target: str
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __bool__(self) -> bool:
        return self.allowed


class ScopeViolation(Exception):
    """Raised when code attempts to act on a target that scope denies."""

    def __init__(self, decision: ScopeDecision):
        self.decision = decision
        super().__init__(f"Scope violation for '{decision.target}': {decision.reason}")


# ---------------------------------------------------------------------------
# Token-bucket rate limiter (per assessment)
# ---------------------------------------------------------------------------


class TokenBucketLimiter:
    """Simple async token-bucket limiter enforcing requests/sec and concurrency."""

    def __init__(self, requests_per_second: float, concurrency: int):
        self._rate = requests_per_second
        self._capacity = max(1.0, requests_per_second)
        self._tokens = self._capacity
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(concurrency)

    async def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_refill = now

    async def acquire(self) -> None:
        await self._semaphore.acquire()
        async with self._lock:
            while True:
                await self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(max(deficit, 0.001))

    def release(self) -> None:
        self._semaphore.release()

    def __aenter__(self):
        return self.acquire()

    async def __aexit__(self, *exc):
        self.release()


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------


class ScopeEngine:
    """
    Bound to a single assessment's ScopeConfig. Provides:
      - is_domain_allowed(hostname) -> ScopeDecision
      - is_ip_allowed(ip) -> ScopeDecision
      - resolve_and_check(hostname) -> ScopeDecision  (prevents DNS rebinding
        to an excluded/out-of-scope IP)
      - rate_limiter: TokenBucketLimiter bound to this assessment's config
      - guard(target) -> raises ScopeViolation if not allowed
    """

    def __init__(self, assessment_id: UUID, config: ScopeConfig):
        self.assessment_id = assessment_id
        self.config = config
        self.rate_limiter = TokenBucketLimiter(
            requests_per_second=config.rate_limit.requests_per_second,
            concurrency=config.rate_limit.concurrency,
        )
        self._audit: list[ScopeDecision] = []

    # -- authorization & window gates -------------------------------------

    def _authorization_gate(self) -> Optional[ScopeDecision]:
        if not self.config.authorization.is_confirmed():
            return ScopeDecision(
                allowed=False,
                reason=f"Authorization status is '{self.config.authorization.status.value}', "
                "not CONFIRMED. No active testing permitted.",
                target="*",
            )
        if not self.config.window.is_active():
            return ScopeDecision(
                allowed=False,
                reason="Current time is outside the authorized assessment window.",
                target="*",
            )
        return None

    # -- domain checks -------------------------------------------------------

    def is_domain_allowed(self, hostname: str) -> ScopeDecision:
        gate = self._authorization_gate()
        if gate is not None:
            return self._record(gate)

        hostname = hostname.strip().lower().rstrip(".")

        for rule in self.config.excluded_domains:
            if rule.matches(hostname):
                return self._record(
                    ScopeDecision(False, f"'{hostname}' matches excluded domain rule '{rule.pattern}'.", hostname)
                )

        for rule in self.config.included_domains:
            if rule.matches(hostname):
                return self._record(
                    ScopeDecision(True, f"'{hostname}' matches included domain rule '{rule.pattern}'.", hostname)
                )

        return self._record(
            ScopeDecision(False, f"'{hostname}' does not match any included domain rule.", hostname)
        )

    # -- IP checks -------------------------------------------------------------

    def is_ip_allowed(self, ip: str) -> ScopeDecision:
        gate = self._authorization_gate()
        if gate is not None:
            return self._record(gate)

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return self._record(ScopeDecision(False, f"'{ip}' is not a valid IP address.", ip))

        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
            # Private/internal ranges must be *explicitly* included (e.g. for
            # internal pentests); never allowed implicitly via a public-domain rule.
            explicitly_included = any(rule.matches(ip) for rule in self.config.included_cidrs)
            if not explicitly_included:
                return self._record(
                    ScopeDecision(
                        False,
                        f"'{ip}' is a private/internal/loopback address and was not explicitly "
                        "included in scope. This also blocks SSRF-style redirection to internal hosts.",
                        ip,
                    )
                )

        for rule in self.config.excluded_cidrs:
            if rule.matches(ip):
                return self._record(
                    ScopeDecision(False, f"'{ip}' matches excluded CIDR '{rule.cidr}'.", ip)
                )

        for rule in self.config.included_cidrs:
            if rule.matches(ip):
                return self._record(
                    ScopeDecision(True, f"'{ip}' matches included CIDR '{rule.cidr}'.", ip)
                )

        return self._record(
            ScopeDecision(False, f"'{ip}' does not match any included CIDR rule.", ip)
        )

    # -- combined resolve+check (anti DNS-rebinding / SSRF) -----------------

    async def resolve_and_check(self, hostname: str) -> ScopeDecision:
        """
        Checks the hostname pattern AND resolves it, then checks the
        resolved IP too. This prevents a scope-allowed domain from being
        used to pivot to an out-of-scope or internal IP via DNS tricks.
        """
        domain_decision = self.is_domain_allowed(hostname)
        if not domain_decision.allowed:
            return domain_decision

        loop = asyncio.get_event_loop()
        try:
            infos = await loop.run_in_executor(None, socket.getaddrinfo, hostname, None)
        except socket.gaierror as exc:
            return self._record(
                ScopeDecision(False, f"DNS resolution failed for '{hostname}': {exc}", hostname)
            )

        resolved_ips = {info[4][0] for info in infos}
        for ip in resolved_ips:
            ip_decision = self.is_ip_allowed(ip)
            if not ip_decision.allowed:
                return self._record(
                    ScopeDecision(
                        False,
                        f"'{hostname}' resolved to '{ip}', which is not allowed: {ip_decision.reason}",
                        hostname,
                    )
                )

        return self._record(
            ScopeDecision(True, f"'{hostname}' and all resolved IPs {sorted(resolved_ips)} are in scope.", hostname)
        )

    # -- enforcement helper ------------------------------------------------

    def guard(self, decision: ScopeDecision) -> None:
        """Raise if a decision denies access. Call this immediately before any I/O."""
        if not decision.allowed:
            logger.warning(
                "SCOPE DENIAL assessment=%s target=%s reason=%s",
                self.assessment_id,
                decision.target,
                decision.reason,
            )
            raise ScopeViolation(decision)

    # -- audit trail ---------------------------------------------------------

    def _record(self, decision: ScopeDecision) -> ScopeDecision:
        self._audit.append(decision)
        level = logging.INFO if decision.allowed else logging.WARNING
        logger.log(
            level,
            "assessment=%s target=%s allowed=%s reason=%s",
            self.assessment_id,
            decision.target,
            decision.allowed,
            decision.reason,
        )
        return decision

    @property
    def audit_log(self) -> list[ScopeDecision]:
        return list(self._audit)
