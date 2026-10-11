"""
SentinelAI - Phase 7: Vulnerability Analyzers
Analyzer registry + orchestrator.

Mirrors Section 6's "Do NOT always run every tool" philosophy, but at
the analyzer level: each analyzer's cheap applies_to() check decides
whether it runs at all, so an exchange with no reflection indicators
never pays for XSS analysis, etc. Adding a new analyzer later (Section
8 lists many more categories: SSRF, LFI, SSTI, XXE, deserialization...)
means writing one more ExchangeAnalyzer/ComparativeAnalyzer and
registering it here -- the orchestrator and callers never change.
"""

from __future__ import annotations

from app.analyzers.base import ComparativeAnalyzer, ExchangeAnalyzer
from app.analyzers.idor import IdorAnalyzer
from app.analyzers.open_redirect import OpenRedirectAnalyzer
from app.analyzers.reflected_xss import ReflectedXssAnalyzer
from app.analyzers.security_headers import SecurityHeadersAnalyzer
from app.analyzers.sql_injection import SqlInjectionAnalyzer
from app.schemas.finding import FindingCandidate
from app.schemas.response_intel import AnalyzedExchange

# Registration order has no effect on results; analyzers are independent.
EXCHANGE_ANALYZERS: list[ExchangeAnalyzer] = [
    ReflectedXssAnalyzer(),
    SqlInjectionAnalyzer(),
    OpenRedirectAnalyzer(),
    SecurityHeadersAnalyzer(),  # duck-typed, not a formal ExchangeAnalyzer subclass
]

COMPARATIVE_ANALYZERS: list[ComparativeAnalyzer] = [
    IdorAnalyzer(),
]


def analyze_exchange(exchange: AnalyzedExchange) -> list[FindingCandidate]:
    """Run every applicable single-exchange analyzer and collect results."""
    findings: list[FindingCandidate] = []
    for analyzer in EXCHANGE_ANALYZERS:
        try:
            if analyzer.applies_to(exchange):
                findings.extend(analyzer.analyze(exchange))
        except Exception as exc:  # noqa: BLE001 - one analyzer's bug must not kill the run
            findings.append(_analyzer_error_as_info_finding(analyzer.name, exchange, exc))
    return findings


def analyze_exchange_pair(
    exchange_a: AnalyzedExchange, exchange_b: AnalyzedExchange
) -> list[FindingCandidate]:
    """Run every applicable comparative analyzer over a pair of exchanges."""
    findings: list[FindingCandidate] = []
    for analyzer in COMPARATIVE_ANALYZERS:
        try:
            if analyzer.applies_to(exchange_a, exchange_b):
                findings.extend(analyzer.analyze(exchange_a, exchange_b))
        except Exception as exc:  # noqa: BLE001
            findings.append(
                _analyzer_error_as_info_finding(analyzer.name, exchange_a, exc)
            )
    return findings


def analyze_batch(exchanges: list[AnalyzedExchange]) -> list[FindingCandidate]:
    """Convenience: run single-exchange analyzers over every exchange in
    a batch (e.g. everything captured so far for an assessment)."""
    findings: list[FindingCandidate] = []
    for exchange in exchanges:
        findings.extend(analyze_exchange(exchange))
    return findings


def _analyzer_error_as_info_finding(
    analyzer_name: str, exchange: AnalyzedExchange, exc: Exception
) -> FindingCandidate:
    """An analyzer crashing is itself worth recording (Section 22:
    everything must be auditable) rather than silently dropped, but it
    must never masquerade as a real vulnerability finding -- hence
    INFO severity, zeroed risk, and a distinct category is avoided by
    reusing SECURITY_MISCONFIGURATION with explicit framing in the title."""
    from app.schemas.finding import (
        CATEGORY_MAPPING,
        EvidenceItem,
        RiskScore,
        Severity,
        VulnerabilityCategory,
    )

    cwe, owasp = CATEGORY_MAPPING[VulnerabilityCategory.SECURITY_MISCONFIGURATION]
    return FindingCandidate(
        title=f"[analyzer error] {analyzer_name} raised an exception",
        category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
        cwe=cwe,
        owasp=owasp,
        severity=Severity.INFO,
        risk=RiskScore(
            evidence_score=0.0,
            confidence_score=0.0,
            exploitability_score=0.0,
            impact_score=0.0,
        ),
        endpoint=exchange.request.path,
        method=exchange.request.method.value,
        evidence=[EvidenceItem(description=str(exc))],
        requests=[exchange.request.id],
        responses=[exchange.response.id],
        recommendation="Investigate analyzer failure; not a security finding.",
        analyzer_name=analyzer_name,
    )
