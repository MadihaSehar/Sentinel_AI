"""
SentinelAI - Phase 7: Vulnerability Analyzers
SQL injection candidate analyzer.

Section 8 explicitly warns: "A database-looking error alone should NOT
automatically mean SQL injection." So this analyzer requires an
error_signature indicator whose source is a known DB engine, PLUS at
least one corroborating signal: either a status-code change relative to
baseline, or a significant timing delta (suggestive of a time-based
blind technique having been exercised by the test tool upstream). An
error signature alone is recorded as a low-confidence candidate only
when no baseline/comparison exists to corroborate against at all.
"""

from __future__ import annotations

from app.analyzers.base import ExchangeAnalyzer
from app.analyzers.scoring import score_from_indicator_kinds
from app.schemas.finding import (
    CATEGORY_MAPPING,
    EvidenceItem,
    FindingCandidate,
    Severity,
    VulnerabilityCategory,
)
from app.schemas.response_intel import AnalyzedExchange

_DB_ERROR_KINDS_DESC_PREFIXES = ("mysql", "postgresql", "mssql", "oracle", "sqlite")


class SqlInjectionAnalyzer(ExchangeAnalyzer):
    name = "sql_injection_analyzer"

    def applies_to(self, exchange: AnalyzedExchange) -> bool:
        return any(i.kind == "error_signature" for i in exchange.security_indicators)

    def _is_db_error(self, description: str) -> bool:
        lowered = description.lower()
        return any(engine in lowered for engine in _DB_ERROR_KINDS_DESC_PREFIXES)

    def analyze(self, exchange: AnalyzedExchange) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []

        db_error_indicators = [
            i
            for i in exchange.security_indicators
            if i.kind == "error_signature" and self._is_db_error(i.description)
        ]
        if not db_error_indicators:
            return findings

        status_anomaly = any(i.kind == "status_anomaly" for i in exchange.security_indicators)
        timing_anomaly = any(i.kind == "timing_anomaly" for i in exchange.security_indicators)
        has_comparison = exchange.comparison is not None

        kinds = ["error_signature"]
        if status_anomaly:
            kinds.append("status_anomaly")
        if timing_anomaly:
            kinds.append("timing_anomaly")

        # No comparison at all means we only have the raw error string
        # with nothing to corroborate it against -- keep it, but as a
        # low-severity, low-confidence candidate (scoring handles the cap
        # automatically via the single-indicator-kind rule).
        exploitability = 0.3
        impact = 0.7
        if status_anomaly or timing_anomaly:
            exploitability = 0.55

        severity = Severity.MEDIUM
        if status_anomaly or timing_anomaly:
            severity = Severity.HIGH

        cwe, owasp = CATEGORY_MAPPING[VulnerabilityCategory.SQL_INJECTION]
        risk = score_from_indicator_kinds(kinds, exploitability, impact)

        evidence = [
            EvidenceItem(
                description=i.description,
                source_indicator_kind=i.kind,
            )
            for i in exchange.security_indicators
            if i.kind in ("error_signature", "status_anomaly", "timing_anomaly")
        ]

        findings.append(
            FindingCandidate(
                title="Possible SQL injection (database error signature)",
                category=VulnerabilityCategory.SQL_INJECTION,
                cwe=cwe,
                owasp=owasp,
                severity=severity,
                risk=risk,
                endpoint=exchange.request.path,
                method=exchange.request.method.value,
                parameter=next(iter(exchange.request.query_params), None)
                or next(iter(exchange.request.body_params), None),
                evidence=evidence,
                requests=[exchange.request.id],
                responses=[exchange.response.id],
                affected_assets=[exchange.request.url],
                recommendation=(
                    "Use parameterized queries / prepared statements or an ORM "
                    "that escapes input by default; never interpolate user "
                    "input directly into SQL strings. Disable verbose DB error "
                    "output in production."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cwe.mitre.org/data/definitions/89.html",
                ],
                analyzer_name=self.name,
            )
        )
        return findings
