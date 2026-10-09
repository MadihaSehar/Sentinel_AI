"""
SentinelAI - Phase 7: Vulnerability Analyzers
IDOR / BOLA comparative analyzer.

Unlike the other analyzers, IDOR cannot be judged from a single exchange
-- it requires comparing two requests for what looks like the same kind
of object (same path shape, different identifier) made under two
different authorization contexts (e.g. user A's session vs user B's
session, or authenticated vs unauthenticated), and checking whether both
got a structurally similar, successful response.

This analyzer makes NO authorization decisions and sends NO requests
itself -- it only compares two already-captured AnalyzedExchanges that
the orchestrator/test harness decided to fetch (e.g. "the same endpoint,
as two different authenticated users"). The caller is responsible for
ensuring exchange_b genuinely represents a different authorization
context; this module only checks whether the *response content* suggests
the same protected object was returned both times.
"""

from __future__ import annotations

import re

from app.analyzers.base import ComparativeAnalyzer
from app.schemas.finding import (
    CATEGORY_MAPPING,
    EvidenceItem,
    FindingCandidate,
    RiskScore,
    Severity,
    VulnerabilityCategory,
)
from app.schemas.response_intel import AnalyzedExchange

_ID_SEGMENT_RE = re.compile(r"/(\d+|[0-9a-fA-F-]{8,})(?=/|$)")

_STRUCTURAL_SIMILARITY_THRESHOLD = 0.8
_SUCCESS_STATUSES = {200, 201}


def _path_shape(path: str) -> str:
    """Collapse numeric/UUID-like path segments to a placeholder so two
    requests for /api/orders/101 and /api/orders/205 compare equal."""
    return _ID_SEGMENT_RE.sub("/{id}", path)


class IdorAnalyzer(ComparativeAnalyzer):
    name = "idor_analyzer"

    def applies_to(
        self, exchange_a: AnalyzedExchange, exchange_b: AnalyzedExchange
    ) -> bool:
        if exchange_a.request.method != exchange_b.request.method:
            return False
        if _path_shape(exchange_a.request.path) != _path_shape(exchange_b.request.path):
            return False
        # Must actually reference different objects to be interesting.
        return exchange_a.request.path != exchange_b.request.path

    def analyze(
        self, exchange_a: AnalyzedExchange, exchange_b: AnalyzedExchange
    ) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []

        resp_a, resp_b = exchange_a.response, exchange_b.response
        if (
            resp_a.status_code not in _SUCCESS_STATUSES
            or resp_b.status_code not in _SUCCESS_STATUSES
        ):
            return findings

        from app.analysis.similarity import structural_similarity

        sim = structural_similarity(resp_a.body, resp_b.body)
        if sim < _STRUCTURAL_SIMILARITY_THRESHOLD:
            # Different-shaped responses suggest access was NOT granted
            # to equivalent data (e.g. an error page or empty result).
            return findings

        cwe, owasp = CATEGORY_MAPPING[VulnerabilityCategory.IDOR]
        risk = RiskScore(
            evidence_score=0.7,
            confidence_score=0.5,  # still needs human/consensus review
            exploitability_score=0.6,
            impact_score=0.7,
        )

        findings.append(
            FindingCandidate(
                title="Possible IDOR / Broken Object Level Authorization",
                category=VulnerabilityCategory.IDOR,
                cwe=cwe,
                owasp=owasp,
                severity=Severity.HIGH,
                risk=risk,
                endpoint=_path_shape(exchange_a.request.path),
                method=exchange_a.request.method.value,
                evidence=[
                    EvidenceItem(
                        description=(
                            f"Requests to '{exchange_a.request.path}' and "
                            f"'{exchange_b.request.path}' under different "
                            f"authorization contexts both returned "
                            f"{resp_a.status_code}/{resp_b.status_code} with "
                            f"{round(sim * 100, 1)}% structural similarity, "
                            "suggesting both callers received equivalent "
                            "object data regardless of ownership."
                        ),
                        source_indicator_kind="structural_similarity",
                    )
                ],
                requests=[exchange_a.request.id, exchange_b.request.id],
                responses=[resp_a.id, resp_b.id],
                affected_assets=[exchange_a.request.url, exchange_b.request.url],
                recommendation=(
                    "Enforce object-level authorization checks server-side on "
                    "every access to an identifier-addressed resource -- never "
                    "rely on the identifier being hard to guess."
                ),
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                    "https://cwe.mitre.org/data/definitions/639.html",
                ],
                analyzer_name=self.name,
            )
        )
        return findings
