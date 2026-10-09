"""
SentinelAI - Phase 7: Vulnerability Analyzers
Open redirect candidate analyzer.

Checks whether a parameter whose value looks like a URL (query param
name commonly used for redirects, or a value that is itself an absolute
URL / protocol-relative URL) is echoed into the Location header or into
the final entry of the response's redirect chain, pointing somewhere
outside the request's own host. Purely structural -- no payload
execution, no network requests performed by this analyzer.
"""

from __future__ import annotations

from urllib.parse import urlparse

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

_REDIRECT_PARAM_NAMES = {
    "url", "redirect", "redirect_uri", "redirect_url", "return",
    "return_url", "returnto", "return_to", "next", "dest", "destination",
    "continue", "target", "out", "to",
}


def _is_external(base_host: str, candidate_url: str) -> bool:
    parsed = urlparse(candidate_url)
    if not parsed.netloc:
        # relative path / same-origin, or protocol-relative "//evil.com"
        return candidate_url.startswith("//") and parsed.netloc not in ("", base_host)
    return parsed.netloc.split(":")[0] != base_host.split(":")[0]


class OpenRedirectAnalyzer(ExchangeAnalyzer):
    name = "open_redirect_analyzer"

    def applies_to(self, exchange: AnalyzedExchange) -> bool:
        if not exchange.response.redirect_chain:
            return False
        return any(
            p.lower() in _REDIRECT_PARAM_NAMES for p in exchange.request.query_params
        )

    def analyze(self, exchange: AnalyzedExchange) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        base_host = urlparse(exchange.request.url).netloc

        suspect_params = [
            (name, value)
            for name, value in exchange.request.query_params.items()
            if name.lower() in _REDIRECT_PARAM_NAMES
        ]
        if not suspect_params:
            return findings

        final_hop = exchange.response.redirect_chain[-1]
        if not _is_external(base_host, final_hop):
            return findings

        # Does the final redirect target actually correspond to one of
        # the suspect parameter values (not just "some redirect happened")?
        matched_param = None
        for name, value in suspect_params:
            if value and (value in final_hop or final_hop.endswith(value.lstrip("/"))):
                matched_param = name
                break

        kinds = ["status_anomaly"] if not matched_param else ["status_anomaly", "parameter_match"]
        exploitability = 0.5 if matched_param else 0.3
        impact = 0.4
        severity = Severity.MEDIUM if matched_param else Severity.LOW

        cwe, owasp = CATEGORY_MAPPING[VulnerabilityCategory.OPEN_REDIRECT]
        risk = score_from_indicator_kinds(kinds, exploitability, impact)

        findings.append(
            FindingCandidate(
                title="Possible open redirect",
                category=VulnerabilityCategory.OPEN_REDIRECT,
                cwe=cwe,
                owasp=owasp,
                severity=severity,
                risk=risk,
                endpoint=exchange.request.path,
                method=exchange.request.method.value,
                parameter=matched_param or suspect_params[0][0],
                evidence=[
                    EvidenceItem(
                        description=(
                            f"Redirect chain ends at external host "
                            f"'{urlparse(final_hop).netloc}', "
                            f"{'matching' if matched_param else 'following'} "
                            f"parameter '{matched_param or suspect_params[0][0]}'."
                        ),
                        source_indicator_kind="redirect_chain",
                    )
                ],
                requests=[exchange.request.id],
                responses=[exchange.response.id],
                affected_assets=[exchange.request.url],
                recommendation=(
                    "Validate redirect targets against an allowlist of known "
                    "internal paths/hosts; never redirect directly to a "
                    "user-controlled absolute URL."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards",
                    "https://cwe.mitre.org/data/definitions/601.html",
                ],
                analyzer_name=self.name,
            )
        )
        return findings
