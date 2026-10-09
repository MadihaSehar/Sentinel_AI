"""
SentinelAI - Phase 7: Vulnerability Analyzers
Security-header analyzer.

Unlike the other analyzers, this one doesn't need indicators from Phase 6
-- it inspects the response headers directly, deterministically. It is
cheap, always-applicable to HTML responses, and produces three distinct
finding categories: generic security misconfiguration (missing
hardening headers), clickjacking (missing/weak frame-ancestors
protection), and CORS misconfiguration (reflective/wildcard
Access-Control-Allow-Origin combined with credentials allowed).

These are, by nature, higher-confidence findings than the other
analyzers: a missing header is directly observable fact, not an
inference from a side-channel signal. Confidence is set accordingly
rather than through the indicator-kind scorer.
"""

from __future__ import annotations

from app.schemas.finding import (
    CATEGORY_MAPPING,
    EvidenceItem,
    FindingCandidate,
    RiskScore,
    Severity,
    VulnerabilityCategory,
)
from app.schemas.response_intel import AnalyzedExchange

_HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")

_RECOMMENDED_HEADERS = {
    "strict-transport-security": (
        "Add 'Strict-Transport-Security' to enforce HTTPS and prevent "
        "protocol-downgrade attacks."
    ),
    "x-content-type-options": (
        "Add 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing."
    ),
    "content-security-policy": (
        "Add a 'Content-Security-Policy' to restrict script/style/frame "
        "sources as defense-in-depth against XSS and clickjacking."
    ),
}


def _headers_lower(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in (headers or {}).items()}


class SecurityHeadersAnalyzer:
    """Not an ExchangeAnalyzer subclass with the single-finding-type
    contract -- this one legitimately produces multiple distinct finding
    categories per response, so it implements the same duck-typed
    interface (applies_to/analyze) directly."""

    name = "security_headers_analyzer"

    def applies_to(self, exchange: AnalyzedExchange) -> bool:
        ct = (exchange.response.content_type or "").lower()
        return any(h in ct for h in _HTML_CONTENT_TYPES) and exchange.response.status_code < 400

    def analyze(self, exchange: AnalyzedExchange) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        headers = _headers_lower(exchange.response.headers)

        findings.extend(self._check_missing_hardening_headers(exchange, headers))
        findings.extend(self._check_clickjacking(exchange, headers))
        findings.extend(self._check_cors(exchange, headers))
        return findings

    # -- individual checks ------------------------------------------------

    def _check_missing_hardening_headers(
        self, exchange: AnalyzedExchange, headers: dict[str, str]
    ) -> list[FindingCandidate]:
        missing = [h for h in _RECOMMENDED_HEADERS if h not in headers]
        if not missing:
            return []

        cwe, owasp = CATEGORY_MAPPING[VulnerabilityCategory.SECURITY_MISCONFIGURATION]
        risk = RiskScore(
            evidence_score=1.0,  # directly observed, not inferred
            confidence_score=0.9,
            exploitability_score=0.2,
            impact_score=0.3,
        )
        return [
            FindingCandidate(
                title="Missing security hardening headers",
                category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                cwe=cwe,
                owasp=owasp,
                severity=Severity.LOW,
                risk=risk,
                endpoint=exchange.request.path,
                method=exchange.request.method.value,
                evidence=[
                    EvidenceItem(description=_RECOMMENDED_HEADERS[h]) for h in missing
                ],
                requests=[exchange.request.id],
                responses=[exchange.response.id],
                affected_assets=[exchange.request.url],
                recommendation="Add the missing response headers listed in evidence.",
                references=["https://owasp.org/www-project-secure-headers/"],
                analyzer_name=self.name,
            )
        ]

    def _check_clickjacking(
        self, exchange: AnalyzedExchange, headers: dict[str, str]
    ) -> list[FindingCandidate]:
        xfo = headers.get("x-frame-options", "").lower()
        csp = headers.get("content-security-policy", "").lower()
        has_frame_ancestors = "frame-ancestors" in csp
        protected = xfo in ("deny", "sameorigin") or has_frame_ancestors
        if protected:
            return []

        cwe, owasp = CATEGORY_MAPPING[VulnerabilityCategory.CLICKJACKING]
        risk = RiskScore(
            evidence_score=1.0,
            confidence_score=0.85,
            exploitability_score=0.4,
            impact_score=0.3,
        )
        return [
            FindingCandidate(
                title="Missing clickjacking protection",
                category=VulnerabilityCategory.CLICKJACKING,
                cwe=cwe,
                owasp=owasp,
                severity=Severity.LOW,
                risk=risk,
                endpoint=exchange.request.path,
                method=exchange.request.method.value,
                evidence=[
                    EvidenceItem(
                        description=(
                            "Response has neither a restrictive X-Frame-Options "
                            "header nor a CSP frame-ancestors directive, so the "
                            "page can be embedded in a third-party iframe."
                        )
                    )
                ],
                requests=[exchange.request.id],
                responses=[exchange.response.id],
                affected_assets=[exchange.request.url],
                recommendation=(
                    "Set 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or a CSP "
                    "'frame-ancestors' directive."
                ),
                references=["https://cwe.mitre.org/data/definitions/1021.html"],
                analyzer_name=self.name,
            )
        ]

    def _check_cors(
        self, exchange: AnalyzedExchange, headers: dict[str, str]
    ) -> list[FindingCandidate]:
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower() == "true"
        if not acao:
            return []

        request_origin = exchange.request.headers.get("Origin") or exchange.request.headers.get(
            "origin"
        )
        reflects_origin = bool(request_origin) and acao == request_origin
        wildcard_with_creds = acao == "*" and acac

        if not (reflects_origin and acac) and not wildcard_with_creds:
            return []

        cwe, owasp = CATEGORY_MAPPING[VulnerabilityCategory.CORS_MISCONFIGURATION]
        risk = RiskScore(
            evidence_score=1.0,
            confidence_score=0.8,
            exploitability_score=0.55,
            impact_score=0.5,
        )
        description = (
            "Access-Control-Allow-Origin reflects the request Origin while "
            "Access-Control-Allow-Credentials is true, allowing any origin to "
            "make authenticated cross-origin requests."
            if reflects_origin
            else "Access-Control-Allow-Origin is '*' combined with "
            "Access-Control-Allow-Credentials: true (invalid per spec, but "
            "indicates a broken/misconfigured CORS policy)."
        )
        return [
            FindingCandidate(
                title="Permissive CORS policy with credentials",
                category=VulnerabilityCategory.CORS_MISCONFIGURATION,
                cwe=cwe,
                owasp=owasp,
                severity=Severity.HIGH,
                risk=risk,
                endpoint=exchange.request.path,
                method=exchange.request.method.value,
                evidence=[EvidenceItem(description=description)],
                requests=[exchange.request.id],
                responses=[exchange.response.id],
                affected_assets=[exchange.request.url],
                recommendation=(
                    "Maintain an explicit allowlist of trusted origins instead "
                    "of reflecting the request Origin, and never combine a "
                    "wildcard origin with credentials."
                ),
                references=["https://cwe.mitre.org/data/definitions/942.html"],
                analyzer_name=self.name,
            )
        ]
