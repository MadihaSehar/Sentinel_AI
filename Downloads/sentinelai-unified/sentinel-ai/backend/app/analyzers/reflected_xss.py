"""
SentinelAI - Phase 7: Vulnerability Analyzers
Reflected XSS candidate analyzer.

Evidence required (Section 8/13 - never a single signal):
  1. A 'reflection' indicator in an unescaped, script-relevant context
     (html_body, html_attribute, or js_string) -- i.e. it was NOT
     HTML-entity-escaped by the application.
  2. Supporting evidence that the DOM actually changed shape as a result
     (new <script> tag or new inline event handler attribute), OR the
     reflection landed in js_string/html_attribute context, which is
     inherently higher-risk than plain html_body text.

A bare html-escaped reflection, or a reflection with no DOM-shape
corroboration in body context, is intentionally scored low / not
reported as a candidate at all -- this is the false-positive guard
called out in Section 13.
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

_HIGH_RISK_CONTEXTS = {"js_string", "html_attribute"}


class ReflectedXssAnalyzer(ExchangeAnalyzer):
    name = "reflected_xss_analyzer"

    def applies_to(self, exchange: AnalyzedExchange) -> bool:
        return any(i.kind == "reflection" for i in exchange.security_indicators)

    def analyze(self, exchange: AnalyzedExchange) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []

        reflection_indicators = [
            i for i in exchange.security_indicators if i.kind == "reflection"
        ]
        # Only unescaped reflections are candidates -- an HTML-escaped
        # reflection means the application already neutralized it.
        unescaped = [i for i in reflection_indicators if "HTML-escaped" not in i.description]
        if not unescaped:
            return findings

        has_dom_corroboration = any(
            i.kind in ("dom_new_script", "dom_new_event_handler")
            for i in exchange.security_indicators
        )
        in_high_risk_context = any(
            any(ctx in i.description for ctx in _HIGH_RISK_CONTEXTS) for i in unescaped
        )

        # Require at least one corroborating signal beyond the raw
        # reflection itself before even producing a candidate.
        if not (has_dom_corroboration or in_high_risk_context):
            return findings

        kinds = ["reflection"]
        if has_dom_corroboration:
            kinds.extend(
                i.kind
                for i in exchange.security_indicators
                if i.kind in ("dom_new_script", "dom_new_event_handler")
            )

        exploitability = 0.6 if has_dom_corroboration else 0.4
        impact = 0.6

        cwe, owasp = CATEGORY_MAPPING[VulnerabilityCategory.XSS_REFLECTED]
        risk = score_from_indicator_kinds(kinds, exploitability, impact)

        evidence = [
            EvidenceItem(
                description=i.description,
                source_indicator_kind=i.kind,
                ref=(i.evidence_refs[0] if i.evidence_refs else None),
            )
            for i in unescaped
        ]
        if has_dom_corroboration:
            evidence.extend(
                EvidenceItem(
                    description=i.description,
                    source_indicator_kind=i.kind,
                    ref=(i.evidence_refs[0] if i.evidence_refs else None),
                )
                for i in exchange.security_indicators
                if i.kind in ("dom_new_script", "dom_new_event_handler")
            )

        severity = Severity.HIGH if has_dom_corroboration else Severity.MEDIUM

        findings.append(
            FindingCandidate(
                title="Possible reflected XSS",
                category=VulnerabilityCategory.XSS_REFLECTED,
                cwe=cwe,
                owasp=owasp,
                severity=severity,
                risk=risk,
                endpoint=exchange.request.path,
                method=exchange.request.method.value,
                parameter=unescaped[0].evidence_refs[0] if unescaped[0].evidence_refs else None,
                evidence=evidence,
                requests=[exchange.request.id],
                responses=[exchange.response.id],
                affected_assets=[exchange.request.url],
                recommendation=(
                    "Context-aware output encoding of user input before it is "
                    "written into HTML, attributes, or script contexts; "
                    "consider a Content-Security-Policy as defense in depth."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://cwe.mitre.org/data/definitions/79.html",
                ],
                analyzer_name=self.name,
            )
        )
        return findings
