"""
Minimum-evidence rules per vulnerability category (Section 13).

Each category defines a set of RULES. A rule is a frozenset of EvidenceType
that must ALL be present (an AND-set). A category is satisfied if AT LEAST
ONE of its rules is fully matched (OR across rules). This mirrors how real
bugs are actually confirmed: there are usually a few distinct *paths* to
confidently proving a vulnerability (e.g. for SQLi: error-based OR
boolean-based OR union-based OR time-based), and each path individually
needs more than one weak signal.

Also defines per-category baseline EXPLOITABILITY and IMPACT weights, used
by the risk-scoring formulas in false_positive_engine.py. These are
starting points informed by common CWE/OWASP guidance -- NOT a substitute
for case-by-case AI/human judgment, which is why they feed a *score*
rather than a hard-coded severity.
"""

from __future__ import annotations

from dataclasses import dataclass

from .schemas import EvidenceType as E
from .schemas import VulnCategory as C


@dataclass(frozen=True)
class CategoryProfile:
    # OR of AND-sets: satisfy ANY one full set to pass the deterministic gate.
    rules: tuple[frozenset[E], ...]
    # Baseline exploitability/impact in [0,1] before evidence-specific adjustment.
    base_exploitability: float
    base_impact: float
    cwe: str
    owasp: str


CATEGORY_PROFILES: dict[C, CategoryProfile] = {
    C.SQL_INJECTION: CategoryProfile(
        rules=(
            frozenset({E.DB_ERROR_SIGNATURE, E.STRUCTURAL_DIFF}),
            frozenset({E.BOOLEAN_RESPONSE_DIFF, E.STATUS_CODE_DIFF}),
            frozenset({E.UNION_BASED_DIFF, E.STRUCTURAL_DIFF}),
            frozenset({E.RESPONSE_TIME_DELTA, E.BOOLEAN_RESPONSE_DIFF}),  # time-based
        ),
        base_exploitability=0.75,
        base_impact=0.90,
        cwe="CWE-89",
        owasp="A03:2021-Injection",
    ),
    C.COMMAND_INJECTION: CategoryProfile(
        rules=(
            frozenset({E.OS_COMMAND_OUTPUT_OBSERVED}),
            frozenset({E.RESPONSE_TIME_DELTA, E.STRUCTURAL_DIFF}),  # blind, time-based
        ),
        base_exploitability=0.85,
        base_impact=0.95,
        cwe="CWE-78",
        owasp="A03:2021-Injection",
    ),
    C.SSRF: CategoryProfile(
        rules=(
            frozenset({E.OUTBOUND_CALLBACK_RECEIVED}),
            frozenset({E.INTERNAL_SERVICE_RESPONSE_LEAKED, E.STRUCTURAL_DIFF}),
        ),
        base_exploitability=0.70,
        base_impact=0.85,
        cwe="CWE-918",
        owasp="A10:2021-SSRF",
    ),
    C.LFI_PATH_TRAVERSAL: CategoryProfile(
        rules=(
            frozenset({E.FILE_CONTENT_DISCLOSED}),
            frozenset({E.PATH_TRAVERSAL_CONFIRMED, E.STRUCTURAL_DIFF}),
        ),
        base_exploitability=0.75,
        base_impact=0.80,
        cwe="CWE-22",
        owasp="A01:2021-Broken Access Control",
    ),
    C.RFI: CategoryProfile(
        rules=(frozenset({E.OUTBOUND_CALLBACK_RECEIVED, E.OS_COMMAND_OUTPUT_OBSERVED}),),
        base_exploitability=0.80,
        base_impact=0.90,
        cwe="CWE-98",
        owasp="A03:2021-Injection",
    ),
    C.SSTI: CategoryProfile(
        rules=(frozenset({E.TEMPLATE_EXPRESSION_EVALUATED}),),
        base_exploitability=0.70,
        base_impact=0.85,
        cwe="CWE-1336",
        owasp="A03:2021-Injection",
    ),
    C.XXE: CategoryProfile(
        rules=(
            frozenset({E.XML_ENTITY_RESOLVED, E.FILE_CONTENT_DISCLOSED}),
            frozenset({E.XML_ENTITY_RESOLVED, E.OUTBOUND_CALLBACK_RECEIVED}),
        ),
        base_exploitability=0.65,
        base_impact=0.80,
        cwe="CWE-611",
        owasp="A05:2021-Security Misconfiguration",
    ),
    C.INSECURE_DESERIALIZATION: CategoryProfile(
        rules=(frozenset({E.DESERIALIZATION_GADGET_TRIGGERED}),),
        base_exploitability=0.60,
        base_impact=0.90,
        cwe="CWE-502",
        owasp="A08:2021-Software and Data Integrity Failures",
    ),
    C.AUTH_WEAKNESS: CategoryProfile(
        rules=(frozenset({E.AUTH_NOT_REQUIRED_CONFIRMED, E.SENSITIVE_DATA_IN_RESPONSE}),),
        base_exploitability=0.70,
        base_impact=0.80,
        cwe="CWE-287",
        owasp="A07:2021-Identification and Authentication Failures",
    ),
    C.AUTHZ_WEAKNESS: CategoryProfile(
        rules=(
            frozenset({E.DIFFERENT_RESPONSE_FOR_OTHER_IDENTITY, E.SENSITIVE_DATA_IN_RESPONSE}),
        ),
        base_exploitability=0.70,
        base_impact=0.80,
        cwe="CWE-285",
        owasp="A01:2021-Broken Access Control",
    ),
    C.IDOR_BOLA: CategoryProfile(
        rules=(
            frozenset(
                {E.DIFFERENT_RESPONSE_FOR_OTHER_IDENTITY, E.SENSITIVE_DATA_IN_RESPONSE, E.STATUS_CODE_DIFF}
            ),
        ),
        base_exploitability=0.75,
        base_impact=0.80,
        cwe="CWE-639",
        owasp="A01:2021-Broken Access Control",
    ),
    C.SECURITY_MISCONFIGURATION: CategoryProfile(
        # Deliberately permissive -- this is a catch-all; two independent
        # signals of *something* misconfigured is the bar.
        rules=(
            frozenset({E.HEADER_DIFF, E.SENSITIVE_DATA_IN_RESPONSE}),
            frozenset({E.STATUS_CODE_DIFF, E.STRUCTURAL_DIFF}),
        ),
        base_exploitability=0.40,
        base_impact=0.50,
        cwe="CWE-16",
        owasp="A05:2021-Security Misconfiguration",
    ),
    C.XSS_REFLECTED: CategoryProfile(
        rules=(
            frozenset({E.REFLECTED_PARAM, E.UNESCAPED_IN_HTML_CONTEXT}),
            frozenset({E.REFLECTED_PARAM, E.SCRIPT_EXECUTION_CONFIRMED}),
        ),
        base_exploitability=0.55,
        base_impact=0.60,
        cwe="CWE-79",
        owasp="A03:2021-Injection",
    ),
    C.XSS_STORED: CategoryProfile(
        rules=(
            frozenset({E.STORED_PAYLOAD_RETRIEVED, E.UNESCAPED_IN_HTML_CONTEXT}),
            frozenset({E.STORED_PAYLOAD_RETRIEVED, E.SCRIPT_EXECUTION_CONFIRMED}),
        ),
        base_exploitability=0.70,
        base_impact=0.75,
        cwe="CWE-79",
        owasp="A03:2021-Injection",
    ),
    C.XSS_DOM: CategoryProfile(
        rules=(frozenset({E.DOM_SINK_REACHED, E.SCRIPT_EXECUTION_CONFIRMED}),),
        base_exploitability=0.55,
        base_impact=0.60,
        cwe="CWE-79",
        owasp="A03:2021-Injection",
    ),
    C.CSRF: CategoryProfile(
        rules=(
            frozenset({E.CSRF_TOKEN_MISSING, E.STATE_CHANGE_CONFIRMED}),
            frozenset({E.CSRF_TOKEN_NOT_VALIDATED, E.STATE_CHANGE_CONFIRMED}),
        ),
        base_exploitability=0.50,
        base_impact=0.55,
        cwe="CWE-352",
        owasp="A01:2021-Broken Access Control",
    ),
    C.CLICKJACKING: CategoryProfile(
        rules=(frozenset({E.X_FRAME_OPTIONS_MISSING, E.CSP_FRAME_ANCESTORS_MISSING}),),
        base_exploitability=0.35,
        base_impact=0.35,
        cwe="CWE-1021",
        owasp="A05:2021-Security Misconfiguration",
    ),
    C.OPEN_REDIRECT: CategoryProfile(
        rules=(frozenset({E.OPEN_REDIRECT_CONFIRMED}),),
        base_exploitability=0.30,
        base_impact=0.30,
        cwe="CWE-601",
        owasp="A01:2021-Broken Access Control",
    ),
    C.INSECURE_CORS: CategoryProfile(
        rules=(
            frozenset({E.ACAO_REFLECTS_ARBITRARY_ORIGIN, E.ACAC_TRUE_WITH_WILDCARD_ORIGIN}),
            frozenset({E.ACAO_REFLECTS_ARBITRARY_ORIGIN, E.SENSITIVE_DATA_IN_RESPONSE}),
        ),
        base_exploitability=0.45,
        base_impact=0.55,
        cwe="CWE-942",
        owasp="A05:2021-Security Misconfiguration",
    ),
    C.API_EXCESSIVE_DATA_EXPOSURE: CategoryProfile(
        rules=(frozenset({E.SENSITIVE_DATA_IN_RESPONSE, E.STRUCTURAL_DIFF}),),
        base_exploitability=0.55,
        base_impact=0.65,
        cwe="CWE-213",
        owasp="API3:2023-Broken Object Property Level Authorization",
    ),
    C.API_RATE_LIMIT: CategoryProfile(
        rules=(frozenset({E.RATE_LIMIT_ABSENT_AFTER_N_REQUESTS}),),
        base_exploitability=0.40,
        base_impact=0.40,
        cwe="CWE-799",
        owasp="API4:2023-Unrestricted Resource Consumption",
    ),
    C.API_MASS_ASSIGNMENT: CategoryProfile(
        rules=(frozenset({E.EXTRA_FIELDS_ACCEPTED, E.STATE_CHANGE_CONFIRMED}),),
        base_exploitability=0.55,
        base_impact=0.65,
        cwe="CWE-915",
        owasp="API6:2023-Unrestricted Access to Sensitive Business Flows",
    ),
}


def get_profile(category: C) -> CategoryProfile:
    try:
        return CATEGORY_PROFILES[category]
    except KeyError as exc:
        raise ValueError(f"No rule profile registered for category: {category}") from exc
