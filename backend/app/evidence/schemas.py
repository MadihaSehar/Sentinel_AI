"""
Data contracts for the False Positive Engine (Section 13).

The core principle from the spec:

    "A database-looking error alone should NOT automatically mean SQL
     injection. A reflected parameter alone should NOT automatically mean
     exploitable XSS. A different HTTP response alone should NOT
     automatically mean IDOR. Require multiple pieces of evidence."

This module defines the vocabulary of *evidence atoms* deterministic
analyzers (Section 9, Response Analysis Engine) can produce, and the
scoring structures the False Positive Engine fills in:

    Evidence Score        -- how much, and how strong, raw evidence exists
    Confidence Score       -- evidence score blended with AI consensus (Sec 12)
    Exploitability Score   -- how practically exploitable the evidence implies
    Impact Score           -- how bad it would be if real (CWE/OWASP-informed)
    Final Risk Score       -- combined score used for report prioritization
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class VulnCategory(str, Enum):
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    LFI_PATH_TRAVERSAL = "lfi_path_traversal"
    RFI = "rfi"
    SSTI = "ssti"
    XXE = "xxe"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    AUTH_WEAKNESS = "auth_weakness"
    AUTHZ_WEAKNESS = "authz_weakness"
    IDOR_BOLA = "idor_bola"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    CSRF = "csrf"
    CLICKJACKING = "clickjacking"
    OPEN_REDIRECT = "open_redirect"
    INSECURE_CORS = "insecure_cors"
    API_EXCESSIVE_DATA_EXPOSURE = "api_excessive_data_exposure"
    API_RATE_LIMIT = "api_rate_limit"
    API_MASS_ASSIGNMENT = "api_mass_assignment"


class EvidenceType(str, Enum):
    """
    Atomic, independently-observable signals that deterministic analyzers
    (Section 9) can emit. No single one of these should, by itself, prove
    a vulnerability -- the rules in rules.py define which *combinations*
    are required per category.
    """

    # Generic response-diffing signals
    STATUS_CODE_DIFF = "status_code_diff"
    CONTENT_LENGTH_DIFF = "content_length_diff"
    RESPONSE_TIME_DELTA = "response_time_delta"
    STRUCTURAL_DIFF = "structural_diff"
    HEADER_DIFF = "header_diff"

    # Injection-family signals
    DB_ERROR_SIGNATURE = "db_error_signature"
    BOOLEAN_RESPONSE_DIFF = "boolean_response_diff"
    UNION_BASED_DIFF = "union_based_diff"
    OS_COMMAND_OUTPUT_OBSERVED = "os_command_output_observed"
    TEMPLATE_EXPRESSION_EVALUATED = "template_expression_evaluated"
    XML_ENTITY_RESOLVED = "xml_entity_resolved"
    DESERIALIZATION_GADGET_TRIGGERED = "deserialization_gadget_triggered"

    # Path / file / SSRF signals
    FILE_CONTENT_DISCLOSED = "file_content_disclosed"
    PATH_TRAVERSAL_CONFIRMED = "path_traversal_confirmed"
    OUTBOUND_CALLBACK_RECEIVED = "outbound_callback_received"
    INTERNAL_SERVICE_RESPONSE_LEAKED = "internal_service_response_leaked"

    # Client-side signals
    REFLECTED_PARAM = "reflected_param"
    UNESCAPED_IN_HTML_CONTEXT = "unescaped_in_html_context"
    STORED_PAYLOAD_RETRIEVED = "stored_payload_retrieved"
    DOM_SINK_REACHED = "dom_sink_reached"
    SCRIPT_EXECUTION_CONFIRMED = "script_execution_confirmed"

    # Access-control / session signals
    DIFFERENT_RESPONSE_FOR_OTHER_IDENTITY = "different_response_for_other_identity"
    SENSITIVE_DATA_IN_RESPONSE = "sensitive_data_in_response"
    AUTH_NOT_REQUIRED_CONFIRMED = "auth_not_required_confirmed"
    CSRF_TOKEN_MISSING = "csrf_token_missing"
    CSRF_TOKEN_NOT_VALIDATED = "csrf_token_not_validated"
    STATE_CHANGE_CONFIRMED = "state_change_confirmed"
    X_FRAME_OPTIONS_MISSING = "x_frame_options_missing"
    CSP_FRAME_ANCESTORS_MISSING = "csp_frame_ancestors_missing"
    OPEN_REDIRECT_CONFIRMED = "open_redirect_confirmed"
    ACAO_REFLECTS_ARBITRARY_ORIGIN = "acao_reflects_arbitrary_origin"
    ACAC_TRUE_WITH_WILDCARD_ORIGIN = "acac_true_with_wildcard_origin"
    EXTRA_FIELDS_ACCEPTED = "extra_fields_accepted"
    RATE_LIMIT_ABSENT_AFTER_N_REQUESTS = "rate_limit_absent_after_n_requests"


class EvidenceItem(BaseModel):
    type: EvidenceType
    detail: str = Field(..., max_length=500)
    source: str = Field(..., description="Which analyzer/tool produced this, e.g. 'nuclei', 'response_diff_analyzer'")
    strength: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Analyzer's own confidence in this single signal"
    )


class FalsePositiveVerdict(str, Enum):
    SUFFICIENT_EVIDENCE = "sufficient_evidence"          # passes deterministic rule, proceed to AI/consensus
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"       # fails deterministic rule -> drop or request more data
    LIKELY_FALSE_POSITIVE = "likely_false_positive"       # evidence actively contradicts the finding


class ScoreBreakdown(BaseModel):
    evidence_score: float = Field(..., ge=0.0, le=1.0)
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    exploitability_score: float = Field(..., ge=0.0, le=1.0)
    impact_score: float = Field(..., ge=0.0, le=1.0)
    final_risk_score: float = Field(..., ge=0.0, le=1.0)


class FalsePositiveAssessment(BaseModel):
    category: VulnCategory
    verdict: FalsePositiveVerdict
    matched_rule: str | None = Field(
        default=None, description="Name of the minimum-evidence rule that was satisfied, if any"
    )
    missing_evidence: list[EvidenceType] = Field(default_factory=list)
    evidence: list[EvidenceItem]
    scores: ScoreBreakdown
    explanation: str
