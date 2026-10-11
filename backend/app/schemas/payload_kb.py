"""
SentinelAI - Phase 8: Payload Knowledge Base
Schema for normalized payload-family metadata (Section 7).

Design intent: this is a KNOWLEDGE index, not an attack library. Each
entry describes a *family* of test technique (what it targets, in what
context, how you'd detect success) with at most one or two canonical,
textbook-level example strings -- the kind already in every OWASP
Testing Guide page and taught in any intro appsec course. The AI
Orchestrator queries this by category/context to decide what KIND of
test is relevant (Section 7: "The AI should select payload/test
families based on application context. Do NOT blindly execute every
payload."); it is the analyzers and allowlisted tools (Nuclei, ffuf
templates, etc.) that actually hold and fire full payload sets, under
the Scope Enforcement Layer -- never this module, and never unreviewed
LLM output.
"""

from __future__ import annotations

import enum
from typing import Optional

from pydantic import BaseModel, Field


class PayloadCategory(str, enum.Enum):
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    LFI = "lfi"
    RFI = "rfi"
    PATH_TRAVERSAL = "path_traversal"
    CSRF = "csrf"
    XXE = "xxe"
    SSTI = "ssti"
    IDOR_BOLA = "idor_bola"
    OPEN_REDIRECT = "open_redirect"
    CORS = "cors"
    JWT = "jwt"
    AUTHENTICATION = "authentication"
    API_SECURITY = "api_security"
    GRAPHQL = "graphql"
    FILE_UPLOAD = "file_upload"
    DESERIALIZATION = "deserialization"
    PROTOTYPE_POLLUTION = "prototype_pollution"


class PayloadContext(str, enum.Enum):
    HTML_BODY = "html"
    HTML_ATTRIBUTE = "attribute"
    JS_STRING = "js_string"
    URL_PARAM = "url"
    HTTP_HEADER = "header"
    JSON_BODY = "json"
    XML_BODY = "xml"
    SQL_STRING_CONTEXT = "sql_string"
    SQL_NUMERIC_CONTEXT = "sql_numeric"
    FILE_PATH = "file_path"
    TEMPLATE = "template"
    COOKIE = "cookie"
    MULTIPART_UPLOAD = "multipart"
    GENERIC = "generic"


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Encoding(str, enum.Enum):
    NONE = "none"
    URL = "url"
    HTML_ENTITY = "html_entity"
    BASE64 = "base64"
    UNICODE = "unicode"
    DOUBLE_URL = "double_url"


class PayloadEntry(BaseModel):
    """One normalized technique-family entry. Matches the metadata shape
    specified in Section 7's example JSON block."""

    id: str  # stable slug, e.g. "xss-reflected-html-body-basic"
    category: PayloadCategory
    context: PayloadContext
    encoding: Encoding = Encoding.NONE
    risk_level: RiskLevel
    source: str = "PayloadsAllTheThings"
    description: str
    detection_method: str
    requires_authorization: bool = True

    # At most a small, canonical example -- never a large arsenal. This
    # field is optional precisely so most entries can carry zero example
    # strings and rely purely on description/detection_method to convey
    # the technique to the orchestrator and to a human reviewer.
    example: Optional[str] = None

    applicable_technologies: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class CategorySelectionResult(BaseModel):
    """What select_payload_families() returns to the AI Orchestrator:
    which categories are relevant given discovered context, and why."""

    category: PayloadCategory
    reason: str
    matched_technologies: list[str] = Field(default_factory=list)
    entry_count: int = 0
