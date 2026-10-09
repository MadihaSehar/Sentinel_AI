"""
Maps a nuclei template's tags to an OWASP Top 10 (2021) category.

This is a best-effort heuristic for triage/reporting, NOT an authoritative
classification — a human or the downstream AI consensus layer should
confirm it for any finding above "low" severity. CWE IDs, when present,
come directly from the template's own `classification.cwe-id` field
instead (see nuclei.py) and are far more reliable than this mapping.
"""

from __future__ import annotations

_TAG_TO_OWASP: dict[str, str] = {
    # A01:2021 - Broken Access Control
    "idor": "A01:2021-Broken Access Control",
    "bola": "A01:2021-Broken Access Control",
    "authbypass": "A01:2021-Broken Access Control",
    "access-control": "A01:2021-Broken Access Control",
    "default-login": "A01:2021-Broken Access Control",
    # A02:2021 - Cryptographic Failures
    "crypto": "A02:2021-Cryptographic Failures",
    "tls": "A02:2021-Cryptographic Failures",
    "ssl": "A02:2021-Cryptographic Failures",
    # A03:2021 - Injection
    "sqli": "A03:2021-Injection",
    "xss": "A03:2021-Injection",
    "ssti": "A03:2021-Injection",
    "rce": "A03:2021-Injection",
    "command-injection": "A03:2021-Injection",
    "xxe": "A03:2021-Injection",
    # A04:2021 - Insecure Design
    "race-condition": "A04:2021-Insecure Design",
    # A05:2021 - Security Misconfiguration
    "misconfig": "A05:2021-Security Misconfiguration",
    "misconfiguration": "A05:2021-Security Misconfiguration",
    "exposure": "A05:2021-Security Misconfiguration",
    "exposed-panel": "A05:2021-Security Misconfiguration",
    "config": "A05:2021-Security Misconfiguration",
    "cors": "A05:2021-Security Misconfiguration",
    # A06:2021 - Vulnerable and Outdated Components
    "cve": "A06:2021-Vulnerable and Outdated Components",
    "cnvd": "A06:2021-Vulnerable and Outdated Components",
    "oast": "A10:2021-Server-Side Request Forgery",
    "ssrf": "A10:2021-Server-Side Request Forgery",
    # A07:2021 - Identification and Authentication Failures
    "auth": "A07:2021-Identification and Authentication Failures",
    "jwt": "A07:2021-Identification and Authentication Failures",
    # A08:2021 - Software and Data Integrity Failures
    "deserialization": "A08:2021-Software and Data Integrity Failures",
    "prototype-pollution": "A08:2021-Software and Data Integrity Failures",
    # A09:2021 - Security Logging and Monitoring Failures
    "logging": "A09:2021-Security Logging and Monitoring Failures",
}


def map_tags_to_owasp(tags: list[str]) -> str | None:
    for tag in tags:
        owasp = _TAG_TO_OWASP.get(tag.lower())
        if owasp:
            return owasp
    return None
