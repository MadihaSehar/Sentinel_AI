"""
A realistic, fictional sample assessment used to showcase the report
output without running a live scan. Everything here targets ``example.com``
(the IANA-reserved documentation domain) so nothing points at a real host.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .schemas import (
    ConsensusStatus,
    ReportAsset,
    ReportData,
    ReportFinding,
    Severity,
)


def build_sample_baseline_report() -> ReportData:
    """
    A fictional *earlier* scan of the same target, used to demonstrate the
    scan-to-scan diff. Compared with ``build_sample_report()`` it yields a
    realistic mix: the SQLi and open redirect are new, the CSRF and directory
    listing were fixed, the XSS/IDOR/headers/banner are still open (and the
    XSS severity changed between scans).
    """
    return ReportData(
        target="example.com",
        assessment_name="Previous Assessment (Q3)",
        assessment_type="bug_bounty",
        generated_at=datetime(2026, 7, 12, 10, 0, tzinfo=timezone.utc),
        findings=[
            # Still open — but reported at a lower severity last quarter.
            ReportFinding(
                title="Reflected Cross-Site Scripting in error page",
                severity=Severity.MEDIUM,
                category="Cross-Site Scripting",
                cwe="CWE-79",
                endpoint="https://www.example.com/search",
                method="GET",
                parameter="query",
                description="Reflected XSS in the search results page.",
                recommendation="Context-aware output encoding and a strict CSP.",
            ),
            # Still open.
            ReportFinding(
                title="Insecure Direct Object Reference on invoice download",
                severity=Severity.HIGH,
                category="Broken Access Control",
                cwe="CWE-639",
                endpoint="https://api.example.com/v1/invoices/{id}",
                method="GET",
                parameter="id",
                description="Sequential invoice IDs with no ownership check.",
                recommendation="Enforce per-object ownership checks.",
            ),
            # Still open.
            ReportFinding(
                title="Missing security headers",
                severity=Severity.MEDIUM,
                category="Security Misconfiguration",
                cwe="CWE-693",
                endpoint="https://www.example.com/",
                method="GET",
                description="CSP/HSTS/X-Frame-Options absent.",
                recommendation="Add HSTS, CSP, X-Frame-Options, nosniff.",
            ),
            # Still open.
            ReportFinding(
                title="Verbose server banner discloses software version",
                severity=Severity.INFO,
                category="Information Disclosure",
                cwe="CWE-200",
                endpoint="https://staging.example.com/",
                method="GET",
                description="Server header leaks exact versions.",
                recommendation="ServerTokens Prod.",
            ),
            # Fixed since — no longer present in the current scan.
            ReportFinding(
                title="Cross-Site Request Forgery on email change",
                severity=Severity.HIGH,
                category="Cross-Site Request Forgery",
                cwe="CWE-352",
                endpoint="https://www.example.com/account/email",
                method="POST",
                description="State-changing POST without an anti-CSRF token.",
                recommendation="Add synchronizer tokens / SameSite cookies.",
            ),
            # Fixed since.
            ReportFinding(
                title="Directory listing enabled on backup path",
                severity=Severity.MEDIUM,
                category="Security Misconfiguration",
                cwe="CWE-548",
                endpoint="https://www.example.com/backup/",
                method="GET",
                description="Autoindex exposed backup archives.",
                recommendation="Disable directory listing (autoindex off).",
            ),
        ],
    )


def build_sample_report() -> ReportData:
    return ReportData(
        target="example.com",
        assessment_name="Quarterly External Assessment",
        assessment_type="bug_bounty",
        generated_at=datetime(2026, 10, 11, 14, 30, tzinfo=timezone.utc),
        authorized_by="security@example.com",
        authorization_statement="Authorized under internal pentest engagement PT-2026-Q4.",
        scan_duration_seconds=842.0,
        tools_used=["subfinder", "dnsx", "httpx", "naabu", "katana", "ffuf", "nuclei"],
        subdomains=[
            "www.example.com",
            "api.example.com",
            "staging.example.com",
            "blog.example.com",
            "mail.example.com",
        ],
        assets=[
            ReportAsset(
                hostname="www.example.com",
                ip_addresses=["93.184.216.34"],
                technologies=["nginx 1.25.3", "React 18", "Cloudflare"],
                open_ports=[80, 443],
            ),
            ReportAsset(
                hostname="api.example.com",
                ip_addresses=["93.184.216.35"],
                technologies=["nginx 1.25.3", "FastAPI", "PostgreSQL"],
                open_ports=[443, 8080],
            ),
            ReportAsset(
                hostname="staging.example.com",
                ip_addresses=["93.184.216.36"],
                technologies=["Apache 2.4.57", "PHP 8.1", "MySQL"],
                open_ports=[80, 443, 22],
            ),
        ],
        findings=[
            ReportFinding(
                title="SQL Injection in product search",
                severity=Severity.CRITICAL,
                category="Injection",
                cwe="CWE-89",
                owasp="A03:2021 – Injection",
                endpoint="https://api.example.com/v1/products",
                method="GET",
                parameter="q",
                description=(
                    "The product search endpoint concatenates the 'q' parameter directly "
                    "into a SQL query. A boolean-based blind injection was confirmed: "
                    "payloads altering the WHERE clause changed the result set "
                    "deterministically, and a time-based payload induced a measurable "
                    "server delay."
                ),
                evidence=[
                    "GET /v1/products?q=widget' AND 1=1-- -   → 200, 42 results",
                    "GET /v1/products?q=widget' AND 1=2-- -   → 200, 0 results",
                    "GET /v1/products?q=widget';SELECT pg_sleep(5)-- -   → 5.1s response",
                ],
                recommendation=(
                    "Replace string concatenation with parameterized queries / prepared "
                    "statements. Add an allow-list validator for the search term and apply "
                    "least-privilege database credentials so the web role cannot read "
                    "unrelated tables."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                ],
                consensus_status=ConsensusStatus.CONFIRMED,
                agreement_score=1.0,
                consensus_confidence=0.94,
                participating_models=["gemini", "deepseek", "llama3.1 (local)"],
            ),
            ReportFinding(
                title="Reflected Cross-Site Scripting in error page",
                severity=Severity.HIGH,
                category="Cross-Site Scripting",
                cwe="CWE-79",
                owasp="A03:2021 – Injection",
                endpoint="https://www.example.com/search",
                method="GET",
                parameter="query",
                description=(
                    "The search results page reflects the 'query' parameter into the HTML "
                    "response without output encoding, allowing arbitrary script execution "
                    "in a victim's browser."
                ),
                evidence=[
                    "GET /search?query=<script>alert(document.domain)</script>",
                    "Response body contained the payload unescaped inside <h2>…</h2>",
                ],
                recommendation=(
                    "Context-aware output encoding on all reflected values, a strict "
                    "Content-Security-Policy, and framework auto-escaping (do not disable "
                    "it for this view)."
                ),
                references=["https://owasp.org/www-community/attacks/xss/"],
                consensus_status=ConsensusStatus.CONFIRMED,
                agreement_score=1.0,
                consensus_confidence=0.89,
                participating_models=["gemini", "deepseek", "llama3.1 (local)"],
            ),
            ReportFinding(
                title="Insecure Direct Object Reference on invoice download",
                severity=Severity.HIGH,
                category="Broken Access Control",
                cwe="CWE-639",
                owasp="A01:2021 – Broken Access Control",
                endpoint="https://api.example.com/v1/invoices/{id}",
                method="GET",
                parameter="id",
                description=(
                    "Invoice IDs are sequential integers and the endpoint does not verify "
                    "that the authenticated user owns the requested invoice, allowing "
                    "horizontal privilege escalation and disclosure of other customers' "
                    "billing data."
                ),
                evidence=[
                    "User A (invoice 1001) requested /v1/invoices/1002 → 200 with User B's data",
                ],
                recommendation=(
                    "Enforce an ownership check on every object access, and switch "
                    "sequential IDs to unguessable UUIDs as defense in depth."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                ],
                consensus_status=ConsensusStatus.LIKELY,
                agreement_score=0.75,
                consensus_confidence=0.78,
                participating_models=["gemini", "deepseek", "llama3.1 (local)"],
            ),
            ReportFinding(
                title="Missing security headers",
                severity=Severity.MEDIUM,
                category="Security Misconfiguration",
                cwe="CWE-693",
                owasp="A05:2021 – Security Misconfiguration",
                endpoint="https://www.example.com/",
                method="GET",
                description=(
                    "Responses omit Content-Security-Policy, Strict-Transport-Security, "
                    "X-Content-Type-Options and X-Frame-Options, weakening defense-in-depth "
                    "against XSS, clickjacking and protocol-downgrade attacks."
                ),
                evidence=[
                    "Response headers lacked: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options",
                ],
                recommendation=(
                    "Add HSTS (with preload), a restrictive CSP, X-Content-Type-Options: "
                    "nosniff and X-Frame-Options: DENY at the edge/reverse proxy."
                ),
                references=["https://owasp.org/www-project-secure-headers/"],
                consensus_status=ConsensusStatus.CONFIRMED,
                agreement_score=1.0,
                consensus_confidence=0.82,
                participating_models=["gemini", "deepseek", "llama3.1 (local)"],
            ),
            ReportFinding(
                title="Open redirect via 'next' parameter",
                severity=Severity.LOW,
                category="Open Redirect",
                cwe="CWE-601",
                owasp="A01:2021 – Broken Access Control",
                endpoint="https://www.example.com/login",
                method="GET",
                parameter="next",
                description=(
                    "The login flow redirects to an attacker-controlled absolute URL "
                    "supplied in 'next' after authentication, enabling phishing and OAuth "
                    "token theft chains."
                ),
                evidence=["GET /login?next=https://evil.example.net → 302 Location: https://evil.example.net"],
                recommendation=(
                    "Allow only relative paths or an explicit allow-list of hosts for "
                    "post-login redirects."
                ),
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
                consensus_status=ConsensusStatus.LIKELY,
                agreement_score=0.66,
                consensus_confidence=0.61,
                participating_models=["gemini", "deepseek", "llama3.1 (local)"],
            ),
            ReportFinding(
                title="Verbose server banner discloses software version",
                severity=Severity.INFO,
                category="Information Disclosure",
                cwe="CWE-200",
                owasp="A05:2021 – Security Misconfiguration",
                endpoint="https://staging.example.com/",
                method="GET",
                description=(
                    "The Server header and default error pages reveal exact software "
                    "versions, helping an attacker target known CVEs."
                ),
                evidence=["Server: Apache/2.4.57 (Ubuntu)"],
                recommendation="Suppress or genericize version banners (ServerTokens Prod).",
                references=[],
                consensus_status=ConsensusStatus.CONFIRMED,
                agreement_score=1.0,
                consensus_confidence=0.7,
                participating_models=["gemini", "deepseek", "llama3.1 (local)"],
            ),
        ],
    )
