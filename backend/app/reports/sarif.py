"""
Export a :class:`ReportData` as SARIF 2.1.0 — the OASIS-standard JSON format
for static/security analysis results.

GitHub ingests SARIF natively: upload the file (or post it via the code
scanning API) and each finding shows up in the repository's
**Security → Code scanning** tab and inline on pull requests. GitLab, Azure
DevOps and VS Code consume the same format.

Key mappings GitHub relies on:
  * ``level``                      — error | warning | note
  * ``properties.security-severity`` — a "0.0"–"10.0" string that drives the
    Critical/High/Medium/Low label in the Security tab.
"""
from __future__ import annotations

from .schemas import ReportData, ReportFinding, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "SentinelAI"
TOOL_VERSION = "1.0.0"
TOOL_URI = "https://github.com/MadihaSehar/Sentinel_AI"

# Severity → SARIF result level.
_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Severity → GitHub `security-severity` (numeric CVSS-style string).
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}


def _rule_id(f: ReportFinding) -> str:
    """Stable rule identifier — prefer the CWE, else a slug of the category."""
    if f.cwe:
        return f.cwe.replace(" ", "")
    slug = "".join(c if c.isalnum() else "-" for c in f.category.lower()).strip("-")
    return f"sentinelai-{slug or 'finding'}"


def _build_rules(findings: list[ReportFinding]) -> list[dict]:
    """One rule per unique ruleId, in first-seen order."""
    rules: dict[str, dict] = {}
    for f in findings:
        rid = _rule_id(f)
        if rid in rules:
            continue
        rule: dict = {
            "id": rid,
            "name": f.category.replace(" ", ""),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description},
            "defaultConfiguration": {"level": _LEVEL[f.severity.value]},
            "properties": {
                "security-severity": _SECURITY_SEVERITY[f.severity.value],
                "tags": [t for t in ["security", f.category, f.owasp] if t],
            },
        }
        if f.references:
            rule["helpUri"] = f.references[0]
        if f.cwe:
            rule["properties"]["cwe"] = f.cwe
        rules[rid] = rule
    return list(rules.values())


def _build_result(f: ReportFinding) -> dict:
    location: dict = {
        "physicalLocation": {
            "artifactLocation": {"uri": f.endpoint},
        }
    }
    message = f.description
    if f.recommendation:
        message += f"\n\nRemediation: {f.recommendation}"

    return {
        "ruleId": _rule_id(f),
        "level": _LEVEL[f.severity.value],
        "message": {"text": message},
        "locations": [location],
        "properties": {
            "severity": f.severity.value,
            "security-severity": _SECURITY_SEVERITY[f.severity.value],
            "method": f.method,
            "parameter": f.parameter,
            "consensus_status": f.consensus_status.value,
            "agreement_score": f.agreement_score,
            "consensus_confidence": f.consensus_confidence,
            "participating_models": f.participating_models,
        },
    }


def build_sarif(data: ReportData) -> dict:
    """Render ``data`` as a SARIF 2.1.0 log (a JSON-serializable dict)."""
    findings = data.sorted_findings()
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": _build_rules(findings),
                    }
                },
                "properties": {
                    "target": data.target,
                    "assessment": data.assessment_name,
                    "generated_at": data.generated_at.isoformat(),
                },
                "results": [_build_result(f) for f in findings],
            }
        ],
    }
