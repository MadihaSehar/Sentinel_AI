"""
Scan-to-scan diff: compare two assessment snapshots and bucket every
finding as **new**, **fixed**, or **still-open**.

This is file-based: it loads two report snapshots (SentinelAI's own JSON
export, or a SARIF file) and compares them, so it works today without the
findings needing to live in the database. The same ``diff_reports`` engine
can later be fed two DB-loaded ``ReportData`` instances unchanged.

Two findings are "the same" when their *identity key* matches:
``(rule, method, endpoint, parameter)`` — where ``rule`` is the CWE if
present else the category. Severity is deliberately NOT part of the key, so
a finding whose severity changed between scans is still recognised as the
same finding (and flagged as changed).
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from .schemas import ConsensusStatus, ReportData, ReportFinding, Severity

# Identity key: (rule, method, endpoint, parameter)
FindingKey = tuple[str, str, str, str]


def _normalize_endpoint(endpoint: str) -> str:
    e = endpoint.strip().lower()
    # Drop a trailing slash (but keep a bare "/").
    if len(e) > 1 and e.endswith("/"):
        e = e.rstrip("/")
    return e


def _rule_of(f: ReportFinding) -> str:
    if f.cwe:
        return f.cwe.replace(" ", "")
    return f.category.strip().lower()


def finding_key(f: ReportFinding) -> FindingKey:
    return (
        _rule_of(f),
        f.method.strip().upper(),
        _normalize_endpoint(f.endpoint),
        (f.parameter or "").strip().lower(),
    )


# --------------------------------------------------------------------------- #
# Diff result model
# --------------------------------------------------------------------------- #
class ChangedFinding(BaseModel):
    """A finding present in both scans, carrying any severity change."""

    finding: ReportFinding
    previous_severity: Severity
    severity_changed: bool


class DiffResult(BaseModel):
    baseline_target: str
    current_target: str
    baseline_name: str
    current_name: str

    new: list[ReportFinding] = Field(default_factory=list)
    fixed: list[ReportFinding] = Field(default_factory=list)
    still_open: list[ChangedFinding] = Field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "still_open": len(self.still_open),
        }

    def _sev_breakdown(self, findings: list[ReportFinding]) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in findings:
            out[f.severity.value] += 1
        return out

    def severity_breakdown(self) -> dict[str, dict[str, int]]:
        return {
            "new": self._sev_breakdown(self.new),
            "fixed": self._sev_breakdown(self.fixed),
            "still_open": self._sev_breakdown([c.finding for c in self.still_open]),
        }

    def trend(self) -> str:
        """A one-line human verdict comparing the two scans."""
        n, fx = len(self.new), len(self.fixed)
        if n == 0 and fx > 0:
            return "Improved"
        if n > 0 and fx == 0:
            return "Regressed"
        if n == 0 and fx == 0:
            return "No change"
        return "Mixed"


def diff_reports(baseline: ReportData, current: ReportData) -> DiffResult:
    """Compare ``baseline`` (older) against ``current`` (newer)."""
    base_by_key: dict[FindingKey, ReportFinding] = {
        finding_key(f): f for f in baseline.findings
    }
    curr_by_key: dict[FindingKey, ReportFinding] = {
        finding_key(f): f for f in current.findings
    }

    new: list[ReportFinding] = []
    still_open: list[ChangedFinding] = []
    for key, f in curr_by_key.items():
        prev = base_by_key.get(key)
        if prev is None:
            new.append(f)
        else:
            still_open.append(
                ChangedFinding(
                    finding=f,
                    previous_severity=prev.severity,
                    severity_changed=prev.severity != f.severity,
                )
            )

    fixed = [f for key, f in base_by_key.items() if key not in curr_by_key]

    # Most severe first within each bucket.
    new.sort(key=lambda f: f.severity.rank, reverse=True)
    fixed.sort(key=lambda f: f.severity.rank, reverse=True)
    still_open.sort(key=lambda c: c.finding.severity.rank, reverse=True)

    return DiffResult(
        baseline_target=baseline.target,
        current_target=current.target,
        baseline_name=baseline.assessment_name,
        current_name=current.assessment_name,
        new=new,
        fixed=fixed,
        still_open=still_open,
    )


# --------------------------------------------------------------------------- #
# Loaders — accept SentinelAI's own JSON export or a SARIF file
# --------------------------------------------------------------------------- #
class ReportLoadError(ValueError):
    """Raised when a file cannot be parsed as a known report format."""


def _severity_from_security_severity(value: str | None, fallback: str | None) -> Severity:
    if fallback:
        try:
            return Severity(fallback.strip().lower())
        except ValueError:
            pass
    try:
        score = float(value) if value is not None else 0.0
    except (TypeError, ValueError):
        score = 0.0
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def _report_from_sarif(data: dict) -> ReportData:
    try:
        run = data["runs"][0]
    except (KeyError, IndexError) as exc:
        raise ReportLoadError("SARIF file has no runs.") from exc

    driver = run.get("tool", {}).get("driver", {})
    rules_by_id = {r.get("id"): r for r in driver.get("rules", [])}
    props = run.get("properties", {})

    findings: list[ReportFinding] = []
    for res in run.get("results", []):
        rprops = res.get("properties", {})
        rule = rules_by_id.get(res.get("ruleId"), {})
        rule_props = rule.get("properties", {})

        # Endpoint from the first location.
        endpoint = "unknown"
        locs = res.get("locations") or []
        if locs:
            endpoint = (
                locs[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
                or endpoint
            )

        message = (res.get("message", {}) or {}).get("text", "") or ""
        description, _, remediation = message.partition("\n\nRemediation: ")

        severity = _severity_from_security_severity(
            rprops.get("security-severity") or rule_props.get("security-severity"),
            rprops.get("severity"),
        )

        consensus_raw = rprops.get("consensus_status")
        try:
            consensus = ConsensusStatus(consensus_raw) if consensus_raw else ConsensusStatus.REQUIRES_MANUAL_REVIEW
        except ValueError:
            consensus = ConsensusStatus.REQUIRES_MANUAL_REVIEW

        title = (rule.get("shortDescription", {}) or {}).get("text") or res.get("ruleId") or "Finding"
        category = rule.get("name") or "Uncategorized"
        cwe = rule_props.get("cwe") or (res.get("ruleId") if str(res.get("ruleId", "")).upper().startswith("CWE-") else None)

        findings.append(
            ReportFinding(
                title=title,
                severity=severity,
                category=category,
                cwe=cwe,
                endpoint=endpoint,
                method=rprops.get("method", "GET") or "GET",
                parameter=rprops.get("parameter"),
                description=description or title,
                recommendation=remediation or "",
                consensus_status=consensus,
                agreement_score=float(rprops.get("agreement_score", 0.0) or 0.0),
                consensus_confidence=float(rprops.get("consensus_confidence", 0.0) or 0.0),
                participating_models=list(rprops.get("participating_models", []) or []),
            )
        )

    return ReportData(
        target=props.get("target", "unknown"),
        assessment_name=props.get("assessment", "Imported SARIF scan"),
        findings=findings,
    )


def load_report_data(data: dict) -> ReportData:
    """Parse a report dict, auto-detecting SentinelAI JSON vs SARIF."""
    if not isinstance(data, dict):
        raise ReportLoadError("Report must be a JSON object.")
    if "runs" in data and "version" in data:
        return _report_from_sarif(data)
    if "findings" in data or "target" in data:
        try:
            return ReportData.model_validate(data)
        except Exception as exc:  # noqa: BLE001 - surface a clean message
            raise ReportLoadError(f"Not a valid SentinelAI report JSON: {exc}") from exc
    raise ReportLoadError("Unrecognized report format (expected SentinelAI JSON or SARIF).")
