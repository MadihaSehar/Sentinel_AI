"""
Render a :class:`DiffResult` into an HTML report (and PDF), styled to match
the main report: a trend banner, a New / Fixed / Still-open summary, then the
findings grouped into those three buckets.
"""
from __future__ import annotations

from .builder import _SEV_STYLE, _badge, _e, render_pdf
from .diff import ChangedFinding, DiffResult
from .schemas import ReportFinding

_BUCKET_STYLE = {
    "new": ("#7f1d1d", "#fee2e2", "#dc2626", "New"),
    "still_open": ("#854d0e", "#fef9c3", "#ca8a04", "Still Open"),
    "fixed": ("#065f46", "#d1fae5", "#059669", "Fixed"),
}

_TREND_COLOR = {
    "Improved": "#059669",
    "Regressed": "#dc2626",
    "Mixed": "#ca8a04",
    "No change": "#64748b",
}


def _summary_card(label: str, value: int, key: str) -> str:
    fg, bg, border, _ = _BUCKET_STYLE[key]
    return (
        f'<td align="center" width="33%" '
        f'style="background-color:{bg};border:1px solid {border};padding:12px;">'
        f'<div style="font-size:26px;font-weight:bold;color:{fg};">{value}</div>'
        f'<div style="font-size:10px;color:{fg};text-transform:uppercase;letter-spacing:1px;">'
        f"{label}</div></td>"
    )


def _finding_row(f: ReportFinding, note: str = "") -> str:
    fg, bg, border = _SEV_STYLE[f.severity.value]
    meta = f"{f.method} {f.endpoint}"
    if f.parameter:
        meta += f" &nbsp;·&nbsp; param: {_e(f.parameter)}"
    note_html = (
        f'<span style="font-size:9px;color:#b45309;font-weight:bold;">&nbsp;{_e(note)}</span>'
        if note
        else ""
    )
    return (
        f'<div style="border:1px solid #e2e8f0;border-left:4px solid {border};'
        f'border-radius:4px;padding:8px 10px;margin:6px 0;">'
        f'<table width="100%" cellpadding="0" cellspacing="0"><tr>'
        f'<td style="font-size:12px;font-weight:bold;color:#0f172a;">{_e(f.title)}{note_html}</td>'
        f'<td align="right">{_badge(f.severity)}</td></tr></table>'
        f'<div style="font-size:9px;font-family:monospace;color:#475569;margin-top:3px;">{meta}</div>'
        f"</div>"
    )


def _bucket_section(key: str, findings: list[ReportFinding], changed: list[ChangedFinding] | None = None) -> str:
    fg, bg, border, label = _BUCKET_STYLE[key]
    count = len(changed) if changed is not None else len(findings)
    header = (
        f'<table width="100%" cellpadding="0" cellspacing="0" style="margin-top:16px;">'
        f'<tr><td style="border-bottom:2px solid {border};padding-bottom:4px;">'
        f'<span style="font-size:14px;font-weight:bold;color:{fg};">{label}</span> '
        f'<span style="font-size:11px;color:#64748b;">({count})</span></td></tr></table>'
    )
    if changed is not None:
        if not changed:
            return header + '<div style="font-size:10px;color:#64748b;font-style:italic;margin-top:4px;">None.</div>'
        rows = "".join(
            _finding_row(
                c.finding,
                note=(
                    f"severity {c.previous_severity.value} → {c.finding.severity.value}"
                    if c.severity_changed
                    else ""
                ),
            )
            for c in changed
        )
        return header + rows
    if not findings:
        return header + '<div style="font-size:10px;color:#64748b;font-style:italic;margin-top:4px;">None.</div>'
    return header + "".join(_finding_row(f) for f in findings)


def build_diff_html(diff: DiffResult) -> str:
    counts = diff.counts()
    trend = diff.trend()
    trend_color = _TREND_COLOR[trend]

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<title>SentinelAI Diff — {_e(diff.current_target)}</title>
<style>
  @page {{ size: A4; margin: 1.6cm; }}
  body {{ font-family: Helvetica, Arial, sans-serif; color: #0f172a; margin: 0; }}
  h2 {{ font-size: 14px; border-bottom: 2px solid #0ea5e9; padding-bottom: 4px; margin: 20px 0 8px 0; }}
  .muted {{ color: #64748b; font-size: 10px; }}
  table {{ border-collapse: collapse; }}
</style>
</head>
<body>
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0f172a;border-radius:6px;">
    <tr><td style="padding:18px 20px;">
      <div style="font-size:11px;color:#38bdf8;letter-spacing:3px;font-weight:bold;">
        SENTINELAI &nbsp;·&nbsp; SCAN COMPARISON</div>
      <div style="font-size:22px;color:#ffffff;font-weight:bold;margin-top:6px;">{_e(diff.current_target)}</div>
      <div style="font-size:11px;color:#94a3b8;margin-top:4px;">
        Baseline: {_e(diff.baseline_name)} &nbsp;→&nbsp; Current: {_e(diff.current_name)}</div>
    </td></tr>
  </table>

  <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:10px;">
    <tr><td style="background-color:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:10px 14px;">
      <span style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px;">Trend</span>
      &nbsp;<span style="font-size:16px;font-weight:bold;color:{trend_color};">{trend}</span>
      <span style="font-size:11px;color:#475569;">
        &nbsp;&nbsp;{counts['fixed']} fixed · {counts['new']} new · {counts['still_open']} still open</span>
    </td></tr>
  </table>

  <table width="100%" cellpadding="0" cellspacing="6" style="margin:12px 0;"><tr>
    {_summary_card("New", counts['new'], "new")}
    {_summary_card("Still Open", counts['still_open'], "still_open")}
    {_summary_card("Fixed", counts['fixed'], "fixed")}
  </tr></table>

  {_bucket_section("new", diff.new)}
  {_bucket_section("still_open", [], diff.still_open)}
  {_bucket_section("fixed", diff.fixed)}

  <div style="margin-top:22px;border-top:1px solid #e2e8f0;padding-top:8px;">
    <div class="muted" style="line-height:1.5;">
      Findings are matched across scans by (vulnerability rule, method, endpoint, parameter).
      "Fixed" means a baseline finding no longer appears in the current scan; verify fixes
      manually before closing them. Generated by SentinelAI.
    </div>
  </div>
</body>
</html>"""


def build_diff_pdf(diff: DiffResult) -> bytes:
    return render_pdf(build_diff_html(diff))
