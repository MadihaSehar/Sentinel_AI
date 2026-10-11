"""
Render a :class:`ReportData` into a polished, self-contained HTML report,
and (optionally) convert that HTML to PDF.

The HTML is deliberately written against the CSS subset that ``xhtml2pdf``
understands (tables for layout, no fl/ex/grid, inline-ish styles) so the
*same* markup renders correctly both in a browser and in the exported PDF.
Everything is inlined — no external fonts, CSS or images — so a saved
``.html`` file is fully portable and a generated PDF needs no network.

PDF generation uses ``xhtml2pdf`` which is pure-Python (no Cairo/Pango
system libraries), so it works unchanged in CI and slim Docker images.
"""
from __future__ import annotations

import html
import io
from datetime import datetime

from .schemas import ReportData, ReportFinding, Severity

# Severity → (text color, background tint, border) — chosen to read well on
# white paper and in print, and to survive xhtml2pdf's color handling.
_SEV_STYLE: dict[str, tuple[str, str, str]] = {
    "critical": ("#7f1d1d", "#fee2e2", "#dc2626"),
    "high": ("#9a3412", "#ffedd5", "#ea580c"),
    "medium": ("#854d0e", "#fef9c3", "#ca8a04"),
    "low": ("#075985", "#e0f2fe", "#0284c7"),
    "info": ("#334155", "#f1f5f9", "#64748b"),
}

_RATING_COLOR = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#ca8a04",
    "Low": "#0284c7",
    "Informational": "#64748b",
}


def _e(value: object) -> str:
    """HTML-escape any value."""
    return html.escape(str(value), quote=True)


def _badge(sev: Severity) -> str:
    fg, bg, border = _SEV_STYLE[sev.value]
    return (
        f'<span style="background-color:{bg};color:{fg};border:1px solid {border};'
        f'border-radius:3px;padding:1px 6px;font-size:9px;font-weight:bold;'
        f'text-transform:uppercase;">{_e(sev.value)}</span>'
    )


def _consensus_label(f: ReportFinding) -> str:
    return f.consensus_status.value.replace("_", " ").title()


def _severity_summary_table(data: ReportData) -> str:
    counts = data.severity_counts()
    cells = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        fg, bg, border = _SEV_STYLE[sev]
        cells.append(
            f'<td align="center" width="20%" '
            f'style="background-color:{bg};border:1px solid {border};padding:10px;">'
            f'<div style="font-size:22px;font-weight:bold;color:{fg};">{counts[sev]}</div>'
            f'<div style="font-size:9px;color:{fg};text-transform:uppercase;letter-spacing:1px;">'
            f'{sev}</div></td>'
        )
    return (
        '<table width="100%" cellpadding="0" cellspacing="4" '
        'style="margin:12px 0;"><tr>' + "".join(cells) + "</tr></table>"
    )


def _finding_block(index: int, f: ReportFinding) -> str:
    fg, bg, border = _SEV_STYLE[f.severity.value]

    meta_rows = [
        ("Category", f.category),
        ("Endpoint", f"{f.method} {f.endpoint}"),
    ]
    if f.parameter:
        meta_rows.append(("Parameter", f.parameter))
    if f.cwe:
        meta_rows.append(("CWE", f.cwe))
    if f.owasp:
        meta_rows.append(("OWASP", f.owasp))
    meta_rows.append(("CVSS band", f.severity.cvss_band))

    meta_html = "".join(
        f'<tr><td width="28%" style="padding:3px 8px;color:#64748b;font-size:10px;">{_e(k)}</td>'
        f'<td style="padding:3px 8px;font-size:10px;font-family:monospace;color:#0f172a;">{_e(v)}</td></tr>'
        for k, v in meta_rows
    )

    evidence_html = ""
    if f.evidence:
        items = "".join(
            f'<div style="font-family:monospace;font-size:9px;background-color:#0f172a;'
            f'color:#e2e8f0;padding:6px 8px;margin:3px 0;border-radius:3px;">{_e(ev)}</div>'
            for ev in f.evidence
        )
        evidence_html = (
            '<div style="margin-top:8px;"><div style="font-size:10px;font-weight:bold;'
            'color:#334155;margin-bottom:2px;">Evidence</div>' + items + "</div>"
        )

    refs_html = ""
    if f.references:
        items = "".join(f"<li style='font-size:9px;color:#0369a1;'>{_e(r)}</li>" for r in f.references)
        refs_html = (
            '<div style="margin-top:6px;"><div style="font-size:10px;font-weight:bold;'
            'color:#334155;">References</div><ul style="margin:2px 0 0 14px;padding:0;">'
            + items
            + "</ul></div>"
        )

    models = ", ".join(f.participating_models) if f.participating_models else "—"
    consensus_html = (
        '<table width="100%" cellpadding="0" cellspacing="0" '
        'style="margin-top:8px;background-color:#f8fafc;border:1px solid #e2e8f0;border-radius:4px;">'
        '<tr><td style="padding:6px 8px;">'
        '<span style="font-size:9px;font-weight:bold;color:#334155;text-transform:uppercase;'
        'letter-spacing:1px;">AI Consensus</span><br/>'
        f'<span style="font-size:10px;color:#0f172a;">Verdict: <b>{_e(_consensus_label(f))}</b> '
        f'&nbsp;|&nbsp; Agreement: <b>{f.agreement_score:.0%}</b> '
        f'&nbsp;|&nbsp; Confidence: <b>{f.consensus_confidence:.0%}</b></span><br/>'
        f'<span style="font-size:9px;color:#64748b;">Models: {_e(models)}</span>'
        "</td></tr></table>"
    )

    return (
        f'<div style="border:1px solid #e2e8f0;border-left:4px solid {border};'
        f'border-radius:4px;padding:12px 14px;margin:10px 0;">'
        f'<table width="100%" cellpadding="0" cellspacing="0"><tr>'
        f'<td style="font-size:13px;font-weight:bold;color:#0f172a;">{index}. {_e(f.title)}</td>'
        f'<td align="right">{_badge(f.severity)}</td>'
        f"</tr></table>"
        f'<table width="100%" cellpadding="0" cellspacing="0" style="margin-top:6px;">{meta_html}</table>'
        f'<div style="font-size:11px;color:#1e293b;margin-top:8px;line-height:1.5;">{_e(f.description)}</div>'
        f"{evidence_html}"
        f'<div style="margin-top:8px;background-color:#ecfdf5;border:1px solid #a7f3d0;'
        f'border-radius:4px;padding:8px;"><span style="font-size:10px;font-weight:bold;'
        f'color:#065f46;text-transform:uppercase;letter-spacing:1px;">Remediation</span>'
        f'<div style="font-size:11px;color:#064e3b;margin-top:2px;line-height:1.5;">{_e(f.recommendation)}</div></div>'
        f"{refs_html}"
        f"{consensus_html}"
        f"</div>"
    )


def build_report_html(data: ReportData) -> str:
    """Render ``data`` into a complete, standalone HTML document."""
    generated = data.generated_at
    if isinstance(generated, datetime):
        generated_str = generated.strftime("%Y-%m-%d %H:%M UTC")
    else:  # pragma: no cover - defensive
        generated_str = str(generated)

    rating = data.risk_rating()
    rating_color = _RATING_COLOR[rating]
    score = data.risk_score()

    findings_sorted = data.sorted_findings()
    findings_html = (
        "".join(_finding_block(i + 1, f) for i, f in enumerate(findings_sorted))
        or '<div style="color:#64748b;font-size:11px;font-style:italic;">'
        "No vulnerabilities were confirmed in this assessment.</div>"
    )

    # Attack-surface appendix
    asset_rows = "".join(
        f"<tr><td style='padding:4px 8px;font-size:10px;font-family:monospace;'>{_e(a.hostname)}</td>"
        f"<td style='padding:4px 8px;font-size:10px;'>{_e(', '.join(a.ip_addresses) or '—')}</td>"
        f"<td style='padding:4px 8px;font-size:10px;'>{_e(', '.join(a.technologies) or '—')}</td>"
        f"<td style='padding:4px 8px;font-size:10px;'>{_e(', '.join(str(p) for p in a.open_ports) or '—')}</td></tr>"
        for a in data.assets
    ) or "<tr><td colspan='4' style='padding:6px 8px;font-size:10px;color:#64748b;'>No assets recorded.</td></tr>"

    subdomains_html = (
        ", ".join(_e(s) for s in data.subdomains) if data.subdomains else "—"
    )
    tools_html = ", ".join(_e(t) for t in data.tools_used) if data.tools_used else "—"

    auth_html = ""
    if data.authorization_statement or data.authorized_by:
        auth_html = (
            '<div style="margin-top:6px;font-size:10px;color:#475569;">'
            f'<b>Authorization:</b> {_e(data.authorization_statement or "Confirmed")}'
            + (f" &nbsp;|&nbsp; <b>By:</b> {_e(data.authorized_by)}" if data.authorized_by else "")
            + "</div>"
        )

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<title>SentinelAI Report — {_e(data.target)}</title>
<style>
  @page {{ size: A4; margin: 1.6cm; }}
  body {{ font-family: Helvetica, Arial, sans-serif; color: #0f172a; margin: 0; }}
  h2 {{ font-size: 14px; color: #0f172a; border-bottom: 2px solid #0ea5e9;
        padding-bottom: 4px; margin: 20px 0 8px 0; }}
  .muted {{ color: #64748b; font-size: 10px; }}
  table {{ border-collapse: collapse; }}
</style>
</head>
<body>

  <!-- Cover / header -->
  <table width="100%" cellpadding="0" cellspacing="0"
         style="background-color:#0f172a;border-radius:6px;">
    <tr><td style="padding:18px 20px;">
      <div style="font-size:11px;color:#38bdf8;letter-spacing:3px;font-weight:bold;">
        SENTINELAI &nbsp;·&nbsp; SECURITY ASSESSMENT REPORT</div>
      <div style="font-size:24px;color:#ffffff;font-weight:bold;margin-top:6px;">{_e(data.target)}</div>
      <div style="font-size:11px;color:#94a3b8;margin-top:4px;">
        {_e(data.assessment_name)} &nbsp;·&nbsp; {_e(data.assessment_type)} &nbsp;·&nbsp; {generated_str}</div>
    </td></tr>
  </table>
  {auth_html}

  <!-- Executive summary -->
  <h2>Executive Summary</h2>
  <table width="100%" cellpadding="0" cellspacing="0"><tr>
    <td width="62%" style="vertical-align:top;font-size:11px;color:#1e293b;line-height:1.6;padding-right:14px;">
      SentinelAI performed an automated, AI-verified security assessment of
      <b>{_e(data.target)}</b>. The scan mapped the target's attack surface and ran
      vulnerability checks whose results were then independently reviewed by multiple
      AI models, with only cross-validated findings promoted into this report to
      minimise false positives.
    </td>
    <td width="38%" align="center"
        style="background-color:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:12px;">
      <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;">Overall Risk</div>
      <div style="font-size:30px;font-weight:bold;color:{rating_color};">{rating}</div>
      <div style="font-size:10px;color:#64748b;">Risk score: {score}/100</div>
    </td>
  </tr></table>

  {_severity_summary_table(data)}

  <!-- Findings -->
  <h2>Findings</h2>
  {findings_html}

  <!-- Attack surface appendix -->
  <h2>Attack Surface</h2>
  <div class="muted" style="margin-bottom:4px;"><b>Subdomains:</b> {subdomains_html}</div>
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e2e8f0;">
    <tr style="background-color:#f1f5f9;">
      <th align="left" style="padding:5px 8px;font-size:9px;color:#475569;text-transform:uppercase;">Host</th>
      <th align="left" style="padding:5px 8px;font-size:9px;color:#475569;text-transform:uppercase;">IPs</th>
      <th align="left" style="padding:5px 8px;font-size:9px;color:#475569;text-transform:uppercase;">Technologies</th>
      <th align="left" style="padding:5px 8px;font-size:9px;color:#475569;text-transform:uppercase;">Open Ports</th>
    </tr>
    {asset_rows}
  </table>

  <!-- Methodology -->
  <h2>Methodology & Tooling</h2>
  <div class="muted" style="line-height:1.6;">
    <b>Tools:</b> {tools_html}<br/>
    Pipeline: Reconnaissance → DNS → HTTP Discovery → Port Scan → Crawl →
    Directory Scan → Nuclei → Multi-Model AI Consensus → Reporting.
  </div>

  <!-- Disclaimer -->
  <div style="margin-top:22px;border-top:1px solid #e2e8f0;padding-top:8px;">
    <div class="muted" style="line-height:1.5;">
      This report was generated by SentinelAI for an authorized security assessment.
      Findings are AI-assisted and should be validated by a qualified security
      professional before remediation decisions. Unauthorized scanning of systems
      you do not own or have explicit written permission to test is illegal.
    </div>
  </div>

</body>
</html>"""


class PDFGenerationError(RuntimeError):
    """Raised when the PDF backend fails or is unavailable."""


def render_pdf(html_str: str) -> bytes:
    """Convert an HTML document string into PDF bytes via xhtml2pdf."""
    try:
        from xhtml2pdf import pisa  # lazy import: HTML rendering never needs it
    except ImportError as exc:  # pragma: no cover - only if dep missing
        raise PDFGenerationError(
            "PDF generation requires the 'xhtml2pdf' package (pip install xhtml2pdf)."
        ) from exc

    buffer = io.BytesIO()
    result = pisa.CreatePDF(src=html_str, dest=buffer, encoding="utf-8")
    if result.err:
        raise PDFGenerationError(f"xhtml2pdf reported {result.err} error(s) while rendering the report.")
    return buffer.getvalue()


def build_report_pdf(data: ReportData) -> bytes:
    """Build the report HTML and render it straight to PDF bytes."""
    return render_pdf(build_report_html(data))
