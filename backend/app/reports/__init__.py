"""Report generation: build a self-contained HTML/PDF security report."""
from .builder import (
    PDFGenerationError,
    build_report_html,
    build_report_pdf,
    render_pdf,
)
from .diff import (
    DiffResult,
    ReportLoadError,
    diff_reports,
    load_report_data,
)
from .diff_builder import build_diff_html, build_diff_pdf
from .sample_data import build_sample_baseline_report, build_sample_report
from .sarif import build_sarif
from .schemas import (
    ConsensusStatus,
    ReportAsset,
    ReportData,
    ReportFinding,
    Severity,
)

__all__ = [
    "PDFGenerationError",
    "build_report_html",
    "build_report_pdf",
    "render_pdf",
    "build_sample_report",
    "build_sample_baseline_report",
    "build_sarif",
    "diff_reports",
    "load_report_data",
    "build_diff_html",
    "build_diff_pdf",
    "DiffResult",
    "ReportLoadError",
    "ReportData",
    "ReportFinding",
    "ReportAsset",
    "Severity",
    "ConsensusStatus",
]
