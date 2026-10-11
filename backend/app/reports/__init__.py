"""Report generation: build a self-contained HTML/PDF security report."""
from .builder import (
    PDFGenerationError,
    build_report_html,
    build_report_pdf,
    render_pdf,
)
from .sample_data import build_sample_report
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
    "build_sarif",
    "ReportData",
    "ReportFinding",
    "ReportAsset",
    "Severity",
    "ConsensusStatus",
]
