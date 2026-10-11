#!/usr/bin/env python3
"""
Compare two exported SentinelAI scans and write a diff report.

Each input may be a SentinelAI report JSON (produced with ?format=json) or a
SARIF file (?format=sarif). The output format is chosen from the output
extension: ``.pdf`` → PDF, anything else → HTML.

Usage:
    python scripts/diff_reports.py baseline.json current.json -o diff.html
    python scripts/diff_reports.py old.sarif new.sarif -o diff.pdf
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _load(path: Path):
    from app.reports import load_report_data

    return load_report_data(json.loads(path.read_text(encoding="utf-8")))


def main() -> int:
    parser = argparse.ArgumentParser(description="Diff two SentinelAI scan exports.")
    parser.add_argument("baseline", type=Path, help="Older scan (JSON or SARIF)")
    parser.add_argument("current", type=Path, help="Newer scan (JSON or SARIF)")
    parser.add_argument(
        "-o", "--output", type=Path, default=Path("diff.html"),
        help="Output file (.html or .pdf). Default: diff.html",
    )
    args = parser.parse_args()

    from app.reports import build_diff_html, build_diff_pdf, diff_reports

    diff = diff_reports(_load(args.baseline), _load(args.current))

    if args.output.suffix.lower() == ".pdf":
        args.output.write_bytes(build_diff_pdf(diff))
    else:
        args.output.write_text(build_diff_html(diff), encoding="utf-8")

    c = diff.counts()
    print(
        f"Trend: {diff.trend()}  |  {c['fixed']} fixed, {c['new']} new, "
        f"{c['still_open']} still open  →  {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
