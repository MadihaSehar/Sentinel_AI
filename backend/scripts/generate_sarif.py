#!/usr/bin/env python3
"""
Generate a SARIF file for upload to GitHub code scanning.

Two modes, chosen automatically from the environment:

  * **Live** — if SENTINEL_API_URL, SENTINEL_TOKEN and SENTINEL_ASSESSMENT_ID
    are all set, fetch real SARIF from a running SentinelAI instance:
        GET {SENTINEL_API_URL}/reports/assessments/{id}?format=sarif
  * **Sample** — otherwise, emit the bundled demo SARIF so the workflow is
    runnable out of the box (and so a first run proves the upload path end
    to end in your repo's Security tab).

Usage:
    python scripts/generate_sarif.py [output_path]   # default: results.sarif
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Make `app` importable whether run from repo root or backend/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _from_live_api(api_url: str, token: str, assessment_id: str) -> dict:
    import httpx

    url = f"{api_url.rstrip('/')}/reports/assessments/{assessment_id}"
    resp = httpx.get(
        url,
        params={"format": "sarif"},
        headers={"Authorization": f"Bearer {token}"},
        timeout=60.0,
    )
    resp.raise_for_status()
    return resp.json()


def main() -> int:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results.sarif")

    api_url = os.getenv("SENTINEL_API_URL")
    token = os.getenv("SENTINEL_TOKEN")
    assessment_id = os.getenv("SENTINEL_ASSESSMENT_ID")

    if api_url and token and assessment_id:
        print(f"Fetching SARIF for assessment {assessment_id} from {api_url}")
        sarif = _from_live_api(api_url, token, assessment_id)
    else:
        print("No live credentials set — generating the bundled sample SARIF.")
        from app.reports import build_sample_report, build_sarif

        sarif = build_sarif(build_sample_report())

    output.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    n = len(sarif.get("runs", [{}])[0].get("results", []))
    print(f"Wrote {n} result(s) to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
