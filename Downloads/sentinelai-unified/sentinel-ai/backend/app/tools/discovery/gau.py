"""gau (getallurls): historical URLs from Wayback/CommonCrawl/OTX/URLScan.
https://github.com/lc/gau

Takes domain(s) via stdin, one per line.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.tools.base import SecurityTool

logger = logging.getLogger("sentinel.tools.gau")


class GauTool(SecurityTool):
    name = "gau"
    binary = "gau"
    version = "2.x"
    timeout_seconds = 180
    max_output_bytes = 25 * 1024 * 1024  # historical URL dumps can be large

    def build_args(self, target: str, options: dict[str, Any]) -> list[str]:
        args = ["--json"]
        if options.get("subdomains", True):
            args.append("--subs")
        threads = options.get("threads")
        if isinstance(threads, int) and 0 < threads <= 50:
            args += ["--threads", str(threads)]
        blocklist = options.get("blocklist_extensions")
        if blocklist:
            args += ["--blacklist", ",".join(blocklist)]
        return args

    def normalize_output(self, raw_stdout: str) -> list[dict]:
        records: list[dict] = []
        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("gau: could not parse line: %r", line[:200])
                continue
            url = obj.get("url")
            if url:
                records.append({"url": url, "source": "gau", "status_code": obj.get("status")})
        return records
