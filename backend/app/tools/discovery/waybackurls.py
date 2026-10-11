"""waybackurls: fetch known URLs from the Wayback Machine.
https://github.com/tomnomnom/waybackurls

Takes domain(s) via stdin, one per line. Output is plain text (one URL
per line) — there is no JSON mode for this tool.
"""

from __future__ import annotations

import logging
from typing import Any

from app.tools.base import SecurityTool

logger = logging.getLogger("sentinel.tools.waybackurls")


class WaybackurlsTool(SecurityTool):
    name = "waybackurls"
    binary = "waybackurls"
    version = "latest"
    timeout_seconds = 180
    max_output_bytes = 25 * 1024 * 1024

    def build_args(self, target: str, options: dict[str, Any]) -> list[str]:
        args = []
        if options.get("include_subs", True):
            args.append("--get-versions") if options.get("get_versions") else None
        return [a for a in args if a]

    def normalize_output(self, raw_stdout: str) -> list[dict]:
        records: list[dict] = []
        for line in raw_stdout.splitlines():
            url = line.strip()
            if not url:
                continue
            if not (url.startswith("http://") or url.startswith("https://")):
                logger.warning("waybackurls: skipping malformed line: %r", url[:200])
                continue
            records.append({"url": url, "source": "waybackurls", "status_code": None})
        return records
