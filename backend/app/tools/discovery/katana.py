"""katana: web crawler. https://github.com/projectdiscovery/katana

Takes its seed URL(s) via stdin (one per line), consistent with the
dnsx/httpx pattern, so results can be batched across many hosts at once.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.tools.base import SecurityTool

logger = logging.getLogger("sentinel.tools.katana")


class KatanaTool(SecurityTool):
    name = "katana"
    binary = "katana"
    version = "1.x"
    timeout_seconds = 240

    def build_args(self, target: str, options: dict[str, Any]) -> list[str]:
        args = ["-silent", "-jsonl", "-no-color"]
        depth = options.get("depth", 3)
        if isinstance(depth, int) and 0 < depth <= 10:
            args += ["-depth", str(depth)]
        if options.get("js_crawl", True):
            args.append("-jc")
        rate_limit = options.get("rate_limit")
        if isinstance(rate_limit, (int, float)) and rate_limit > 0:
            args += ["-rate-limit", str(int(rate_limit))]
        return args

    def normalize_output(self, raw_stdout: str) -> list[dict]:
        """katana -jsonl: {"timestamp":..., "request": {"method":...,"endpoint":...}, "response": {"status_code":...}}"""
        records: list[dict] = []
        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("katana: could not parse line: %r", line[:200])
                continue
            request = obj.get("request", {})
            response = obj.get("response", {})
            url = request.get("endpoint") or obj.get("url")
            if not url:
                continue
            records.append(
                {
                    "url": url,
                    "method": request.get("method", "GET"),
                    "source": "katana",
                    "status_code": response.get("status_code"),
                    "content_type": response.get("headers", {}).get("content_type"),
                }
            )
        return records
