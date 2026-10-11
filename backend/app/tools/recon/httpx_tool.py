"""httpx: HTTP probing / tech fingerprinting. https://github.com/projectdiscovery/httpx

Takes its host list via stdin, same pattern as dnsx.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.tools.base import SecurityTool

logger = logging.getLogger("sentinel.tools.httpx")


class HttpxTool(SecurityTool):
    name = "httpx"
    binary = "httpx"
    version = "1.x"
    timeout_seconds = 180

    def build_args(self, target: str, options: dict[str, Any]) -> list[str]:
        args = [
            "-silent",
            "-json",
            "-title",
            "-tech-detect",
            "-status-code",
            "-content-length",
            "-web-server",
        ]
        rate_limit = options.get("rate_limit")
        if isinstance(rate_limit, (int, float)) and rate_limit > 0:
            args += ["-rate-limit", str(int(rate_limit))]
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
                logger.warning("httpx: could not parse line: %r", line[:200])
                continue
            url = obj.get("url")
            if not url:
                continue
            records.append(
                {
                    "url": url,
                    "hostname": obj.get("host") or obj.get("input", ""),
                    "status_code": obj.get("status_code"),
                    "title": obj.get("title"),
                    "technologies": obj.get("tech", []) or [],
                    "content_length": obj.get("content_length"),
                    "webserver": obj.get("webserver"),
                }
            )
        return records
