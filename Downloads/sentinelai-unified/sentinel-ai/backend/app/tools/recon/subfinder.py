"""subfinder: passive subdomain enumeration. https://github.com/projectdiscovery/subfinder"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.tools.base import SecurityTool

logger = logging.getLogger("sentinel.tools.subfinder")


class SubfinderTool(SecurityTool):
    name = "subfinder"
    binary = "subfinder"
    version = "2.x"
    timeout_seconds = 180

    def build_args(self, target: str, options: dict[str, Any]) -> list[str]:
        args = ["-d", target, "-silent", "-oJ", "-json"]
        if options.get("all_sources"):
            args.append("-all")
        max_time = options.get("max_enum_time_minutes")
        if isinstance(max_time, int) and 0 < max_time <= 30:
            args += ["-timeout", str(max_time)]
        return args

    def normalize_output(self, raw_stdout: str) -> list[dict]:
        """subfinder -oJ emits one JSON object per line: {"host": "...", "source": "..."}"""
        records: list[dict] = []
        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("subfinder: could not parse line: %r", line[:200])
                continue
            host = obj.get("host")
            if host:
                records.append({"hostname": host, "source_tool": "subfinder"})
        return records
