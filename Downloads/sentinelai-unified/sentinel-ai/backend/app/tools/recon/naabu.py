"""naabu: fast port scanner. https://github.com/projectdiscovery/naabu

Takes its host/IP list via stdin, same pattern as dnsx/httpx.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.tools.base import SecurityTool

logger = logging.getLogger("sentinel.tools.naabu")


class NaabuTool(SecurityTool):
    name = "naabu"
    binary = "naabu"
    version = "2.x"
    timeout_seconds = 300

    def build_args(self, target: str, options: dict[str, Any]) -> list[str]:
        args = ["-silent", "-json"]
        top_ports = options.get("top_ports", 100)
        if isinstance(top_ports, int) and top_ports in (100, 1000):
            args += ["-top-ports", str(top_ports)]
        else:
            args += ["-top-ports", "100"]
        rate = options.get("rate")
        if isinstance(rate, (int, float)) and rate > 0:
            args += ["-rate", str(int(rate))]
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
                logger.warning("naabu: could not parse line: %r", line[:200])
                continue
            ip = obj.get("ip") or obj.get("host")
            port = obj.get("port")
            if ip is None or port is None:
                continue
            records.append({"ip": ip, "port": int(port), "protocol": obj.get("protocol", "tcp")})
        return records
