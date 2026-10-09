"""dnsx: fast DNS resolver/record retriever. https://github.com/projectdiscovery/dnsx

Takes its target list via stdin (one hostname per line), not as a CLI arg,
so `target` here is unused in build_args and the caller passes the
newline-joined host list as stdin_data to execute().
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.tools.base import SecurityTool

logger = logging.getLogger("sentinel.tools.dnsx")

_RECORD_FLAGS = {
    "a": "-a",
    "aaaa": "-aaaa",
    "cname": "-cname",
    "ns": "-ns",
    "mx": "-mx",
    "txt": "-txt",
}


class DnsxTool(SecurityTool):
    name = "dnsx"
    binary = "dnsx"
    version = "1.x"
    timeout_seconds = 120

    def build_args(self, target: str, options: dict[str, Any]) -> list[str]:
        record_types = options.get("record_types") or ["a", "aaaa", "cname"]
        args = ["-silent", "-json", "-resp"]
        for rt in record_types:
            flag = _RECORD_FLAGS.get(rt.lower())
            if flag:
                args.append(flag)
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
                logger.warning("dnsx: could not parse line: %r", line[:200])
                continue
            host = obj.get("host")
            if not host:
                continue
            for rtype, key in (("A", "a"), ("AAAA", "aaaa"), ("CNAME", "cname"), ("NS", "ns"), ("MX", "mx"), ("TXT", "txt")):
                values = obj.get(key) or []
                for value in values:
                    records.append({"hostname": host, "record_type": rtype, "value": value})
        return records
