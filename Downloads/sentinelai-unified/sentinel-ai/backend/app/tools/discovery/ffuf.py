"""ffuf: fast web fuzzer for content/directory discovery. https://github.com/ffuf/ffuf

Security note: the wordlist path is NEVER taken as a free-form string from
options. `options["wordlist"]` is a *key* into a small server-side
allowlist (_ALLOWED_WORDLISTS below) — this prevents path traversal or
reading arbitrary files on the host via a crafted option.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from app.tools.base import SecurityTool

logger = logging.getLogger("sentinel.tools.ffuf")

_WORDLIST_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "configs", "wordlists")

_ALLOWED_WORDLISTS = {
    "common-small": os.path.normpath(os.path.join(_WORDLIST_DIR, "common-small.txt")),
}


class UnknownWordlistError(ValueError):
    pass


class FfufTool(SecurityTool):
    name = "ffuf"
    binary = "ffuf"
    version = "2.x"
    timeout_seconds = 300

    def build_args(self, target: str, options: dict[str, Any]) -> list[str]:
        wordlist_key = options.get("wordlist", "common-small")
        wordlist_path = _ALLOWED_WORDLISTS.get(wordlist_key)
        if wordlist_path is None:
            raise UnknownWordlistError(
                f"'{wordlist_key}' is not an allowlisted wordlist. "
                f"Allowed: {sorted(_ALLOWED_WORDLISTS)}"
            )

        url = target if "FUZZ" in target else target.rstrip("/") + "/FUZZ"

        args = [
            "-u", url,
            "-w", wordlist_path,
            "-json",
            "-silent",
            "-se",  # stop on spurious errors instead of hanging
        ]
        rate = options.get("rate")
        if isinstance(rate, (int, float)) and rate > 0:
            args += ["-rate", str(int(rate))]
        match_codes = options.get("match_codes", "200,204,301,302,307,401,403")
        args += ["-mc", match_codes]
        threads = options.get("threads", 10)
        if isinstance(threads, int) and 0 < threads <= 40:
            args += ["-t", str(threads)]
        return args

    def normalize_output(self, raw_stdout: str) -> list[dict]:
        """ffuf -json prints one JSON object per result line (not an envelope, with -silent)."""
        records: list[dict] = []
        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("ffuf: could not parse line: %r", line[:200])
                continue
            url = obj.get("url")
            status = obj.get("status")
            if url is None or status is None:
                continue
            records.append(
                {
                    "url": url,
                    "status_code": int(status),
                    "content_length": obj.get("length"),
                    "words": obj.get("words"),
                    "lines": obj.get("lines"),
                }
            )
        return records
