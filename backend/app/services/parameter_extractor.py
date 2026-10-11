"""
Deterministic parameter discovery: extracts query-string parameter names
from already-collected URLs (crawled + historical). No network activity,
no external tool, no scope check needed — this is pure string parsing
over data SentinelAI already fetched.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

from app.schemas.discovery import Parameter


def extract_parameters(urls: list[str]) -> list[Parameter]:
    seen: dict[str, str] = {}  # param name -> one example URL
    for url in urls:
        try:
            parsed = urlparse(url)
        except ValueError:
            continue
        if not parsed.query:
            continue
        for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
            if key and key not in seen:
                seen[key] = url
    return [Parameter(name=name, example_url=example) for name, example in sorted(seen.items())]
