"""
SentinelAI - Phase 6: Response Intelligence Engine
Header comparison utilities.
"""

from __future__ import annotations

# Headers that routinely vary between otherwise-identical responses and
# would otherwise create noisy false "differences".
_VOLATILE_HEADERS = {
    "date",
    "x-request-id",
    "x-trace-id",
    "x-amzn-trace-id",
    "etag",
    "set-cookie",
    "server-timing",
    "cf-ray",
}


def diff_headers(
    baseline: dict[str, str], test: dict[str, str], ignore_volatile: bool = True
) -> dict[str, object]:
    """Return {added, removed, changed} keyed by lower-cased header name."""
    b = {k.lower(): v for k, v in (baseline or {}).items()}
    t = {k.lower(): v for k, v in (test or {}).items()}

    if ignore_volatile:
        b = {k: v for k, v in b.items() if k not in _VOLATILE_HEADERS}
        t = {k: v for k, v in t.items() if k not in _VOLATILE_HEADERS}

    added = {k: v for k, v in t.items() if k not in b}
    removed = {k: v for k, v in b.items() if k not in t}
    changed = {
        k: {"baseline": b[k], "test": t[k]}
        for k in (b.keys() & t.keys())
        if b[k] != t[k]
    }

    return {"added": added, "removed": removed, "changed": changed}
