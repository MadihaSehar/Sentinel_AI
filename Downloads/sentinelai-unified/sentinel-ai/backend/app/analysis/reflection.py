"""
SentinelAI - Phase 6: Response Intelligence Engine
Reflection detection.

This module answers one narrow question: "did a value that we sent as
input reappear in the response, and if so, where/how?" It does not decide
whether that reflection is exploitable -- that requires the vulnerability
analyzers (Section 8) plus AI/consensus review (Sections 10-13). A
reflection alone is a SecurityIndicator, never a Finding.

The "marker" concept: when a test tool (e.g. ffuf/katana/custom analyzer)
sends a request, it tags the value it controls with a unique, inert
marker string (e.g. a random token) BEFORE submission. This module only
ever looks for markers the caller supplies -- it never generates or knows
about attack payloads itself.
"""

from __future__ import annotations

import html
import re
import urllib.parse
from dataclasses import dataclass

from app.schemas.response_intel import ReflectionPoint

_CONTEXT_WINDOW = 40


@dataclass
class MarkerInput:
    parameter: str
    marker: str


def _snippet(body: str, index: int, marker_len: int) -> str:
    start = max(0, index - _CONTEXT_WINDOW)
    end = min(len(body), index + marker_len + _CONTEXT_WINDOW)
    return body[start:end]


def _classify_context(body: str, index: int) -> str:
    """Best-effort classification of where in the document a reflection
    landed, using only local structural cues (no execution)."""
    window_start = max(0, index - 80)
    before = body[window_start:index]

    # Inside a <script> block?
    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script_open != -1 and last_script_open > last_script_close:
        return "js_string"

    # Inside an HTML tag, i.e. between the last '<' and next '>' before index
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt != -1 and last_lt > last_gt:
        return "html_attribute"

    # JSON-value heuristic: only fire when the body as a whole looks like
    # a JSON document (starts with '{' or '[') AND the immediate token
    # before the reflection is a quoted-key colon, e.g. `"name": `.
    stripped_doc = body.lstrip()
    if stripped_doc[:1] in ("{", "["):
        tail = before.rstrip()
        if re.search(r'"\s*:\s*"?$', tail):
            return "json_value"

    return "html_body"


def find_reflections(
    body: str,
    markers: list[MarkerInput],
    headers: dict[str, str] | None = None,
) -> list[ReflectionPoint]:
    """Scan a response body (and optionally headers) for occurrences of
    each marker, in raw, URL-decoded, and HTML-entity-decoded form.
    Returns one ReflectionPoint per occurrence found."""
    results: list[ReflectionPoint] = []

    variants_cache: dict[str, list[tuple[str, bool, bool]]] = {}

    def variants(marker: str) -> list[tuple[str, bool, bool]]:
        """Return (text, encoded, html_escaped) candidates to search for."""
        if marker in variants_cache:
            return variants_cache[marker]
        out = [(marker, False, False)]
        escaped = html.escape(marker)
        if escaped != marker:
            out.append((escaped, False, True))
        try:
            decoded_url = urllib.parse.unquote(marker)
        except Exception:
            decoded_url = marker
        quoted = urllib.parse.quote(marker)
        if quoted != marker:
            out.append((quoted, True, False))
        variants_cache[marker] = out
        return out

    for m in markers:
        for needle, encoded, escaped in variants(m.marker):
            if not needle:
                continue
            for match in re.finditer(re.escape(needle), body):
                idx = match.start()
                ctx = _classify_context(body, idx)
                results.append(
                    ReflectionPoint(
                        parameter=m.parameter,
                        marker=m.marker,
                        context=ctx,
                        position=idx,
                        surrounding=_snippet(body, idx, len(needle)),
                        encoded=encoded,
                        html_escaped=escaped,
                    )
                )

        if headers:
            for header_name, header_val in headers.items():
                if m.marker and m.marker in header_val:
                    results.append(
                        ReflectionPoint(
                            parameter=m.parameter,
                            marker=m.marker,
                            context="header",
                            position=0,
                            surrounding=f"{header_name}: {header_val}"[:120],
                            encoded=False,
                            html_escaped=False,
                        )
                    )

    return results
