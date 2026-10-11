"""
SentinelAI - Phase 6: Response Intelligence Engine
Deterministic similarity analysis between two response bodies.

No AI calls here. This runs on every captured exchange, cheaply, so that
only high-value evidence is ever escalated to an LLM (Section 29: Cost
Control -- "local deterministic analysis before LLM calls").
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from rapidfuzz import fuzz

_WHITESPACE_RE = re.compile(r"\s+")
_TAG_RE = re.compile(r"<[^>]+>")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]+")


def body_hash(body: str) -> str:
    """Stable hash used for exact-duplicate detection / deduplication."""
    return hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()


def normalize_whitespace(body: str) -> str:
    return _WHITESPACE_RE.sub(" ", body).strip()


def strip_tags(body: str) -> str:
    """Rough text-only view of an HTML body, used for text similarity so
    that unrelated markup churn doesn't dominate the score."""
    return normalize_whitespace(_TAG_RE.sub(" ", body))


def text_similarity(a: str, b: str) -> float:
    """Token-level similarity in [0.0, 1.0] using a normalized edit-ratio.
    Cheap, deterministic, and tolerant of large bodies (no O(n^2) diff)."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    ta, tb = strip_tags(a), strip_tags(b)
    return fuzz.ratio(ta, tb) / 100.0


def token_set(body: str) -> set[str]:
    return set(_TOKEN_RE.findall(body))


def structural_similarity(a: str, b: str) -> float:
    """Jaccard similarity over token sets -- a cheap proxy for "same
    shape of page" that's robust to content that merely reordered."""
    sa, sb = token_set(a), token_set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    intersection = len(sa & sb)
    union = len(sa | sb)
    return intersection / union if union else 0.0


@dataclass
class LengthComparison:
    delta: int
    ratio: float


def length_comparison(a: str, b: str) -> LengthComparison:
    la, lb = len(a), len(b)
    delta = lb - la
    ratio = (lb / la) if la else (1.0 if lb == 0 else float("inf"))
    return LengthComparison(delta=delta, ratio=round(ratio, 4) if ratio != float("inf") else -1.0)
