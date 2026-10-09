"""
SentinelAI - Phase 6: Response Intelligence Engine
Lightweight DOM diffing between a baseline and a test HTML response.

Goal: cheap, deterministic structural comparison -- counts of added /
removed / changed nodes, new <script> tags, and new inline event-handler
attributes (onerror=, onload=, etc.) -- purely as observational evidence.
This module does not execute any script or render JS; it only parses
markup with BeautifulSoup/lxml.
"""

from __future__ import annotations

from bs4 import BeautifulSoup, Tag

from app.schemas.response_intel import DomDiff

_EVENT_ATTR_PREFIXES = ("on",)


def _parse(body: str) -> BeautifulSoup:
    return BeautifulSoup(body or "", "lxml")


def _element_signature(tag: Tag) -> str:
    """A coarse fingerprint for a tag: name + sorted attribute keys.
    Used for set-based added/removed comparison, not exact diffing."""
    attrs = ",".join(sorted(tag.attrs.keys())) if tag.attrs else ""
    return f"{tag.name}[{attrs}]"


def _event_handlers(soup: BeautifulSoup) -> set[str]:
    handlers: set[str] = set()
    for tag in soup.find_all(True):
        for attr in tag.attrs:
            if isinstance(attr, str) and attr.lower().startswith(_EVENT_ATTR_PREFIXES) and len(attr) > 2:
                handlers.add(f"<{tag.name} {attr}>")
    return handlers


def diff_dom(baseline_html: str, test_html: str, sample_size: int = 5) -> DomDiff:
    base_soup = _parse(baseline_html)
    test_soup = _parse(test_html)

    base_sigs = [_element_signature(t) for t in base_soup.find_all(True)]
    test_sigs = [_element_signature(t) for t in test_soup.find_all(True)]

    base_counts: dict[str, int] = {}
    for s in base_sigs:
        base_counts[s] = base_counts.get(s, 0) + 1
    test_counts: dict[str, int] = {}
    for s in test_sigs:
        test_counts[s] = test_counts.get(s, 0) + 1

    added: list[str] = []
    removed: list[str] = []
    changed = 0

    all_keys = set(base_counts) | set(test_counts)
    for key in all_keys:
        b, t = base_counts.get(key, 0), test_counts.get(key, 0)
        if t > b:
            added.extend([key] * (t - b))
        elif b > t:
            removed.extend([key] * (b - t))
        if b != t:
            changed += 1

    base_scripts = len(base_soup.find_all("script"))
    test_scripts = len(test_soup.find_all("script"))
    new_scripts = max(0, test_scripts - base_scripts)

    base_handlers = _event_handlers(base_soup)
    test_handlers = _event_handlers(test_soup)
    new_handlers = sorted(test_handlers - base_handlers)

    return DomDiff(
        nodes_added=len(added),
        nodes_removed=len(removed),
        nodes_changed=changed,
        new_script_tags=new_scripts,
        new_event_handlers=new_handlers,
        added_elements_sample=added[:sample_size],
        removed_elements_sample=removed[:sample_size],
    )
