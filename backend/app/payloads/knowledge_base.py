"""
SentinelAI - Phase 8: Payload Knowledge Base
Loader, index, and context-aware selection service.

Loads the normalized JSON files under payload-kb/ into validated
PayloadEntry objects, indexes them by category/context/technology, and
exposes select_relevant() -- the function the (future) AI Orchestrator
calls to decide which technique *families* are worth investigating for
a given target, per Section 7:

    "The AI should select payload/test families based on application
     context. Do NOT blindly execute every payload."

This module never executes anything; it only returns metadata. Firing
an actual test still goes through the allowlisted Tool Registry /
analyzers, under the Scope Enforcement Layer.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from app.schemas.payload_kb import (
    CategorySelectionResult,
    PayloadCategory,
    PayloadContext,
    PayloadEntry,
)

# Maps a detected technology/context signal to the categories worth
# investigating and a short human-readable reason. This is the
# deterministic "default reasoning" layer the spec describes in Section
# 6 (e.g. "If an API is detected: Prioritize API analysis"); an AI
# Orchestrator can refine/override this later, but the platform must
# work sensibly without one (Section 28: AI enhances, never becomes a
# single point of failure).
_TECH_CATEGORY_HINTS: dict[str, list[tuple[PayloadCategory, str]]] = {
    "mysql": [(PayloadCategory.SQL_INJECTION, "MySQL backend detected")],
    "postgresql": [(PayloadCategory.SQL_INJECTION, "PostgreSQL backend detected")],
    "mssql": [(PayloadCategory.SQL_INJECTION, "MSSQL backend detected")],
    "oracle": [(PayloadCategory.SQL_INJECTION, "Oracle backend detected")],
    "sqlite": [(PayloadCategory.SQL_INJECTION, "SQLite backend detected")],
    "php": [
        (PayloadCategory.LFI, "PHP applications commonly expose file-include parameters"),
        (PayloadCategory.RFI, "Legacy PHP configurations may allow remote includes"),
        (PayloadCategory.DESERIALIZATION, "PHP unserialize() is a known deserialization sink"),
    ],
    "java": [(PayloadCategory.DESERIALIZATION, "Java serialization is a known deserialization sink")],
    "node-js": [
        (PayloadCategory.PROTOTYPE_POLLUTION, "Node.js object-merge utilities are a common pollution vector"),
    ],
    "jinja2": [(PayloadCategory.SSTI, "Jinja2 template engine detected")],
    "twig": [(PayloadCategory.SSTI, "Twig template engine detected")],
    "freemarker": [(PayloadCategory.SSTI, "FreeMarker template engine detected")],
    "rest-api": [
        (PayloadCategory.API_SECURITY, "REST API surface detected"),
        (PayloadCategory.IDOR_BOLA, "Object-addressed REST endpoints are a common BOLA vector"),
    ],
    "graphql-api": [(PayloadCategory.GRAPHQL, "GraphQL endpoint detected")],
    "jwt-auth": [(PayloadCategory.JWT, "JWT-based authentication detected")],
    "oauth2-bearer": [(PayloadCategory.JWT, "OAuth2 bearer-token authentication detected")],
    "spa": [(PayloadCategory.XSS, "Client-rendered SPA increases DOM XSS surface")],
    "spa-backend": [(PayloadCategory.CORS, "SPA backend commonly configures CORS for cross-origin calls")],
    "file-upload-endpoint": [(PayloadCategory.FILE_UPLOAD, "File upload functionality detected")],
    "login-form": [
        (PayloadCategory.AUTHENTICATION, "Login form detected"),
        (PayloadCategory.CSRF, "Session-cookie login flows are a common CSRF target"),
    ],
    "webhook-consumer": [(PayloadCategory.SSRF, "Server-side URL fetch functionality detected")],
    "url-preview": [(PayloadCategory.SSRF, "URL preview/unfurl functionality detected")],
    "soap-api": [(PayloadCategory.XXE, "SOAP/XML API surface detected")],
    "xml-upload": [(PayloadCategory.XXE, "XML upload functionality detected")],
}

# Always-relevant categories regardless of detected technology -- these
# apply to virtually any web application and are cheap to check.
_ALWAYS_RELEVANT: list[tuple[PayloadCategory, str]] = [
    (PayloadCategory.OPEN_REDIRECT, "Redirect-shaped parameters are common on most sites"),
    (PayloadCategory.CORS, "CORS misconfiguration checks are cheap and broadly applicable"),
]


class PayloadKnowledgeBase:
    def __init__(self, entries: list[PayloadEntry]):
        self._entries = entries
        self._by_id = {e.id: e for e in entries}
        self._by_category: dict[PayloadCategory, list[PayloadEntry]] = {}
        self._by_context: dict[PayloadContext, list[PayloadEntry]] = {}
        for e in entries:
            self._by_category.setdefault(e.category, []).append(e)
            self._by_context.setdefault(e.context, []).append(e)

    # -- construction -------------------------------------------------------

    @classmethod
    def load_from_directory(cls, directory: str | Path) -> "PayloadKnowledgeBase":
        directory = Path(directory)
        entries: list[PayloadEntry] = []
        errors: list[str] = []

        for json_file in sorted(directory.glob("*.json")):
            try:
                raw = json.loads(json_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                errors.append(f"{json_file.name}: invalid JSON ({exc})")
                continue
            if not isinstance(raw, list):
                errors.append(f"{json_file.name}: expected a JSON array at top level")
                continue
            for i, item in enumerate(raw):
                try:
                    entries.append(PayloadEntry(**item))
                except ValidationError as exc:
                    errors.append(f"{json_file.name}[{i}]: {exc}")

        if errors:
            raise ValueError(
                "Payload knowledge base failed to load cleanly:\n" + "\n".join(errors)
            )

        ids = [e.id for e in entries]
        duplicates = {i for i in ids if ids.count(i) > 1}
        if duplicates:
            raise ValueError(f"Duplicate payload entry ids: {sorted(duplicates)}")

        return cls(entries)

    # -- reads ----------------------------------------------------------

    def get(self, entry_id: str) -> PayloadEntry | None:
        return self._by_id.get(entry_id)

    def by_category(self, category: PayloadCategory) -> list[PayloadEntry]:
        return list(self._by_category.get(category, []))

    def by_context(self, context: PayloadContext) -> list[PayloadEntry]:
        return list(self._by_context.get(context, []))

    def all_entries(self) -> list[PayloadEntry]:
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    # -- context-aware selection (Section 7) -----------------------------

    def select_relevant(
        self, detected_technologies: list[str], include_always_relevant: bool = True
    ) -> list[CategorySelectionResult]:
        """Given a list of fingerprinted technology/context tags (e.g.
        from Section 4's tech-fingerprinting stage: "mysql", "php",
        "rest-api", "jwt-auth"...), return the categories worth
        investigating, each with a reason and how many KB entries back
        it -- never the raw payload strings themselves. Order is stable:
        technology-matched categories first (in input-tech order), then
        always-relevant ones, each appearing once even if matched by
        multiple technologies."""
        normalized_techs = [t.lower() for t in detected_technologies]
        seen: set[PayloadCategory] = set()
        results: list[CategorySelectionResult] = []

        for tech in normalized_techs:
            for category, reason in _TECH_CATEGORY_HINTS.get(tech, []):
                if category in seen:
                    continue
                seen.add(category)
                results.append(
                    CategorySelectionResult(
                        category=category,
                        reason=reason,
                        matched_technologies=[tech],
                        entry_count=len(self._by_category.get(category, [])),
                    )
                )

        if include_always_relevant:
            for category, reason in _ALWAYS_RELEVANT:
                if category in seen:
                    continue
                seen.add(category)
                results.append(
                    CategorySelectionResult(
                        category=category,
                        reason=reason,
                        matched_technologies=[],
                        entry_count=len(self._by_category.get(category, [])),
                    )
                )

        return results
