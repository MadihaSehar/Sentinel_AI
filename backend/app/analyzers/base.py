"""
SentinelAI - Phase 7: Vulnerability Analyzers
Analyzer interface.

Two shapes of analyzer:
  - ExchangeAnalyzer: looks at ONE AnalyzedExchange (e.g. reflected XSS,
    SQLi error signatures, missing security headers).
  - ComparativeAnalyzer: looks at TWO exchanges representing the same
    resource fetched under different contexts (e.g. IDOR: user A's
    session requesting user B's object).

Analyzers never execute new requests and never invent payloads -- they
only reason over evidence already captured by Phase 6 (recon/discovery
tools + the Response Intelligence Engine). This keeps "do not allow the
AI to output arbitrary shell commands" / "commands must come from an
allowlisted Tool Registry" intact: analyzers are pure functions over data.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.schemas.finding import FindingCandidate
from app.schemas.response_intel import AnalyzedExchange


class ExchangeAnalyzer(ABC):
    name: str

    @abstractmethod
    def applies_to(self, exchange: AnalyzedExchange) -> bool:
        """Cheap pre-check so the orchestrator doesn't run every analyzer
        on every exchange (Section 6: "Do NOT always run every tool /
        stage"). Should be O(1) on already-computed features/indicators."""
        raise NotImplementedError

    @abstractmethod
    def analyze(self, exchange: AnalyzedExchange) -> list[FindingCandidate]:
        raise NotImplementedError


class ComparativeAnalyzer(ABC):
    name: str

    @abstractmethod
    def applies_to(
        self, exchange_a: AnalyzedExchange, exchange_b: AnalyzedExchange
    ) -> bool:
        raise NotImplementedError

    @abstractmethod
    def analyze(
        self, exchange_a: AnalyzedExchange, exchange_b: AnalyzedExchange
    ) -> list[FindingCandidate]:
        raise NotImplementedError
