"""
Discovery Pipeline: katana (crawl) + gau/waybackurls (historical) -> ffuf (content discovery)
                     -> deterministic parameter extraction

Takes the in-scope HTTP services found by the recon pipeline and expands
the attack surface. Every URL returned by any tool is re-checked against
scope (by hostname) before being kept — gau/waybackurls in particular can
return URLs for hosts never seen before (e.g. decommissioned subdomains
still in the Wayback Machine), and those must not silently get fuzzed or
crawled.
"""

from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import urlparse

from app.core.scope_engine import ScopeEngine
from app.schemas.discovery import CrawledURL, DiscoveredPath, DiscoveryResult, HistoricalURL
from app.services.parameter_extractor import extract_parameters
from app.tools.base import ToolExecutionError
from app.tools.registry import ToolRegistry

logger = logging.getLogger("sentinel.orchestrator.discovery")


class DiscoveryPipeline:
    def __init__(self, scope_engine: ScopeEngine, registry: ToolRegistry):
        self.scope = scope_engine
        self.registry = registry

    async def run(
        self,
        seed_urls: list[str],
        *,
        run_katana: bool = True,
        run_historical: bool = True,
        run_ffuf: bool = True,
        options: Optional[dict] = None,
    ) -> DiscoveryResult:
        options = options or {}
        target_label = seed_urls[0] if seed_urls else "unknown"
        result = DiscoveryResult(target=target_label)

        in_scope_seeds = self._filter_urls(seed_urls, result)
        if not in_scope_seeds:
            result.tool_errors.append("no in-scope seed URLs to discover from.")
            return result

        hosts = sorted({urlparse(u).hostname for u in in_scope_seeds if urlparse(u).hostname})

        if run_katana:
            await self._run_katana(in_scope_seeds, result, options.get("katana", {}))

        if run_historical:
            await self._run_gau(hosts, result, options.get("gau", {}))
            await self._run_waybackurls(hosts, result, options.get("waybackurls", {}))

        if run_ffuf:
            for seed in in_scope_seeds:
                await self._run_ffuf(seed, result, options.get("ffuf", {}))

        all_urls = (
            [c.url for c in result.crawled_urls]
            + [h.url for h in result.historical_urls]
            + [d.url for d in result.discovered_paths]
        )
        result.parameters = extract_parameters(all_urls)

        return result

    # -- stage implementations --------------------------------------------

    async def _run_katana(self, seeds: list[str], result: DiscoveryResult, opts: dict) -> None:
        tool = self.registry.get("katana")
        stdin_data = "\n".join(seeds) + "\n"
        try:
            await self.scope.rate_limiter.acquire()
            try:
                tool_result = await tool.execute("", options=opts, stdin_data=stdin_data)
            finally:
                self.scope.rate_limiter.release()
        except ToolExecutionError as exc:
            result.tool_errors.append(str(exc))
            return

        candidates = tool.normalize_output(tool_result.stdout)
        urls = [c["url"] for c in candidates]
        allowed = set(self._filter_urls(urls, result))
        for c in candidates:
            if c["url"] in allowed:
                result.crawled_urls.append(CrawledURL(**c))

    async def _run_gau(self, hosts: list[str], result: DiscoveryResult, opts: dict) -> None:
        if not hosts:
            return
        tool = self.registry.get("gau")
        stdin_data = "\n".join(hosts) + "\n"
        try:
            await self.scope.rate_limiter.acquire()
            try:
                tool_result = await tool.execute("", options=opts, stdin_data=stdin_data)
            finally:
                self.scope.rate_limiter.release()
        except ToolExecutionError as exc:
            result.tool_errors.append(str(exc))
            return
        self._add_historical(tool, tool_result.stdout, result)

    async def _run_waybackurls(self, hosts: list[str], result: DiscoveryResult, opts: dict) -> None:
        if not hosts:
            return
        tool = self.registry.get("waybackurls")
        stdin_data = "\n".join(hosts) + "\n"
        try:
            await self.scope.rate_limiter.acquire()
            try:
                tool_result = await tool.execute("", options=opts, stdin_data=stdin_data)
            finally:
                self.scope.rate_limiter.release()
        except ToolExecutionError as exc:
            result.tool_errors.append(str(exc))
            return
        self._add_historical(tool, tool_result.stdout, result)

    def _add_historical(self, tool, raw_stdout: str, result: DiscoveryResult) -> None:
        candidates = tool.normalize_output(raw_stdout)
        urls = [c["url"] for c in candidates]
        allowed = set(self._filter_urls(urls, result))
        for c in candidates:
            if c["url"] in allowed:
                result.historical_urls.append(HistoricalURL(**c))

    async def _run_ffuf(self, seed_url: str, result: DiscoveryResult, opts: dict) -> None:
        tool = self.registry.get("ffuf")
        try:
            await self.scope.rate_limiter.acquire()
            try:
                tool_result = await tool.execute(seed_url, options=opts)
            finally:
                self.scope.rate_limiter.release()
        except ToolExecutionError as exc:
            result.tool_errors.append(str(exc))
            return

        candidates = tool.normalize_output(tool_result.stdout)
        urls = [c["url"] for c in candidates]
        allowed = set(self._filter_urls(urls, result))
        for c in candidates:
            if c["url"] in allowed:
                result.discovered_paths.append(DiscoveredPath(**c))

    # -- scope filtering ------------------------------------------------------

    def _filter_urls(self, urls: list[str], result: DiscoveryResult) -> list[str]:
        allowed: list[str] = []
        for url in urls:
            hostname = urlparse(url).hostname
            if not hostname:
                result.skipped_out_of_scope.append(url)
                continue
            decision = self.scope.is_domain_allowed(hostname)
            if decision.allowed:
                allowed.append(url)
            else:
                result.skipped_out_of_scope.append(url)
                logger.info("discovery: dropping out-of-scope url %s (%s)", url, decision.reason)
        return allowed
