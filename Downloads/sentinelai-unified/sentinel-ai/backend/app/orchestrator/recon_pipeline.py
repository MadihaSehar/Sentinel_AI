"""
Recon Pipeline: subfinder -> dnsx -> httpx -> naabu

Every single hostname or IP that comes out of one stage is re-checked
against the ScopeEngine before it is fed into the next stage. A tool
(e.g. subfinder, which does passive enumeration against third-party
sources) can return hosts that are not in scope — those are recorded in
`skipped_out_of_scope` and dropped, never touched by a later stage.

This module never builds shell commands itself; it only calls
`tool.execute(...)` on tools pulled from the ToolRegistry by name.
"""

from __future__ import annotations

import logging
from typing import Optional

from app.core.scope_engine import ScopeEngine
from app.schemas.recon import DNSRecord, HTTPService, OpenPort, ReconResult, Subdomain
from app.tools.base import ToolExecutionError
from app.tools.registry import ToolRegistry

logger = logging.getLogger("sentinel.orchestrator.recon")


class ReconPipeline:
    def __init__(self, scope_engine: ScopeEngine, registry: ToolRegistry):
        self.scope = scope_engine
        self.registry = registry

    async def run(
        self,
        target: str,
        *,
        run_subfinder: bool = True,
        run_dnsx: bool = True,
        run_httpx: bool = True,
        run_naabu: bool = True,
        options: Optional[dict] = None,
    ) -> ReconResult:
        options = options or {}
        result = ReconResult(target=target)

        # The root target itself must be in scope before we do anything.
        root_decision = self.scope.is_domain_allowed(target)
        if not root_decision.allowed:
            result.tool_errors.append(f"root target denied by scope engine: {root_decision.reason}")
            return result

        hosts: set[str] = {target}

        # -- Stage 1: subfinder (passive subdomain enumeration) -----------
        if run_subfinder:
            hosts |= await self._run_subfinder(target, result, options.get("subfinder", {}))

        in_scope_hosts = self._filter_hosts(hosts, result)

        # -- Stage 2: dnsx (resolve + collect records) ---------------------
        if run_dnsx and in_scope_hosts:
            await self._run_dnsx(in_scope_hosts, result, options.get("dnsx", {}))

        # -- Stage 3: httpx (HTTP discovery + fingerprinting) --------------
        if run_httpx and in_scope_hosts:
            await self._run_httpx(in_scope_hosts, result, options.get("httpx", {}))

        # -- Stage 4: naabu (port discovery) -------------------------------
        # Only scan IPs that are in scope; resolve from dnsx A/AAAA records.
        if run_naabu:
            ips = {r.value for r in result.dns_records if r.record_type in ("A", "AAAA")}
            in_scope_ips = self._filter_ips(ips, result)
            if in_scope_ips:
                await self._run_naabu(in_scope_ips, result, options.get("naabu", {}))

        return result

    # -- stage implementations --------------------------------------------

    async def _run_subfinder(self, target: str, result: ReconResult, opts: dict) -> set[str]:
        tool = self.registry.get("subfinder")
        try:
            await self.scope.rate_limiter.acquire()
            try:
                tool_result = await tool.execute(target, options=opts)
            finally:
                self.scope.rate_limiter.release()
        except ToolExecutionError as exc:
            result.tool_errors.append(str(exc))
            return {target}

        discovered = set()
        for rec in tool.normalize_output(tool_result.stdout):
            result.subdomains.append(Subdomain(**rec))
            discovered.add(rec["hostname"])
        discovered.add(target)
        return discovered

    async def _run_dnsx(self, hosts: set[str], result: ReconResult, opts: dict) -> None:
        tool = self.registry.get("dnsx")
        stdin_data = "\n".join(sorted(hosts)) + "\n"
        try:
            await self.scope.rate_limiter.acquire()
            try:
                tool_result = await tool.execute("", options=opts, stdin_data=stdin_data)
            finally:
                self.scope.rate_limiter.release()
        except ToolExecutionError as exc:
            result.tool_errors.append(str(exc))
            return

        for rec in tool.normalize_output(tool_result.stdout):
            result.dns_records.append(DNSRecord(**rec))

    async def _run_httpx(self, hosts: set[str], result: ReconResult, opts: dict) -> None:
        tool = self.registry.get("httpx")
        stdin_data = "\n".join(sorted(hosts)) + "\n"
        try:
            await self.scope.rate_limiter.acquire()
            try:
                tool_result = await tool.execute("", options=opts, stdin_data=stdin_data)
            finally:
                self.scope.rate_limiter.release()
        except ToolExecutionError as exc:
            result.tool_errors.append(str(exc))
            return

        for rec in tool.normalize_output(tool_result.stdout):
            result.http_services.append(HTTPService(**rec))

    async def _run_naabu(self, ips: set[str], result: ReconResult, opts: dict) -> None:
        tool = self.registry.get("naabu")
        stdin_data = "\n".join(sorted(ips)) + "\n"
        try:
            await self.scope.rate_limiter.acquire()
            try:
                tool_result = await tool.execute("", options=opts, stdin_data=stdin_data)
            finally:
                self.scope.rate_limiter.release()
        except ToolExecutionError as exc:
            result.tool_errors.append(str(exc))
            return

        for rec in tool.normalize_output(tool_result.stdout):
            result.open_ports.append(OpenPort(**rec))

    # -- scope filtering helpers --------------------------------------------

    def _filter_hosts(self, hosts: set[str], result: ReconResult) -> set[str]:
        allowed = set()
        for host in hosts:
            decision = self.scope.is_domain_allowed(host)
            if decision.allowed:
                allowed.add(host)
            else:
                result.skipped_out_of_scope.append(host)
                logger.info("recon: dropping out-of-scope host %s (%s)", host, decision.reason)
        return allowed

    def _filter_ips(self, ips: set[str], result: ReconResult) -> set[str]:
        allowed = set()
        for ip in ips:
            decision = self.scope.is_ip_allowed(ip)
            if decision.allowed:
                allowed.add(ip)
            else:
                result.skipped_out_of_scope.append(ip)
                logger.info("recon: dropping out-of-scope ip %s (%s)", ip, decision.reason)
        return allowed
