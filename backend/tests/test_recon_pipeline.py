"""
These tests use fake tool stand-ins (no real subfinder/dnsx/httpx/naabu
binaries required) to verify the ORCHESTRATION logic: that out-of-scope
hosts and IPs discovered mid-pipeline are dropped before being handed to
the next stage, and that in-scope results are aggregated correctly.
"""

from uuid import uuid4

import pytest

from app.core.scope_engine import ScopeEngine
from app.orchestrator.recon_pipeline import ReconPipeline
from app.schemas.scope import AssessmentType, AuthorizationRecord, AuthorizationStatus, ScopeConfig
from app.tools.base import SecurityTool, ToolResult
from app.tools.registry import ToolRegistry


class FakeSubfinder(SecurityTool):
    name = "subfinder"
    binary = "true"

    def build_args(self, target, options):
        return []

    def normalize_output(self, raw_stdout):
        return [
            {"hostname": "api.example.com", "source_tool": "subfinder"},
            {"hostname": "admin.example.com", "source_tool": "subfinder"},  # excluded in scope config
            {"hostname": "totally-unrelated-company.com", "source_tool": "subfinder"},  # out of scope entirely
        ]

    async def execute(self, target, options=None, stdin_data=None):
        return ToolResult(
            tool_name=self.name, command=["fake"], returncode=0, stdout="fake",
            stderr="", duration_seconds=0.0, truncated=False, output_sha256="x",
        )


class FakeDnsx(SecurityTool):
    name = "dnsx"
    binary = "true"

    def build_args(self, target, options):
        return []

    def normalize_output(self, raw_stdout):
        return [
            {"hostname": "example.com", "record_type": "A", "value": "93.184.216.10"},
            {"hostname": "api.example.com", "record_type": "A", "value": "10.0.0.5"},  # resolves to private IP!
        ]

    async def execute(self, target, options=None, stdin_data=None):
        self.last_stdin = stdin_data
        return ToolResult(
            tool_name=self.name, command=["fake"], returncode=0, stdout="fake",
            stderr="", duration_seconds=0.0, truncated=False, output_sha256="x",
        )


class FakeHttpx(SecurityTool):
    name = "httpx"
    binary = "true"

    def build_args(self, target, options):
        return []

    def normalize_output(self, raw_stdout):
        return [
            {"url": "https://example.com", "hostname": "example.com", "status_code": 200,
             "title": "Example", "technologies": ["nginx"], "content_length": 1024, "webserver": "nginx"},
        ]

    async def execute(self, target, options=None, stdin_data=None):
        self.last_stdin = stdin_data
        return ToolResult(
            tool_name=self.name, command=["fake"], returncode=0, stdout="fake",
            stderr="", duration_seconds=0.0, truncated=False, output_sha256="x",
        )


class FakeNaabu(SecurityTool):
    name = "naabu"
    binary = "true"

    def build_args(self, target, options):
        return []

    def normalize_output(self, raw_stdout):
        return [{"ip": "93.184.216.10", "port": 443, "protocol": "tcp"}]

    async def execute(self, target, options=None, stdin_data=None):
        self.last_stdin = stdin_data
        return ToolResult(
            tool_name=self.name, command=["fake"], returncode=0, stdout="fake",
            stderr="", duration_seconds=0.0, truncated=False, output_sha256="x",
        )


def make_scope_engine() -> ScopeEngine:
    cfg = ScopeConfig(
        assessment_type=AssessmentType.BUG_BOUNTY,
        included_domains=[{"pattern": "*.example.com"}],
        excluded_domains=[{"pattern": "admin.example.com"}],
        included_cidrs=[{"cidr": "93.184.0.0/16"}],
        authorization=AuthorizationRecord(status=AuthorizationStatus.CONFIRMED, confirmed_by="tester"),
    )
    return ScopeEngine(uuid4(), cfg)


def make_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(FakeSubfinder())
    registry.register(FakeDnsx())
    registry.register(FakeHttpx())
    registry.register(FakeNaabu())
    return registry


@pytest.mark.asyncio
async def test_pipeline_drops_out_of_scope_subdomain_before_dnsx():
    engine = make_scope_engine()
    registry = make_registry()
    pipeline = ReconPipeline(engine, registry)

    result = await pipeline.run("example.com")

    hostnames_seen_by_dnsx = registry.get("dnsx").last_stdin
    assert "totally-unrelated-company.com" not in hostnames_seen_by_dnsx
    assert "admin.example.com" not in hostnames_seen_by_dnsx
    assert "api.example.com" in hostnames_seen_by_dnsx
    assert "example.com" in hostnames_seen_by_dnsx


@pytest.mark.asyncio
async def test_pipeline_records_skipped_out_of_scope_hosts():
    engine = make_scope_engine()
    registry = make_registry()
    pipeline = ReconPipeline(engine, registry)

    result = await pipeline.run("example.com")

    assert "totally-unrelated-company.com" in result.skipped_out_of_scope
    assert "admin.example.com" in result.skipped_out_of_scope


@pytest.mark.asyncio
async def test_pipeline_drops_private_ip_resolved_mid_pipeline_before_naabu():
    """
    api.example.com is in-scope as a DOMAIN, but dnsx resolves it to a
    private IP (10.0.0.5) which was never explicitly included as a CIDR.
    naabu must never be asked to scan that IP.
    """
    engine = make_scope_engine()
    registry = make_registry()
    pipeline = ReconPipeline(engine, registry)

    result = await pipeline.run("example.com")

    ips_seen_by_naabu = registry.get("naabu").last_stdin
    assert "10.0.0.5" not in ips_seen_by_naabu
    assert "93.184.216.10" in ips_seen_by_naabu
    assert "10.0.0.5" in result.skipped_out_of_scope


@pytest.mark.asyncio
async def test_pipeline_aggregates_all_stage_results():
    engine = make_scope_engine()
    registry = make_registry()
    pipeline = ReconPipeline(engine, registry)

    result = await pipeline.run("example.com")

    assert any(s.hostname == "api.example.com" for s in result.subdomains)
    assert any(r.value == "93.184.216.10" for r in result.dns_records)
    assert any(h.url == "https://example.com" for h in result.http_services)
    assert any(p.port == 443 for p in result.open_ports)


@pytest.mark.asyncio
async def test_pipeline_refuses_to_start_if_root_target_out_of_scope():
    engine = make_scope_engine()
    registry = make_registry()
    pipeline = ReconPipeline(engine, registry)

    result = await pipeline.run("not-in-scope-at-all.net")

    assert result.subdomains == []
    assert result.dns_records == []
    assert any("denied by scope engine" in e for e in result.tool_errors)


@pytest.mark.asyncio
async def test_pipeline_respects_unauthorized_assessment():
    cfg = ScopeConfig(
        assessment_type=AssessmentType.BUG_BOUNTY,
        included_domains=[{"pattern": "*.example.com"}],
        authorization=AuthorizationRecord(status=AuthorizationStatus.PENDING),
    )
    engine = ScopeEngine(uuid4(), cfg)
    registry = make_registry()
    pipeline = ReconPipeline(engine, registry)

    result = await pipeline.run("example.com")

    assert result.subdomains == []
    assert "CONFIRMED" in result.tool_errors[0]
