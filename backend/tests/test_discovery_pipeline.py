from uuid import uuid4

import pytest

from app.core.scope_engine import ScopeEngine
from app.orchestrator.discovery_pipeline import DiscoveryPipeline
from app.schemas.scope import AssessmentType, AuthorizationRecord, AuthorizationStatus, ScopeConfig
from app.tools.base import SecurityTool, ToolResult
from app.tools.registry import ToolRegistry


class FakeKatana(SecurityTool):
    name = "katana"
    binary = "true"

    def build_args(self, target, options):
        return []

    def normalize_output(self, raw_stdout):
        return [
            {"url": "https://example.com/dashboard", "method": "GET", "source": "katana",
             "status_code": 200, "content_type": "text/html"},
            # out-of-scope host that katana's JS crawl happened to pick up (e.g. a CDN link)
            {"url": "https://cdn.thirdparty.net/app.js", "method": "GET", "source": "katana",
             "status_code": 200, "content_type": "application/javascript"},
        ]

    async def execute(self, target, options=None, stdin_data=None):
        self.last_stdin = stdin_data
        return ToolResult(
            tool_name=self.name, command=["fake"], returncode=0, stdout="fake",
            stderr="", duration_seconds=0.0, truncated=False, output_sha256="x",
        )


class FakeGau(SecurityTool):
    name = "gau"
    binary = "true"

    def build_args(self, target, options):
        return []

    def normalize_output(self, raw_stdout):
        return [
            {"url": "https://example.com/old-endpoint?token=abc", "source": "gau", "status_code": 200},
            # a decommissioned out-of-scope subdomain still in the archive
            {"url": "https://old.acquired-company.com/login?user=admin", "source": "gau", "status_code": 404},
        ]

    async def execute(self, target, options=None, stdin_data=None):
        self.last_stdin = stdin_data
        return ToolResult(
            tool_name=self.name, command=["fake"], returncode=0, stdout="fake",
            stderr="", duration_seconds=0.0, truncated=False, output_sha256="x",
        )


class FakeWaybackurls(SecurityTool):
    name = "waybackurls"
    binary = "true"

    def build_args(self, target, options):
        return []

    def normalize_output(self, raw_stdout):
        return [{"url": "https://example.com/api/v1/users?id=5", "source": "waybackurls", "status_code": None}]

    async def execute(self, target, options=None, stdin_data=None):
        self.last_stdin = stdin_data
        return ToolResult(
            tool_name=self.name, command=["fake"], returncode=0, stdout="fake",
            stderr="", duration_seconds=0.0, truncated=False, output_sha256="x",
        )


class FakeFfuf(SecurityTool):
    name = "ffuf"
    binary = "true"

    def build_args(self, target, options):
        return []

    def normalize_output(self, raw_stdout):
        return [
            {"url": "https://example.com/admin", "status_code": 403, "content_length": 10,
             "words": 2, "lines": 1},
        ]

    async def execute(self, target, options=None, stdin_data=None):
        return ToolResult(
            tool_name=self.name, command=["fake"], returncode=0, stdout="fake",
            stderr="", duration_seconds=0.0, truncated=False, output_sha256="x",
        )


def make_scope_engine() -> ScopeEngine:
    cfg = ScopeConfig(
        assessment_type=AssessmentType.BUG_BOUNTY,
        included_domains=[{"pattern": "*.example.com"}],
        authorization=AuthorizationRecord(status=AuthorizationStatus.CONFIRMED, confirmed_by="tester"),
    )
    return ScopeEngine(uuid4(), cfg)


def make_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(FakeKatana())
    registry.register(FakeGau())
    registry.register(FakeWaybackurls())
    registry.register(FakeFfuf())
    return registry


@pytest.mark.asyncio
async def test_katana_result_filters_out_of_scope_crawled_url():
    engine = make_scope_engine()
    registry = make_registry()
    pipeline = DiscoveryPipeline(engine, registry)

    result = await pipeline.run(["https://example.com"])

    crawled = {c.url for c in result.crawled_urls}
    assert "https://example.com/dashboard" in crawled
    assert "https://cdn.thirdparty.net/app.js" not in crawled
    assert "https://cdn.thirdparty.net/app.js" in result.skipped_out_of_scope


@pytest.mark.asyncio
async def test_historical_urls_filter_decommissioned_out_of_scope_subdomain():
    engine = make_scope_engine()
    registry = make_registry()
    pipeline = DiscoveryPipeline(engine, registry)

    result = await pipeline.run(["https://example.com"])

    historical = {h.url for h in result.historical_urls}
    assert "https://example.com/old-endpoint?token=abc" in historical
    assert "https://old.acquired-company.com/login?user=admin" not in historical
    assert any("acquired-company.com" in s for s in result.skipped_out_of_scope)


@pytest.mark.asyncio
async def test_ffuf_discovered_paths_included():
    engine = make_scope_engine()
    registry = make_registry()
    pipeline = DiscoveryPipeline(engine, registry)

    result = await pipeline.run(["https://example.com"])

    assert any(d.url == "https://example.com/admin" and d.status_code == 403 for d in result.discovered_paths)


@pytest.mark.asyncio
async def test_parameters_extracted_across_all_sources():
    engine = make_scope_engine()
    registry = make_registry()
    pipeline = DiscoveryPipeline(engine, registry)

    result = await pipeline.run(["https://example.com"])

    param_names = {p.name for p in result.parameters}
    assert "token" in param_names  # from gau historical URL
    assert "id" in param_names  # from waybackurls historical URL


@pytest.mark.asyncio
async def test_pipeline_refuses_when_all_seed_urls_out_of_scope():
    engine = make_scope_engine()
    registry = make_registry()
    pipeline = DiscoveryPipeline(engine, registry)

    result = await pipeline.run(["https://not-in-scope.net"])

    assert result.crawled_urls == []
    assert result.historical_urls == []
    assert any("no in-scope seed" in e for e in result.tool_errors)
