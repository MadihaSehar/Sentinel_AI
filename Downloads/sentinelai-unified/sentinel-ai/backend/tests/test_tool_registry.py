import pytest

from app.tools.base import SecurityTool
from app.tools.registry import ToolRegistry, UnknownToolError, build_default_registry


class DummyTool(SecurityTool):
    name = "dummy"
    binary = "true"

    def build_args(self, target, options):
        return []

    def normalize_output(self, raw_stdout):
        return []


def test_register_and_get():
    registry = ToolRegistry()
    registry.register(DummyTool())
    assert registry.is_registered("dummy")
    assert registry.get("dummy").name == "dummy"


def test_duplicate_registration_rejected():
    registry = ToolRegistry()
    registry.register(DummyTool())
    with pytest.raises(ValueError):
        registry.register(DummyTool())


def test_unknown_tool_raises():
    registry = ToolRegistry()
    with pytest.raises(UnknownToolError):
        registry.get("sqlmap")  # deliberately not registered anywhere


def test_default_registry_has_recon_discovery_and_vulnerability_toolset():
    registry = build_default_registry()
    assert registry.list_tools() == [
        "dnsx", "ffuf", "gau", "httpx", "katana", "naabu",
        "nuclei", "subfinder", "waybackurls",
    ]
