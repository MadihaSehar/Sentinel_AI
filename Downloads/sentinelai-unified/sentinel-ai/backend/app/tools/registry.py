"""
Tool Registry: the sole allowlist of tools SentinelAI is permitted to run.

Nothing outside this module may invoke a SecurityTool directly from a
string name — the orchestrator asks the registry for a tool by name, and
if it isn't registered, execution simply cannot happen. An AI-driven
"action" from the orchestrator can select a *registered tool name*, never
arbitrary argv or a shell command.
"""

from __future__ import annotations

from app.tools.base import SecurityTool


class UnknownToolError(Exception):
    pass


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, SecurityTool] = {}

    def register(self, tool: SecurityTool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool '{tool.name}' is already registered.")
        self._tools[tool.name] = tool

    def get(self, name: str) -> SecurityTool:
        try:
            return self._tools[name]
        except KeyError:
            raise UnknownToolError(
                f"'{name}' is not a registered tool. Registered tools: {sorted(self._tools)}"
            ) from None

    def list_tools(self) -> list[str]:
        return sorted(self._tools.keys())

    def is_registered(self, name: str) -> bool:
        return name in self._tools


def build_default_registry() -> ToolRegistry:
    """Registers the Phase-3 (recon) and Phase-4 (discovery) toolsets. Called once at app startup."""
    from app.tools.recon.subfinder import SubfinderTool
    from app.tools.recon.dnsx import DnsxTool
    from app.tools.recon.httpx_tool import HttpxTool
    from app.tools.recon.naabu import NaabuTool
    from app.tools.discovery.katana import KatanaTool
    from app.tools.discovery.gau import GauTool
    from app.tools.discovery.waybackurls import WaybackurlsTool
    from app.tools.discovery.ffuf import FfufTool
    from app.tools.vulnerability.nuclei import NucleiTool

    registry = ToolRegistry()
    # Recon (Phase 3)
    registry.register(SubfinderTool())
    registry.register(DnsxTool())
    registry.register(HttpxTool())
    registry.register(NaabuTool())
    # Discovery (Phase 4)
    registry.register(KatanaTool())
    registry.register(GauTool())
    registry.register(WaybackurlsTool())
    registry.register(FfufTool())
    # Vulnerability detection (Phase 5)
    registry.register(NucleiTool())
    return registry
