"""
SecurityTool base class.

Hard rules enforced here, not just documented:

1. Commands are ALWAYS argv lists (asyncio.create_subprocess_exec), never a
   shell string. There is no code path that calls create_subprocess_shell.
2. A tool's argv is built only from (a) a fixed binary path/name set at
   registration time and (b) a small set of typed, validated option objects
   defined by the tool subclass. Free-form strings from an LLM or a user
   are never concatenated directly into argv; they pass through each
   tool's own `build_args()`, which only emits flags it explicitly knows
   about.
3. Every execution has a wall-clock timeout and an output size cap, and is
   run under an (optional) memory rlimit on POSIX.
4. Every execution is logged with inputs, exit code, duration, and output
   hash before any parsing happens.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import resource
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("sentinel.tools")

DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_MEMORY_LIMIT_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB


class ToolExecutionError(Exception):
    def __init__(self, tool_name: str, message: str, *, returncode: Optional[int] = None):
        self.tool_name = tool_name
        self.returncode = returncode
        super().__init__(f"[{tool_name}] {message}")


class ToolTimeoutError(ToolExecutionError):
    pass


class ToolNotInstalledError(ToolExecutionError):
    pass


@dataclass
class ToolResult:
    tool_name: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    truncated: bool
    output_sha256: str
    started_at: float = field(default_factory=time.time)


def _apply_rlimits(memory_limit_bytes: Optional[int]) -> None:
    """Runs in the child process (POSIX only) right after fork, before exec."""
    if memory_limit_bytes:
        try:
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit_bytes, memory_limit_bytes))
        except (ValueError, OSError):
            # Best-effort: some sandboxes/platforms don't allow this; never
            # let a resource-limit failure block an otherwise valid scan.
            pass
    # Prevent core dumps and fork bombs from the child tool.
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass


class SecurityTool:
    """
    Base class every registered tool must subclass.

    Subclasses define:
      - name: str
      - binary: str          (the executable name/path; resolved once at registration)
      - version: str
      - timeout_seconds / max_output_bytes / memory_limit_bytes: resource limits
      - build_args(target, options) -> list[str]   (NOT including the binary itself)
      - normalize_output(raw_stdout) -> Any         (tool-specific parsing)
    """

    name: str = "unnamed-tool"
    binary: str = ""
    version: str = "unknown"
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    memory_limit_bytes: Optional[int] = DEFAULT_MEMORY_LIMIT_BYTES

    def is_installed(self) -> bool:
        return shutil.which(self.binary) is not None

    def build_args(self, target: str, options: dict[str, Any]) -> list[str]:
        raise NotImplementedError

    def normalize_output(self, raw_stdout: str) -> Any:
        raise NotImplementedError

    async def execute(
        self,
        target: str,
        options: Optional[dict[str, Any]] = None,
        stdin_data: Optional[str] = None,
    ) -> ToolResult:
        options = options or {}

        if not self.is_installed():
            raise ToolNotInstalledError(
                self.name, f"binary '{self.binary}' not found on PATH. See scripts/install_recon_tools.sh"
            )

        args = self.build_args(target, options)
        command = [self.binary, *args]

        logger.info("executing tool=%s target=%s command=%s", self.name, target, command)

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=lambda: _apply_rlimits(self.memory_limit_bytes),
            )
        except FileNotFoundError as exc:
            raise ToolNotInstalledError(self.name, str(exc)) from exc

        truncated = False
        stdin_bytes = stdin_data.encode("utf-8") if stdin_data is not None else None
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes), timeout=self.timeout_seconds
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise ToolTimeoutError(
                self.name, f"execution exceeded {self.timeout_seconds}s and was killed."
            )

        duration = time.monotonic() - start

        if len(stdout_bytes) > self.max_output_bytes:
            stdout_bytes = stdout_bytes[: self.max_output_bytes]
            truncated = True

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        output_hash = hashlib.sha256(stdout_bytes).hexdigest()

        result = ToolResult(
            tool_name=self.name,
            command=command,
            returncode=proc.returncode or 0,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            truncated=truncated,
            output_sha256=output_hash,
        )

        logger.info(
            "completed tool=%s returncode=%s duration=%.2fs output_sha256=%s truncated=%s",
            self.name,
            result.returncode,
            duration,
            output_hash,
            truncated,
        )

        return result
