import pytest

from app.tools.base import SecurityTool, ToolNotInstalledError, ToolTimeoutError


class EchoTool(SecurityTool):
    """A harmless test tool that just runs `python3 -c <code>` — no shell involved."""

    name = "echo-test-tool"
    binary = "python3"
    timeout_seconds = 2
    max_output_bytes = 1024  # deliberately small, to test truncation

    def build_args(self, target, options):
        code = options.get("code", "print('hello')")
        return ["-c", code]

    def normalize_output(self, raw_stdout):
        return raw_stdout.strip().splitlines()


class MissingBinaryTool(SecurityTool):
    name = "nonexistent-tool"
    binary = "this-binary-does-not-exist-xyz"

    def build_args(self, target, options):
        return []

    def normalize_output(self, raw_stdout):
        return []


@pytest.mark.asyncio
async def test_tool_executes_and_captures_stdout():
    tool = EchoTool()
    result = await tool.execute("irrelevant", options={"code": "print('hello world')"})
    assert result.returncode == 0
    assert "hello world" in result.stdout
    assert result.output_sha256
    assert not result.truncated


@pytest.mark.asyncio
async def test_tool_enforces_timeout():
    tool = EchoTool()
    with pytest.raises(ToolTimeoutError):
        await tool.execute("irrelevant", options={"code": "import time; time.sleep(10)"})


@pytest.mark.asyncio
async def test_tool_truncates_oversized_output():
    tool = EchoTool()
    # produce output much larger than max_output_bytes
    result = await tool.execute("irrelevant", options={"code": "print('x' * 100000)"})
    assert result.truncated
    assert len(result.stdout.encode("utf-8")) <= tool.max_output_bytes


@pytest.mark.asyncio
async def test_missing_binary_raises_not_installed():
    tool = MissingBinaryTool()
    assert not tool.is_installed()
    with pytest.raises(ToolNotInstalledError):
        await tool.execute("irrelevant")


@pytest.mark.asyncio
async def test_stdin_data_is_passed_through():
    tool = EchoTool()
    code = "import sys; data = sys.stdin.read(); print(data.strip().upper())"
    result = await tool.execute("irrelevant", options={"code": code}, stdin_data="hello from stdin")
    assert "HELLO FROM STDIN" in result.stdout


def test_build_args_never_receives_shell_metacharacters_unescaped():
    """
    Sanity check that our own argv construction doesn't get shell-interpreted:
    passing a string with shell metacharacters as an argv element must be
    treated as a literal, not executed.
    """
    tool = EchoTool()
    args = tool.build_args("irrelevant", {"code": "print('$(whoami); rm -rf /')"})
    # The whole thing is one argv element — never parsed by a shell.
    assert args == ["-c", "print('$(whoami); rm -rf /')"]
