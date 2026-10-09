import pytest

from app.tools.discovery.ffuf import FfufTool, UnknownWordlistError


def test_build_args_uses_allowlisted_wordlist_by_default():
    tool = FfufTool()
    args = tool.build_args("https://example.com", {})
    assert "-w" in args
    wordlist_path = args[args.index("-w") + 1]
    assert wordlist_path.endswith("common-small.txt")


def test_build_args_rejects_arbitrary_wordlist_path():
    tool = FfufTool()
    with pytest.raises(UnknownWordlistError):
        tool.build_args("https://example.com", {"wordlist": "/etc/passwd"})


def test_build_args_rejects_unknown_wordlist_key():
    tool = FfufTool()
    with pytest.raises(UnknownWordlistError):
        tool.build_args("https://example.com", {"wordlist": "rockyou"})


def test_build_args_injects_fuzz_keyword_if_missing():
    tool = FfufTool()
    args = tool.build_args("https://example.com", {})
    url = args[args.index("-u") + 1]
    assert url == "https://example.com/FUZZ"


def test_normalize_output_parses_json_lines():
    tool = FfufTool()
    raw = (
        '{"url":"https://example.com/admin","status":200,"length":512,"words":10,"lines":5}\n'
        '{"url":"https://example.com/backup","status":403,"length":10,"words":2,"lines":1}\n'
    )
    records = tool.normalize_output(raw)
    assert len(records) == 2
    assert records[0]["status_code"] == 200
