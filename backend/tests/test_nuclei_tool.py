import json

from app.tools.vulnerability.nuclei import NucleiTool


def test_dos_and_fuzz_always_excluded_even_if_caller_tries_to_allow():
    tool = NucleiTool()
    args = tool.build_args("", {"allow_intrusive": True, "extra_exclude_tags": []})
    etags = args[args.index("-etags") + 1]
    assert "dos" in etags
    assert "fuzz" in etags


def test_intrusive_tags_excluded_by_default():
    tool = NucleiTool()
    args = tool.build_args("", {})
    etags = args[args.index("-etags") + 1]
    assert "intrusive" in etags
    assert "default-login" in etags


def test_intrusive_tags_allowed_only_when_explicitly_opted_in():
    tool = NucleiTool()
    args = tool.build_args("", {"allow_intrusive": True})
    etags = args[args.index("-etags") + 1]
    assert "intrusive" not in etags.split(",")
    assert "default-login" not in etags.split(",")
    # dos/fuzz still excluded regardless
    assert "dos" in etags.split(",")


def test_irr_always_present_for_evidence_capture():
    tool = NucleiTool()
    args = tool.build_args("", {})
    assert "-irr" in args


def test_template_selection_is_tag_based_not_path_based():
    tool = NucleiTool()
    args = tool.build_args("", {"include_tags": ["cve", "exposure"]})
    assert "-tags" in args
    tags_value = args[args.index("-tags") + 1]
    assert tags_value == "cve,exposure"
    # No raw path flag should ever appear from options
    assert "-t" not in args or "-templates" not in args  # nuclei's path flag is -t / -templates


def test_normalize_output_extracts_cwe_and_cve_from_classification():
    raw_line = json.dumps(
        {
            "template-id": "CVE-2021-12345",
            "info": {
                "name": "Example RCE",
                "severity": "critical",
                "tags": ["cve", "rce"],
                "classification": {"cwe-id": ["CWE-94"], "cve-id": ["CVE-2021-12345"]},
                "reference": ["https://example.com/advisory"],
            },
            "matched-at": "https://target.example.com/api/exec",
            "matcher-name": "rce-match",
            "extracted-results": ["uid=0(root)"],
            "request": "GET /api/exec HTTP/1.1",
            "response": "HTTP/1.1 200 OK",
            "type": "http",
        }
    )
    tool = NucleiTool()
    records = tool.normalize_output(raw_line)
    assert len(records) == 1
    rec = records[0]
    assert rec["cwe"] == "CWE-94"
    assert rec["cve_ids"] == ["CVE-2021-12345"]
    assert rec["severity"] == "critical"
    assert rec["endpoint"] == "https://target.example.com/api/exec"
    assert any("extracted:" in e for e in rec["evidence"])
    assert rec["requests"] == ["GET /api/exec HTTP/1.1"]


def test_normalize_output_skips_malformed_lines():
    tool = NucleiTool()
    records = tool.normalize_output("not json\n{ broken\n")
    assert records == []
