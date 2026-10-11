from pathlib import Path

import pytest

from app.payloads.knowledge_base import PayloadKnowledgeBase
from app.schemas.payload_kb import PayloadCategory, PayloadContext

KB_DIR = Path(__file__).resolve().parents[2] / "payload-kb"


@pytest.fixture(scope="module")
def kb() -> PayloadKnowledgeBase:
    return PayloadKnowledgeBase.load_from_directory(KB_DIR)


def test_kb_loads_without_errors(kb):
    assert len(kb) > 0


def test_every_entry_has_unique_id(kb):
    ids = [e.id for e in kb.all_entries()]
    assert len(ids) == len(set(ids))


def test_every_category_from_spec_has_at_least_one_entry(kb):
    # Section 7 lists these category concepts explicitly.
    expected = [
        PayloadCategory.XSS,
        PayloadCategory.SQL_INJECTION,
        PayloadCategory.COMMAND_INJECTION,
        PayloadCategory.SSRF,
        PayloadCategory.LFI,
        PayloadCategory.RFI,
        PayloadCategory.PATH_TRAVERSAL,
        PayloadCategory.CSRF,
        PayloadCategory.XXE,
        PayloadCategory.SSTI,
        PayloadCategory.IDOR_BOLA,
        PayloadCategory.OPEN_REDIRECT,
        PayloadCategory.CORS,
        PayloadCategory.JWT,
        PayloadCategory.AUTHENTICATION,
        PayloadCategory.API_SECURITY,
        PayloadCategory.GRAPHQL,
        PayloadCategory.FILE_UPLOAD,
        PayloadCategory.DESERIALIZATION,
        PayloadCategory.PROTOTYPE_POLLUTION,
    ]
    missing = [c for c in expected if len(kb.by_category(c)) == 0]
    assert missing == [], f"categories with zero KB entries: {missing}"


def test_get_by_id_returns_entry(kb):
    entry = kb.get("sqli-error-based")
    assert entry is not None
    assert entry.category == PayloadCategory.SQL_INJECTION


def test_get_by_unknown_id_returns_none(kb):
    assert kb.get("does-not-exist") is None


def test_by_context_index(kb):
    sql_string_entries = kb.by_context(PayloadContext.SQL_STRING_CONTEXT)
    assert len(sql_string_entries) > 0
    assert all(e.context == PayloadContext.SQL_STRING_CONTEXT for e in sql_string_entries)


def test_every_entry_requires_authorization(kb):
    # Section 7: requires_authorization should be true across the board
    # for this platform's intended use.
    assert all(e.requires_authorization for e in kb.all_entries())


def test_no_entry_has_more_than_one_example_string(kb):
    # Guard against the KB drifting into a bulk payload arsenal -- each
    # entry should carry at most one canonical example, not a list.
    for e in kb.all_entries():
        assert e.example is None or isinstance(e.example, str)


def test_select_relevant_matches_technology_to_category(kb):
    results = kb.select_relevant(["mysql", "php"], include_always_relevant=False)
    categories = {r.category for r in results}
    assert PayloadCategory.SQL_INJECTION in categories
    assert PayloadCategory.LFI in categories
    assert PayloadCategory.RFI in categories


def test_select_relevant_deduplicates_categories_matched_by_multiple_techs(kb):
    results = kb.select_relevant(["mysql", "postgresql"], include_always_relevant=False)
    sqli_matches = [r for r in results if r.category == PayloadCategory.SQL_INJECTION]
    assert len(sqli_matches) == 1


def test_select_relevant_includes_always_relevant_by_default(kb):
    results = kb.select_relevant([], include_always_relevant=True)
    categories = {r.category for r in results}
    assert PayloadCategory.OPEN_REDIRECT in categories
    assert PayloadCategory.CORS in categories


def test_select_relevant_can_exclude_always_relevant(kb):
    results = kb.select_relevant([], include_always_relevant=False)
    assert results == []


def test_select_relevant_unknown_technology_yields_no_match(kb):
    results = kb.select_relevant(["some-unknown-framework-xyz"], include_always_relevant=False)
    assert results == []


def test_select_relevant_entry_count_matches_kb(kb):
    results = kb.select_relevant(["mysql"], include_always_relevant=False)
    sqli_result = next(r for r in results if r.category == PayloadCategory.SQL_INJECTION)
    assert sqli_result.entry_count == len(kb.by_category(PayloadCategory.SQL_INJECTION))


def test_duplicate_id_detection(tmp_path):
    bad_file = tmp_path / "dupes.json"
    bad_file.write_text(
        """
        [
          {"id": "dup", "category": "xss", "context": "html", "risk_level": "low",
           "description": "a", "detection_method": "b"},
          {"id": "dup", "category": "xss", "context": "html", "risk_level": "low",
           "description": "a", "detection_method": "b"}
        ]
        """
    )
    with pytest.raises(ValueError, match="Duplicate payload entry ids"):
        PayloadKnowledgeBase.load_from_directory(tmp_path)


def test_invalid_entry_reports_validation_error(tmp_path):
    bad_file = tmp_path / "invalid.json"
    bad_file.write_text('[{"id": "x", "category": "not-a-real-category"}]')
    with pytest.raises(ValueError, match="failed to load cleanly"):
        PayloadKnowledgeBase.load_from_directory(tmp_path)


def test_non_array_top_level_reports_error(tmp_path):
    bad_file = tmp_path / "notarray.json"
    bad_file.write_text('{"id": "x"}')
    with pytest.raises(ValueError, match="expected a JSON array"):
        PayloadKnowledgeBase.load_from_directory(tmp_path)
