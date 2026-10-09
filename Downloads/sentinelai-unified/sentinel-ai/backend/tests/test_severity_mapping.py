from app.services.severity_mapping import map_tags_to_owasp


def test_maps_sqli_tag_to_injection():
    assert map_tags_to_owasp(["sqli", "cve"]) == "A03:2021-Injection"


def test_maps_idor_tag_to_broken_access_control():
    assert map_tags_to_owasp(["idor"]) == "A01:2021-Broken Access Control"


def test_unknown_tags_return_none():
    assert map_tags_to_owasp(["some-made-up-tag"]) is None


def test_empty_tags_return_none():
    assert map_tags_to_owasp([]) is None


def test_case_insensitive():
    assert map_tags_to_owasp(["XSS"]) == "A03:2021-Injection"
