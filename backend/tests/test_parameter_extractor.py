from app.services.parameter_extractor import extract_parameters


def test_extracts_unique_param_names():
    urls = [
        "https://example.com/search?q=test&page=1",
        "https://example.com/view?id=5",
        "https://example.com/search?q=other",  # duplicate 'q', should not duplicate
        "https://example.com/no-params",
    ]
    params = extract_parameters(urls)
    names = {p.name for p in params}
    assert names == {"q", "page", "id"}


def test_keeps_first_example_url_for_duplicate_param():
    urls = [
        "https://example.com/search?q=first",
        "https://example.com/search?q=second",
    ]
    params = extract_parameters(urls)
    q_param = next(p for p in params if p.name == "q")
    assert q_param.example_url == "https://example.com/search?q=first"


def test_handles_empty_and_malformed_urls_gracefully():
    urls = ["", "not a url at all", "https://example.com/plain"]
    params = extract_parameters(urls)
    assert params == []


def test_blank_value_param_still_captured():
    urls = ["https://example.com/reset?token="]
    params = extract_parameters(urls)
    assert any(p.name == "token" for p in params)
