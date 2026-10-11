from app.analysis.reflection import MarkerInput, find_reflections


def test_no_markers_no_reflections():
    body = "<html><body>Hello world</body></html>"
    assert find_reflections(body, []) == []


def test_marker_reflected_in_html_body():
    marker = "SENTINEL_CANARY_abc123"
    body = f"<html><body>Search results for: {marker}</body></html>"
    results = find_reflections(body, [MarkerInput(parameter="q", marker=marker)])
    assert len(results) == 1
    assert results[0].context == "html_body"
    assert results[0].encoded is False


def test_marker_reflected_in_html_attribute():
    marker = "SENTINEL_CANARY_attr"
    body = f'<html><body><input value="{marker}"></body></html>'
    results = find_reflections(body, [MarkerInput(parameter="name", marker=marker)])
    assert any(r.context == "html_attribute" for r in results)


def test_marker_reflected_in_script_block():
    marker = "SENTINEL_CANARY_js"
    body = f"<html><body><script>var x = '{marker}';</script></body></html>"
    results = find_reflections(body, [MarkerInput(parameter="x", marker=marker)])
    assert any(r.context == "js_string" for r in results)


def test_html_escaped_marker_detected_as_escaped():
    marker = "<b>abc</b>"
    escaped_body = "<html><body>&lt;b&gt;abc&lt;/b&gt;</body></html>"
    results = find_reflections(escaped_body, [MarkerInput(parameter="q", marker=marker)])
    assert any(r.html_escaped for r in results)


def test_marker_not_present_yields_no_reflection():
    body = "<html><body>nothing here</body></html>"
    results = find_reflections(body, [MarkerInput(parameter="q", marker="NOT_PRESENT_XYZ")])
    assert results == []


def test_marker_reflected_in_json_value():
    marker = "SENTINEL_CANARY_json"
    body = '{"status": "ok", "echo": "' + marker + '"}'
    results = find_reflections(body, [MarkerInput(parameter="echo", marker=marker)])
    assert any(r.context == "json_value" for r in results)


def test_marker_after_colon_in_plain_html_is_not_json():
    marker = "SENTINEL_CANARY_colon"
    body = f"<html><body>Search results for: {marker}</body></html>"
    results = find_reflections(body, [MarkerInput(parameter="q", marker=marker)])
    assert all(r.context != "json_value" for r in results)


def test_marker_reflected_in_response_header():
    marker = "SENTINEL_HEADER_MARKER"
    body = "<html></html>"
    headers = {"X-Echo": f"input-was-{marker}"}
    results = find_reflections(body, [MarkerInput(parameter="q", marker=marker)], headers=headers)
    assert any(r.context == "header" for r in results)
