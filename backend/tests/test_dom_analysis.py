from app.analysis.dom_analysis import diff_dom


def test_identical_dom_has_no_diff():
    html = "<html><body><p>Hello</p></body></html>"
    diff = diff_dom(html, html)
    assert diff.nodes_added == 0
    assert diff.nodes_removed == 0
    assert diff.new_script_tags == 0
    assert diff.new_event_handlers == []


def test_new_script_tag_detected():
    baseline = "<html><body><p>Hello</p></body></html>"
    test = "<html><body><p>Hello</p><script>alert(1)</script></body></html>"
    diff = diff_dom(baseline, test)
    assert diff.new_script_tags == 1
    assert diff.nodes_added >= 1


def test_new_event_handler_detected():
    baseline = "<html><body><img src='a.png'></body></html>"
    test = "<html><body><img src='a.png' onerror='doStuff()'></body></html>"
    diff = diff_dom(baseline, test)
    assert any("onerror" in h for h in diff.new_event_handlers)


def test_removed_elements_detected():
    baseline = "<html><body><div>A</div><div>B</div></body></html>"
    test = "<html><body><div>A</div></body></html>"
    diff = diff_dom(baseline, test)
    assert diff.nodes_removed >= 1
