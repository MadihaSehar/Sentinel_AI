from app.analysis.similarity import (
    body_hash,
    length_comparison,
    structural_similarity,
    text_similarity,
)


def test_identical_bodies_have_similarity_1():
    a = "<html><body><h1>Hello</h1></body></html>"
    assert text_similarity(a, a) == 1.0
    assert structural_similarity(a, a) == 1.0


def test_empty_vs_nonempty_is_zero():
    assert text_similarity("", "something") == 0.0
    assert text_similarity("something", "") == 0.0


def test_both_empty_is_one():
    assert text_similarity("", "") == 1.0


def test_similar_pages_score_high():
    a = "<html><body><p>Welcome user 123</p></body></html>"
    b = "<html><body><p>Welcome user 456</p></body></html>"
    sim = text_similarity(a, b)
    assert sim > 0.8


def test_very_different_pages_score_low():
    a = "<html><body><p>Welcome user 123</p></body></html>"
    b = "<html><body><h1>500 Internal Server Error</h1><pre>Traceback...</pre></body></html>"
    sim = text_similarity(a, b)
    assert sim < 0.6


def test_length_comparison_delta_and_ratio():
    cmp = length_comparison("abc", "abcdef")
    assert cmp.delta == 3
    assert cmp.ratio == 2.0


def test_body_hash_stable_and_sensitive():
    h1 = body_hash("same content")
    h2 = body_hash("same content")
    h3 = body_hash("different content")
    assert h1 == h2
    assert h1 != h3
