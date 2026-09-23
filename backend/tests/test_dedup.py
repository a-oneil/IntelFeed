from app.services.dedup import compute_content_hash


def test_same_content_same_hash():
    hash1 = compute_content_hash("Breaking News Title", "Some article content here")
    hash2 = compute_content_hash("Breaking News Title", "Some article content here")
    assert hash1 == hash2


def test_different_content_different_hash():
    hash1 = compute_content_hash("Title One", "Content alpha")
    hash2 = compute_content_hash("Title Two", "Content beta")
    assert hash1 != hash2


def test_normalization_ignores_case():
    hash1 = compute_content_hash("Breaking News", "Content here")
    hash2 = compute_content_hash("BREAKING NEWS", "CONTENT HERE")
    assert hash1 == hash2


def test_normalization_ignores_punctuation():
    hash1 = compute_content_hash("Hello World", "Some content")
    hash2 = compute_content_hash("Hello, World!", "Some... content?")
    assert hash1 == hash2


def test_normalization_ignores_whitespace():
    hash1 = compute_content_hash("Hello World", "Some content here")
    hash2 = compute_content_hash("Hello   World", "Some   content   here")
    assert hash1 == hash2


def test_hash_with_none_content():
    hash1 = compute_content_hash("Title Only")
    hash2 = compute_content_hash("Title Only", None)
    assert hash1 == hash2
    # Should still produce a valid hex hash
    assert len(hash1) == 64  # SHA-256 hex length
