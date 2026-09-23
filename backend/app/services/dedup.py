import hashlib
import re


def compute_content_hash(title: str, content_text: str | None = None) -> str:
    """Compute SHA256 hash for cross-feed deduplication.

    Uses normalized title + first 500 chars of content_text.
    """
    normalized = _normalize_text(title)
    if content_text:
        normalized += " " + _normalize_text(content_text[:500])
    return hashlib.sha256(normalized.encode()).hexdigest()


def _normalize_text(text: str) -> str:
    """Normalize text for dedup comparison."""
    text = text.lower().strip()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[^\w\s]", "", text)
    return text
