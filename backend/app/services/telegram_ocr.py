"""Optional OCR pass over Telegram-downloaded images.

Off by default. Enable via TELEGRAM_OCR_ENABLED=true. Requires pytesseract +
the tesseract binary present in the worker image (apt-get install tesseract-ocr).

Many ransomware leak channels post screenshots of stolen file trees, sample data,
or victim communications. Turning the bytes into text lets the autolinker pick up
file paths, hostnames, and product names from images the body wouldn't otherwise
contain.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def is_available() -> bool:
    """Return True if pytesseract + the tesseract binary are usable."""
    try:
        import pytesseract  # noqa: F401
    except ImportError:
        return False
    try:
        import pytesseract

        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def ocr_image(path: str | Path, *, min_chars: int = 30, lang: str = "eng") -> str | None:
    """Run OCR over an image file and return the extracted text, or None.

    Returns None when:
      - pytesseract isn't installed
      - the file doesn't exist or fails to load
      - the result is shorter than min_chars (mostly noise)
    """
    target = Path(path)
    if not target.is_file():
        return None
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        logger.debug("pytesseract or Pillow not installed — skipping OCR for %s", target)
        return None

    try:
        with Image.open(target) as img:
            text = pytesseract.image_to_string(img, lang=lang)
    except Exception:
        logger.warning("OCR failed for %s", target, exc_info=True)
        return None

    cleaned = (text or "").strip()
    if len(cleaned) < min_chars:
        return None
    return cleaned


def local_path_for_url(url: str, media_root: str) -> str | None:
    """Map an /api/telegram-media/<channel_id>/<filename> URL back to its on-disk path."""
    if not url or not url.startswith("/api/telegram-media/"):
        return None
    rel = url[len("/api/telegram-media/") :]
    parts = rel.split("/", 1)
    if len(parts) != 2:
        return None
    channel_id, filename = parts
    safe = os.path.normpath(os.path.join(media_root, channel_id, filename))
    if not safe.startswith(os.path.normpath(media_root) + os.sep):
        return None
    return safe
