"""LibreTranslate client for on-demand entry translation.

Wraps the self-hosted LibreTranslate sidecar's `/detect` and `/translate`
endpoints. Translations preserve HTML structure via `format=html`.
"""

from __future__ import annotations

import httpx
import structlog

from app.config import settings
from app.core.exceptions import AppError

logger = structlog.get_logger(__name__)


class TranslationError(AppError):
    def __init__(self, message: str, *, status_code: int = 502) -> None:
        super().__init__(code="translation_failed", message=message, status_code=status_code)


def _base_url() -> str:
    return settings.libretranslate_url.rstrip("/")


def _api_key() -> str:
    return settings.libretranslate_api_key or ""


async def detect_language(text: str) -> tuple[str, float]:
    """Return (language_code, confidence) for the given text."""
    if not text or not text.strip():
        return ("en", 0.0)
    payload: dict[str, str] = {"q": text[:5000]}
    if _api_key():
        payload["api_key"] = _api_key()
    try:
        async with httpx.AsyncClient(timeout=settings.translation_timeout_seconds) as client:
            resp = await client.post(f"{_base_url()}/detect", data=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        logger.warning("libretranslate.detect_failed", error=str(exc))
        raise TranslationError(f"Language detection failed: {exc}") from exc
    if not isinstance(data, list) or not data:
        return ("en", 0.0)
    top = data[0]
    return (str(top.get("language", "en")), float(top.get("confidence", 0.0)))


def _extract_detected_language(data: dict) -> str | None:
    """Pull LibreTranslate's `detectedLanguage.language` from a /translate response."""
    detected = data.get("detectedLanguage")
    if isinstance(detected, dict):
        lang = detected.get("language")
        if isinstance(lang, str) and lang:
            return lang
    return None


async def translate_html(text: str, *, source: str, target: str) -> tuple[str, str | None]:
    """Translate HTML, preserving tag structure. `source` may be 'auto'.

    Returns `(translated_text, detected_source_language)`. The detected language
    is only populated when `source == "auto"` and the server reported one.
    """
    if not text:
        return ("", None)
    payload: dict[str, str] = {
        "q": text,
        "source": source or "auto",
        "target": target,
        "format": "html",
    }
    if _api_key():
        payload["api_key"] = _api_key()
    try:
        async with httpx.AsyncClient(timeout=settings.translation_timeout_seconds) as client:
            resp = await client.post(f"{_base_url()}/translate", data=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        logger.warning("libretranslate.translate_failed", error=str(exc), source=source, target=target)
        raise TranslationError(f"Translation failed: {exc}") from exc
    translated = data.get("translatedText")
    if not isinstance(translated, str):
        raise TranslationError("Translation service returned an unexpected response")
    return (translated, _extract_detected_language(data))


async def translate_text(text: str, *, source: str, target: str) -> tuple[str, str | None]:
    """Translate plain text (no HTML preserved). `source` may be 'auto'.

    Returns `(translated_text, detected_source_language)`.
    """
    if not text:
        return ("", None)
    payload: dict[str, str] = {
        "q": text,
        "source": source or "auto",
        "target": target,
        "format": "text",
    }
    if _api_key():
        payload["api_key"] = _api_key()
    try:
        async with httpx.AsyncClient(timeout=settings.translation_timeout_seconds) as client:
            resp = await client.post(f"{_base_url()}/translate", data=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        logger.warning("libretranslate.translate_text_failed", error=str(exc), source=source, target=target)
        raise TranslationError(f"Translation failed: {exc}") from exc
    translated = data.get("translatedText")
    if not isinstance(translated, str):
        raise TranslationError("Translation service returned an unexpected response")
    return (translated, _extract_detected_language(data))


async def supported_languages() -> list[dict]:
    """Return the list of languages the configured LibreTranslate instance has loaded."""
    try:
        async with httpx.AsyncClient(timeout=settings.translation_timeout_seconds) as client:
            resp = await client.get(f"{_base_url()}/languages")
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPError as exc:
        logger.warning("libretranslate.languages_failed", error=str(exc))
        raise TranslationError(f"Could not fetch supported languages: {exc}") from exc
