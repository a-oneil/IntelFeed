"""Entry embeddings — the vector substrate under Story Threads.

Deliberately not routed through the AI task/assignment machinery. Embedding is
a bulk, non-generative job with no prompt, no schema and no cost, and it has to
keep running when every generative provider is paused, rate-limited or (as in
dev) simply inactive. So it reads its own settings and builds its own client,
borrowing only the Ollama provider row's base URL and bearer token when one is
configured.

Nothing here re-embeds an entry whose text has not changed: ``content_hash``
covers the exact string that was sent, so a re-run is free. What makes that
claim true rather than decorative is the third selector — once nothing is
pending and no model has changed, the sweep walks the least-recently-verified
slice of the corpus and re-hashes it, which is how a re-sanitized article, a
re-fetched body or a change to ``build_text`` itself finds its way back through
here without anyone running a backfill by hand.
"""

import hashlib
import logging

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.providers.base import AIProvider
from app.ai.providers.ollama_provider import DEFAULT_BASE_URL, OllamaProvider
from app.config import settings
from app.core.encryption import decrypt_value
from app.models.ai_provider import AIProvider as AIProviderModel
from app.models.entry_embedding import EMBEDDING_DIM
from app.models.vector_types import to_literal

logger = logging.getLogger(__name__)

# What actually gets embedded. Title carries most of the story identity, so it
# is never truncated; the body is cut at a length that covers the lede and the
# first substantive paragraphs — past that, articles about the same event stop
# resembling each other and start resembling their own publisher's house style.
BODY_CHARS = 1500

# Below this a summary is a teaser, not an article: "Read more", a byline, a
# 119-character blurb, or the three-character stub 130 entries in this corpus
# ship. 70% of embedded entries have a summary under 200 characters while
# averaging 4,381 characters of body, so preferring the summary unconditionally
# threw the article away and embedded the headline with noise attached.
MIN_SUMMARY_CHARS = 300

# No task prefix. nomic-embed-text documents "search_document: " / "clustering: "
# prefixes, and both were measured against real headline pairs here: the
# clustering prefix lifts an unrelated pair from 0.45 to 0.68 cosine while
# lifting a matched pair from 0.96 to 0.98 — it compresses the space and costs
# roughly half the separation the thresholds depend on. Raw text separates best.


def build_text(title: str | None, summary: str | None, content_text: str | None) -> str:
    """The exact string sent to the embedding model for one entry.

    A substantive summary is the better input — it is the lede, already stripped
    of navigation and boilerplate. A thin one is worse than nothing, so the
    article body takes over.
    """
    summary_text = (summary or "").strip()
    body_text = (content_text or "").strip()
    body = summary_text if len(summary_text) >= MIN_SUMMARY_CHARS else (body_text or summary_text)
    return f"{(title or '').strip()}\n\n{body[:BODY_CHARS]}".strip()


def content_hash(embed_text: str, model: str) -> str:
    """Hash of the text *and* the model — swapping models re-embeds the corpus."""
    return hashlib.sha256(f"{model}\x00{embed_text}".encode()).hexdigest()


class EmbeddingsNotConfigured(RuntimeError):
    """Embeddings are switched on but there is nothing to call.

    Raised instead of a connection error so the sweeper can log one quiet line
    and stop: an install with no Ollama provider row and no explicit
    ``embedding_base_url`` has nowhere to send the text.
    """


async def _ollama_provider_row(db: AsyncSession) -> AIProviderModel | None:
    return (
        (
            await db.execute(
                select(AIProviderModel)
                .where(AIProviderModel.provider_type == "ollama")
                .order_by(AIProviderModel.created_at)
            )
        )
        .scalars()
        .first()
    )


async def resolve_provider(db: AsyncSession) -> tuple[AIProvider, str]:
    """(client, model) for embedding calls, or raise if it isn't configured."""
    model = str(settings.get("embedding_model") or "").strip()
    if not model:
        raise EmbeddingsNotConfigured("embedding_model is not set")

    base_url = str(settings.get("embedding_base_url") or "").strip()
    api_key = None

    row = await _ollama_provider_row(db)
    if row:
        base_url = base_url or (row.base_url or "")
        if row.api_key_encrypted:
            api_key = decrypt_value(row.api_key_encrypted)

    if not base_url and row is None:
        # Embeddings ship enabled, but a Claude/OpenAI-only install has no
        # Ollama host to embed with. Say so once per sweep rather than
        # dialling http://ollama:11434 and logging a connection error.
        raise EmbeddingsNotConfigured(
            "no Ollama provider and no embedding_base_url — add an Ollama provider "
            "under Settings → AI Configuration (serving the embedding model) or set "
            "embedding_base_url, or turn embeddings_enabled off"
        )

    return OllamaProvider(base_url=base_url or DEFAULT_BASE_URL, api_key=api_key), model


async def pending_entries(db: AsyncSession, model: str, limit: int) -> list[dict]:
    """Entries with no current embedding, newest first.

    Newest-first matters: threads only look at a recent window, so a partial
    backfill still produces working threads on the way through the archive.
    """
    rows = (
        (
            await db.execute(
                text(
                    """
                SELECT e.id, e.title, e.summary, e.content_text, ee.content_hash AS stored_hash
                FROM entries e
                LEFT JOIN entry_embeddings ee ON ee.entry_id = e.id AND ee.model = :model
                WHERE ee.entry_id IS NULL
                ORDER BY e.published_at DESC NULLS LAST
                LIMIT :limit
                """
                ),
                {"model": model, "limit": limit},
            )
        )
        .mappings()
        .all()
    )
    return [dict(r) for r in rows]


async def stale_entries(db: AsyncSession, model: str, limit: int) -> list[dict]:
    """Entries whose stored embedding came from a different model."""
    rows = (
        (
            await db.execute(
                text(
                    """
                SELECT e.id, e.title, e.summary, e.content_text, ee.content_hash AS stored_hash
                FROM entries e
                JOIN entry_embeddings ee ON ee.entry_id = e.id
                WHERE ee.model <> :model
                ORDER BY e.published_at DESC NULLS LAST
                LIMIT :limit
                """
                ),
                {"model": model, "limit": limit},
            )
        )
        .mappings()
        .all()
    )
    return [dict(r) for r in rows]


async def verify_entries(db: AsyncSession, model: str, limit: int) -> list[dict]:
    """The least-recently-verified slice of the corpus, for re-hashing.

    Only reached when nothing is pending and no model has changed, so it costs
    nothing during a backfill and nothing in steady state beyond hashing a few
    hundred strings. Rows whose hash still matches are stamped and rotate to the
    back; rows whose text (or whose ``build_text`` recipe) has changed since are
    re-embedded by the same path as everything else.
    """
    rows = (
        (
            await db.execute(
                text(
                    """
                SELECT e.id, e.title, e.summary, e.content_text, ee.content_hash AS stored_hash
                FROM entries e
                JOIN entry_embeddings ee ON ee.entry_id = e.id
                WHERE ee.model = :model
                ORDER BY ee.verified_at ASC NULLS FIRST, ee.created_at ASC
                LIMIT :limit
                """
                ),
                {"model": model, "limit": limit},
            )
        )
        .mappings()
        .all()
    )
    return [dict(r) for r in rows]


async def mark_verified(db: AsyncSession, entry_ids: list) -> None:
    """Stamp rows whose stored hash was just confirmed current."""
    if not entry_ids:
        return
    await db.execute(
        text("UPDATE entry_embeddings SET verified_at = now() WHERE entry_id = ANY(:ids)"),
        {"ids": list(entry_ids)},
    )


async def store(db: AsyncSession, entry_id, vector: list[float], model: str, digest: str) -> None:
    if len(vector) != EMBEDDING_DIM:
        raise ValueError(f"embedding model returned {len(vector)} dimensions, schema expects {EMBEDDING_DIM}")
    await db.execute(
        text(
            """
            INSERT INTO entry_embeddings (entry_id, embedding, model, content_hash, verified_at)
            VALUES (:entry_id, (:embedding)::halfvec, :model, :hash, now())
            ON CONFLICT (entry_id) DO UPDATE
            SET embedding = EXCLUDED.embedding,
                model = EXCLUDED.model,
                content_hash = EXCLUDED.content_hash,
                created_at = now(),
                verified_at = now()
            """
        ),
        {"entry_id": entry_id, "embedding": to_literal(vector), "model": model, "hash": digest},
    )


async def embed_batch(db: AsyncSession, provider: AIProvider, model: str, rows: list[dict]) -> int:
    """Embed one batch of entry rows and write the vectors. Returns rows written."""
    prepared = []
    for row in rows:
        embed_text = build_text(row.get("title"), row.get("summary"), row.get("content_text"))
        if not embed_text:
            continue
        digest = content_hash(embed_text, model)
        if digest == row.get("stored_hash"):
            continue
        prepared.append((row["id"], embed_text, digest))
    if not prepared:
        return 0

    vectors = await provider.embed([t for _, t, _ in prepared], model=model)
    for (entry_id, _, digest), vector in zip(prepared, vectors, strict=True):
        await store(db, entry_id, vector, model, digest)
    await db.commit()
    return len(prepared)


async def sweep(db: AsyncSession, limit: int | None = None) -> dict:
    """Embed the next slice of un-embedded entries. Safe to call repeatedly."""
    if not settings.get("embeddings_enabled"):
        return {"status": "disabled", "embedded": 0}

    limit = int(limit or settings.get("embedding_backfill_limit") or 2000)
    batch_size = max(1, int(settings.get("embedding_batch_size") or 32))

    try:
        provider, model = await resolve_provider(db)
    except EmbeddingsNotConfigured as exc:
        logger.info("embeddings sweep skipped: %s", exc)
        return {"status": "unconfigured", "embedded": 0, "reason": str(exc)}
    # Cheapest first: never embedded, then embedded under another model, then —
    # only once both are empty — re-hashing what is already stored.
    mode = "pending"
    rows = await pending_entries(db, model, limit)
    if not rows:
        mode, rows = "model", await stale_entries(db, model, limit)
    if not rows:
        mode, rows = "verify", await verify_entries(db, model, limit)
    if not rows:
        return {"status": "idle", "embedded": 0, "model": model}

    embedded = 0
    failed = 0
    for start in range(0, len(rows), batch_size):
        batch = rows[start : start + batch_size]
        try:
            embedded += await embed_batch(db, provider, model, batch)
            if mode == "verify":
                # Checked is checked, whether or not anything had to be redone;
                # without the stamp the same slice is re-verified forever.
                await mark_verified(db, [r["id"] for r in batch])
                await db.commit()
        except Exception as exc:  # noqa: BLE001 — one bad batch must not sink the sweep
            failed += len(batch)
            await db.rollback()
            logger.warning("embedding batch failed (%d entries): %s", len(batch), exc)

    return {
        "status": "ok",
        "mode": mode,
        "embedded": embedded,
        "failed": failed,
        "model": model,
        "considered": len(rows),
    }
