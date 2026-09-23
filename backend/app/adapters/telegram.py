"""Telegram channel adapter — fetches messages from public channels via MTProto.

Uses Telethon with a single operator-provisioned user account. The session file
is bootstrapped once interactively via scripts/telegram/telegram_login.py and persists
on a Docker volume.

Per-process singleton client, lazy-initialized inside fetch_entries (after fork).
Initialized at module top level would break Celery prefork — see "Gotchas".
"""

from __future__ import annotations

import asyncio
import html as html_mod
import logging
import os
from datetime import UTC, datetime, timedelta
from typing import Any

from app.adapters.base import ExtendedAdapter, ParsedEntry, ParsedFeedMeta, ParsedMedia
from app.config import settings

logger = logging.getLogger(__name__)


def normalize_channel_handle(value: Any) -> Any:
    """Strip Telegram's web-preview ``/s/`` prefix from a channel URL.

    ``t.me/s/<handle>`` is the unauthenticated HTML preview route, not a real
    MTProto username — Telethon's ``get_entity`` rejects it. Users routinely
    paste it because it's the URL the browser lands on.
    """
    if not isinstance(value, str):
        return value
    s = value.strip()
    if not s:
        return s
    for scheme in ("https://", "http://", ""):
        for host in ("t.me/", "telegram.me/"):
            prefix = f"{scheme}{host}s/"
            if s.lower().startswith(prefix.lower()):
                return f"{scheme}{host}{s[len(prefix) :]}"
    return s


# Media type mapping
_MEDIA_PHOTO_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
_MEDIA_VIDEO_MIMES_PREFIX = "video/"
_MEDIA_AUDIO_MIMES_PREFIX = "audio/"
_MEDIA_IMAGE_MIMES_PREFIX = "image/"


class TelegramAdapter(ExtendedAdapter):
    """Fetches messages from a Telegram channel via Telethon (MTProto)."""

    # Per-process, per-session client cache. The default session keys to "" (empty string),
    # named sessions key to their session_name. Initialized lazily inside fetch_entries
    # (post-fork) — never at import time, or every Celery worker would inherit a shared socket.
    _clients: dict[str, Any] = {}
    _clients_lock: asyncio.Lock | None = None
    # Serialized StringSession strings, keyed the same way. We read each SQLite session
    # file exactly once per-process to extract the auth_key, then run Telethon entirely
    # off StringSession so multiple processes (api, listener, celery workers) don't fight
    # over the SQLite session file's writer lock.
    _string_sessions: dict[str, str] = {}
    # Entity cache copied out of the SQLite session at first read. StringSession.save()
    # does not serialize entities, so without this every numeric channel_id / forward
    # PeerUser would miss the cache and raise "Could not find the input entity".
    _session_entities: dict[str, set[tuple]] = {}

    def get_feed_meta(self, config: dict) -> ParsedFeedMeta:
        channel = normalize_channel_handle(config.get("channel") or config.get("channel_username") or "")
        return ParsedFeedMeta(
            title=f"Telegram: {channel}" if channel else "Telegram",
            description=f"Messages from Telegram channel {channel}" if channel else None,
            site_url=f"https://t.me/{channel.lstrip('@')}" if channel and not channel.startswith("http") else channel,
        )

    async def fetch_entries(
        self, config: dict, since: datetime | None = None
    ) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        if not settings.telegram_api_id or not settings.telegram_api_hash:
            raise RuntimeError("Telegram is not configured. Set TELEGRAM_API_ID and TELEGRAM_API_HASH.")

        channel_input = normalize_channel_handle(config.get("channel") or config.get("channel_username"))
        channel_id = config.get("channel_id")
        if not channel_input and not channel_id:
            raise RuntimeError("Telegram feed missing 'channel' in adapter_config.")

        session_name = (config.get("session_name") or "").strip()
        client = await self._get_client(session_name)

        # Prefer username/link — resolves server-side without needing a cached entity.
        # Fall back to numeric channel_id only when no username (private channels), since
        # numeric IDs require an (id, hash) pair in the session entity cache.
        try:
            entity_ref: Any = channel_input if channel_input else channel_id
            entity = await client.get_entity(entity_ref)
        except Exception as exc:
            from telethon import errors as tg_errors  # local import; lib loaded lazily

            if isinstance(exc, getattr(tg_errors, "FloodWaitError", ())):
                wait_s = getattr(exc, "seconds", 0)
                raise RuntimeError(f"Telegram flood wait {wait_s}s while resolving channel")
            if isinstance(
                exc,
                (
                    getattr(tg_errors, "ChannelPrivateError", ()),
                    getattr(tg_errors, "UsernameNotOccupiedError", ()),
                    getattr(tg_errors, "UsernameInvalidError", ()),
                ),
            ):
                raise RuntimeError(f"Telegram channel unavailable: {exc}")
            if isinstance(
                exc,
                (
                    getattr(tg_errors, "AuthKeyUnregisteredError", ()),
                    getattr(tg_errors, "SessionRevokedError", ()),
                    getattr(tg_errors, "AuthKeyDuplicatedError", ()),
                ),
            ):
                # Drop the cached client AND the cached StringSession for this session so
                # the next fetch re-reads SQLite. Operator must re-bootstrap that specific
                # session if SQLite itself is now stale (e.g. revoked server-side).
                type(self)._clients.pop(session_name, None)
                type(self)._string_sessions.pop(session_name, None)
                raise RuntimeError(
                    "Telegram session revoked. Run scripts/telegram/telegram_login.py to re-authenticate."
                )
            raise

        resolved_channel_id = int(getattr(entity, "id", 0)) or None
        # Telethon "channel" entities expose .username; some private channels have None
        resolved_username = getattr(entity, "username", None) or ""
        title = getattr(entity, "title", None) or resolved_username or str(channel_input)
        # Construct the negative "real" channel id used in t.me/c/<id>/<msg> permalinks
        if resolved_channel_id and resolved_channel_id > 0:
            permalink_channel_id = resolved_channel_id
        else:
            permalink_channel_id = -1 * (resolved_channel_id or 0) if resolved_channel_id else None

        last_seen_id = int(config.get("last_seen_id") or 0)
        max_messages = int(config.get("max_messages_per_fetch") or 200)
        max_age_days = int(config.get("max_message_age_days") or 30)
        include_media = bool(config.get("include_media", True))
        media_types = set(config.get("media_types") or ["photo", "video", "document", "audio"])
        extract_forwards = bool(config.get("extract_forwards", True))

        # First fetch: bound by max_message_age_days. Incremental: bound by last_seen_id.
        if last_seen_id == 0 and max_age_days > 0:
            min_date = datetime.now(UTC) - timedelta(days=max_age_days)
        else:
            min_date = None

        entries: list[ParsedEntry] = []
        max_id_seen = last_seen_id
        flood_wait_seconds: int | None = None

        try:
            async for message in client.iter_messages(
                entity,
                min_id=last_seen_id,
                limit=max_messages,
                reverse=True,
                # offset_date + reverse=True => "messages newer than min_date, oldest-first".
                # Without this, the limit slices the OLDEST 200 messages and an active long-lived
                # channel ends up with every result older than the window — silently zero entries.
                offset_date=min_date,
            ):
                msg_date = getattr(message, "date", None)
                if min_date and msg_date and msg_date < min_date:
                    continue

                msg_id = int(getattr(message, "id", 0) or 0)
                if msg_id > max_id_seen:
                    max_id_seen = msg_id

                parsed = self._message_to_entry(
                    message,
                    channel_id=resolved_channel_id,
                    permalink_channel_id=permalink_channel_id,
                    channel_username=resolved_username,
                    extract_forwards=extract_forwards,
                )

                if include_media and getattr(message, "media", None) is not None:
                    media = await self._build_media(
                        client,
                        message,
                        channel_id=resolved_channel_id,
                        media_types=media_types,
                        max_size_mb=settings.telegram_max_media_size_mb,
                    )
                    if media:
                        parsed.media = media
                        if media.metadata.get("telegram_grouped_id") is None:
                            grouped = getattr(message, "grouped_id", None)
                            if grouped:
                                parsed.metadata.setdefault("telegram_grouped_id", int(grouped))

                entries.append(parsed)
        except Exception as exc:
            from telethon import errors as tg_errors

            if isinstance(exc, getattr(tg_errors, "FloodWaitError", ())):
                flood_wait_seconds = int(getattr(exc, "seconds", 0) or 0)
                logger.warning(
                    "Telegram flood wait %ss while iterating channel %s — returning partial batch",
                    flood_wait_seconds,
                    resolved_username or resolved_channel_id,
                )
            elif isinstance(
                exc,
                (
                    getattr(tg_errors, "AuthKeyUnregisteredError", ()),
                    getattr(tg_errors, "SessionRevokedError", ()),
                    getattr(tg_errors, "AuthKeyDuplicatedError", ()),
                ),
            ):
                session_name = (config.get("session_name") or "").strip()
                type(self)._clients.pop(session_name, None)
                type(self)._string_sessions.pop(session_name, None)
                raise RuntimeError(
                    "Telegram session revoked. Run scripts/telegram/telegram_login.py to re-authenticate."
                )
            else:
                raise

        # Coalesce album messages — Telegram sends N media items as N separate messages
        # sharing a `grouped_id`, with the caption text on only one of them. Without
        # merging we'd get one "Message 1342" entry per item and the caption stranded
        # on its own. After merge: one entry with all media + the caption.
        entries = self._merge_album_groups(entries)

        meta = ParsedFeedMeta(
            title=f"Telegram: {resolved_username or title}",
            description=getattr(entity, "about", None) or None,
            site_url=(
                f"https://t.me/{resolved_username}"
                if resolved_username
                else (f"https://t.me/c/{permalink_channel_id}" if permalink_channel_id else None)
            ),
            extra={
                "channel_id": resolved_channel_id,
                "channel_username": resolved_username,
                # Only advance the watermark if we did NOT bail out on a flood mid-iteration —
                # otherwise we'd skip messages we never read.
                "last_seen_id": max_id_seen if flood_wait_seconds is None else last_seen_id,
                "telegram_flood_wait_seconds": flood_wait_seconds,
            },
        )

        return meta, entries

    @staticmethod
    def _merge_album_groups(entries: list[ParsedEntry]) -> list[ParsedEntry]:
        groups: dict[int, list[ParsedEntry]] = {}
        order: list[ParsedEntry] = []
        for e in entries:
            gid = e.metadata.get("telegram_grouped_id")
            if gid:
                groups.setdefault(int(gid), []).append(e)
            else:
                order.append(e)

        merged: list[ParsedEntry] = list(order)
        for gid, group in groups.items():
            # Pick the entry that actually has caption text — its title was built from
            # the first line, so a real caption produces a non-"Message N" title.
            canonical = next(
                (e for e in group if not e.title.startswith("Message ")),
                group[0],
            )
            all_media = [e.media for e in group if e.media is not None]
            # Order the canonical's own media first so it remains the lead attachment.
            if canonical.media in all_media:
                all_media.remove(canonical.media)
                all_media.insert(0, canonical.media)
            canonical.media = all_media[0] if all_media else None
            canonical.additional_media = all_media[1:]
            merged.append(canonical)

        merged.sort(key=lambda e: e.published_at.timestamp() if e.published_at is not None else 0)
        return merged

    async def probe_messages(self, config: dict, message_ids: list[int]) -> dict[int, ParsedEntry | None]:
        """Re-fetch a batch of previously-seen message IDs to detect edits/deletes.

        Returns a dict keyed by message_id:
        - ParsedEntry with the current state if the message still exists.
        - None if the message has been deleted on the Telegram side.

        Used by the worker to keep ingested entries in sync with the source.
        """
        if not message_ids:
            return {}
        if not settings.telegram_api_id or not settings.telegram_api_hash:
            return {}

        channel_input = normalize_channel_handle(config.get("channel") or config.get("channel_username"))
        channel_id = config.get("channel_id")
        if not channel_input and not channel_id:
            return {}

        session_name = (config.get("session_name") or "").strip()
        client = await self._get_client(session_name)

        try:
            entity_ref: Any = channel_input if channel_input else channel_id
            entity = await client.get_entity(entity_ref)
        except Exception:
            return {}

        resolved_channel_id = int(getattr(entity, "id", 0)) or None
        resolved_username = getattr(entity, "username", None) or ""
        if resolved_channel_id and resolved_channel_id > 0:
            permalink_channel_id = resolved_channel_id
        else:
            permalink_channel_id = -1 * (resolved_channel_id or 0) if resolved_channel_id else None
        extract_forwards = bool(config.get("extract_forwards", True))

        out: dict[int, ParsedEntry | None] = {}
        try:
            messages = await client.get_messages(entity, ids=list(message_ids))
        except Exception as exc:
            from telethon import errors as tg_errors

            if isinstance(exc, getattr(tg_errors, "FloodWaitError", ())):
                logger.warning("FloodWait while probing telegram messages: %ss", getattr(exc, "seconds", 0))
                return {}
            logger.warning("Failed to probe telegram messages: %s", exc, exc_info=True)
            return {}

        # get_messages preserves order with ids; missing/deleted slots are None.
        for requested_id, message in zip(message_ids, messages or [], strict=False):
            if message is None:
                out[int(requested_id)] = None
                continue
            parsed = self._message_to_entry(
                message,
                channel_id=resolved_channel_id,
                permalink_channel_id=permalink_channel_id,
                channel_username=resolved_username,
                extract_forwards=extract_forwards,
            )
            out[int(requested_id)] = parsed
        return out

    async def list_my_dialogs(self, session_name: str = "") -> list[dict]:
        """Return every broadcast channel the bootstrap account is joined to.

        Used by the discovery flow so operators can see which Telegram channels they
        already participate in but haven't yet wired into IntelFeed as feeds.
        """
        if not settings.telegram_api_id or not settings.telegram_api_hash:
            raise RuntimeError("Telegram is not configured. Set TELEGRAM_API_ID and TELEGRAM_API_HASH.")
        client = await self._get_client(session_name)

        out: list[dict] = []
        try:
            async for dialog in client.iter_dialogs():
                entity = getattr(dialog, "entity", None)
                if entity is None:
                    continue
                # Telegram exposes broadcast=True only on channels (not groups/supergroups)
                if not getattr(entity, "broadcast", False):
                    continue
                username = getattr(entity, "username", None)
                channel_id = int(getattr(entity, "id", 0))
                participants = getattr(entity, "participants_count", None)
                out.append(
                    {
                        "channel_id": channel_id,
                        "username": username,
                        "title": getattr(entity, "title", None) or username or str(channel_id),
                        "subscribers": int(participants) if participants else None,
                        "verified": bool(getattr(entity, "verified", False)),
                        "scam": bool(getattr(entity, "scam", False)),
                        "fake": bool(getattr(entity, "fake", False)),
                        "is_private": username is None,
                    }
                )
        except Exception as exc:
            from telethon import errors as tg_errors

            if isinstance(exc, getattr(tg_errors, "FloodWaitError", ())):
                raise RuntimeError(f"Telegram flood wait {getattr(exc, 'seconds', 0)}s while listing dialogs")
            raise

        return out

    @classmethod
    async def _get_client(cls, session_name: str = ""):
        """Return the per-process, per-session TelegramClient, initializing lazily.

        session_name="" → use the default session at settings.telegram_session_path.
        session_name="osint" → use {dirname(telegram_session_path)}/osint.session.
        """
        if cls._clients_lock is None:
            cls._clients_lock = asyncio.Lock()

        async with cls._clients_lock:
            existing = cls._clients.get(session_name)
            if existing is not None:
                try:
                    if existing.is_connected():
                        return existing
                except Exception:
                    cls._clients.pop(session_name, None)

            from telethon import TelegramClient  # lazy import

            client = TelegramClient(
                cls._load_string_session(session_name),
                settings.telegram_api_id,
                settings.telegram_api_hash,
                flood_sleep_threshold=settings.telegram_flood_sleep_threshold,
            )
            await client.connect()
            if not await client.is_user_authorized():
                hint = (
                    f"Run scripts/telegram/telegram_login.py --session {session_name}."
                    if session_name
                    else "Run scripts/telegram/telegram_login.py."
                )
                raise RuntimeError(f"Telegram session not authorized. {hint}")
            cls._clients[session_name] = client
            return client

    @staticmethod
    def _resolve_session_path(session_name: str) -> str:
        """Compute the on-disk path for a (possibly named) session."""
        if not session_name:
            return settings.telegram_session_path
        # Reject anything outside [A-Za-z0-9_-] so callers can't escape the session dir
        if not all(c.isalnum() or c in "_-" for c in session_name):
            raise RuntimeError(f"Invalid telegram session_name: {session_name!r}")
        base_dir = os.path.dirname(settings.telegram_session_path)
        return os.path.join(base_dir, f"{session_name}.session")

    @classmethod
    def _load_string_session(cls, session_name: str):
        """Read the SQLite session file once per-process and return a StringSession.

        Telethon's default SQLite session writes the entity cache and update state on
        every operation. With multiple processes (api, telegram-listener, four celery
        workers) all opening the same .session file, those writes collide and surface
        as intermittent "database is locked" errors mid-fetch. StringSession holds the
        auth_key in memory only — never writes to disk — so each process can run an
        independent Telethon client without contention.
        """
        from telethon.sessions import SQLiteSession, StringSession

        cached = cls._string_sessions.get(session_name)
        if cached is not None:
            ss = StringSession(cached)
            ss._entities.update(cls._session_entities.get(session_name, ()))
            return ss

        session_path = cls._resolve_session_path(session_name)
        if not os.path.exists(session_path):
            hint = (
                f"Run scripts/telegram/telegram_login.py --session {session_name}."
                if session_name
                else "Run scripts/telegram/telegram_login.py."
            )
            raise RuntimeError(f"Telegram session not found at {session_path}. {hint}")

        # flock a sibling file so concurrent process startups across our containers
        # (api, telegram-listener, celery-worker) don't race the brief SQLite read.
        # POSIX flock on the bind-mounted /data path is honored cross-container because
        # they all share the host kernel and the same inode.
        import fcntl

        lock_path = session_path + ".lock"
        entities: set[tuple] = set()
        with open(lock_path, "w") as lockf:
            fcntl.flock(lockf, fcntl.LOCK_EX)
            try:
                sqlite = SQLiteSession(session_path)
                ss = StringSession()
                ss.set_dc(sqlite.dc_id, sqlite.server_address, sqlite.port)
                ss.auth_key = sqlite.auth_key
                saved = ss.save()
                try:
                    rows = sqlite._cursor().execute("SELECT id, hash, username, phone, name FROM entities").fetchall()
                    entities = {(int(r[0]), int(r[1]), r[2], r[3], r[4]) for r in rows}
                except Exception:
                    logger.warning(
                        "Failed to copy telegram entity cache from session %s",
                        session_name or "(default)",
                        exc_info=True,
                    )
                sqlite.close()
            finally:
                fcntl.flock(lockf, fcntl.LOCK_UN)

        cls._string_sessions[session_name] = saved
        cls._session_entities[session_name] = entities

        ss = StringSession(saved)
        ss._entities.update(entities)
        return ss

    def _message_to_entry(
        self,
        message,
        *,
        channel_id: int | None,
        permalink_channel_id: int | None,
        channel_username: str,
        extract_forwards: bool,
    ) -> ParsedEntry:
        msg_id = int(getattr(message, "id", 0) or 0)
        msg_text = getattr(message, "message", None) or ""
        msg_date = getattr(message, "date", None)

        # Permalink — public channels: t.me/<username>/<msg_id>; private: t.me/c/<id>/<msg_id>
        if channel_username:
            url = f"https://t.me/{channel_username}/{msg_id}"
        elif permalink_channel_id:
            url = f"https://t.me/c/{permalink_channel_id}/{msg_id}"
        else:
            url = None

        forward_meta: dict | None = None
        forward_prefix = ""
        if extract_forwards and getattr(message, "fwd_from", None) is not None:
            fwd = message.fwd_from
            from_name = getattr(fwd, "from_name", None)
            from_id = getattr(fwd, "from_id", None)
            from_id_str = None
            if from_id is not None:
                # PeerChannel/PeerUser/PeerChat — reduce to a simple string for storage
                for attr in ("channel_id", "user_id", "chat_id"):
                    val = getattr(from_id, attr, None)
                    if val is not None:
                        from_id_str = f"{attr}:{val}"
                        break
            forward_meta = {
                "from_name": from_name,
                "from_id": from_id_str,
                "date": getattr(fwd, "date", None).isoformat() if getattr(fwd, "date", None) else None,
            }
            label = from_name or from_id_str or "another channel"
            forward_prefix = f'<p class="tg-forward"><em>Forwarded from {html_mod.escape(str(label))}</em></p>\n'

        content_html = self._render_message_html(message)
        if forward_prefix:
            content_html = forward_prefix + content_html

        # Title — first line of text, truncated; fall back to "Message {id}" for media-only posts
        first_line = msg_text.split("\n", 1)[0].strip() if msg_text else ""
        if first_line:
            title = first_line[:120] + ("…" if len(first_line) > 120 else "")
        else:
            title = f"Message {msg_id}"

        author = f"@{channel_username}" if channel_username else f"Channel {channel_id}" if channel_id else "Telegram"

        # Reactions → list of {emoji, count}
        reactions: list[dict] = []
        rx = getattr(message, "reactions", None)
        if rx and getattr(rx, "results", None):
            for r in rx.results:
                emoji = None
                reaction = getattr(r, "reaction", None)
                if reaction is not None:
                    emoji = getattr(reaction, "emoticon", None) or getattr(reaction, "document_id", None)
                count = getattr(r, "count", 0)
                if emoji is not None:
                    reactions.append({"emoji": str(emoji), "count": int(count)})

        metadata: dict = {
            "source": "telegram",
            "channel_id": channel_id,
            "channel_username": channel_username,
            "message_id": msg_id,
            "views": getattr(message, "views", None),
            "reactions": reactions,
            "reactions_total": sum(int(r.get("count", 0) or 0) for r in reactions),
        }
        edit_date = getattr(message, "edit_date", None)
        if edit_date:
            metadata["edited_at"] = edit_date.isoformat() if hasattr(edit_date, "isoformat") else str(edit_date)
        if forward_meta is not None:
            metadata["forwarded_from"] = forward_meta
        grouped = getattr(message, "grouped_id", None)
        if grouped:
            metadata["telegram_grouped_id"] = int(grouped)

        return ParsedEntry(
            guid=f"telegram:{channel_id}:{msg_id}",
            url=url,
            title=title,
            author=author,
            content_html=content_html,
            published_at=msg_date,
            metadata=metadata,
        )

    @staticmethod
    def _render_message_html(message) -> str:
        """Convert message text + entities to sanitized-friendly HTML.

        Telethon exposes per-character formatting via `entities` (MessageEntityBold,
        MessageEntityItalic, MessageEntityCode, MessageEntityPre, MessageEntityTextUrl,
        MessageEntityUrl, MessageEntityMention, MessageEntityMentionName, etc.).
        We build HTML by walking the text and wrapping affected ranges.
        """
        text = getattr(message, "message", None) or ""
        entities = getattr(message, "entities", None) or []
        if not text:
            return ""
        if not entities:
            return f"<p>{html_mod.escape(text).replace(chr(10), '<br>')}</p>"

        # Build per-character open/close tag lists.
        opens: list[list[str]] = [[] for _ in range(len(text) + 1)]
        closes: list[list[str]] = [[] for _ in range(len(text) + 1)]

        for ent in entities:
            etype = type(ent).__name__
            offset = int(getattr(ent, "offset", 0) or 0)
            length = int(getattr(ent, "length", 0) or 0)
            if length <= 0 or offset < 0 or offset + length > len(text):
                continue

            open_tag, close_tag = TelegramAdapter._entity_tags(etype, ent, text, offset, length)
            if not open_tag:
                continue
            opens[offset].append(open_tag)
            closes[offset + length].insert(0, close_tag)

        out: list[str] = []
        for i, ch in enumerate(text):
            for tag in closes[i]:
                out.append(tag)
            for tag in opens[i]:
                out.append(tag)
            if ch == "\n":
                out.append("<br>")
            else:
                out.append(html_mod.escape(ch))
        for tag in closes[len(text)]:
            out.append(tag)
        return f"<p>{''.join(out)}</p>"

    @staticmethod
    def _entity_tags(etype: str, ent, text: str, offset: int, length: int) -> tuple[str, str]:
        substr = text[offset : offset + length]
        if etype == "MessageEntityBold":
            return "<strong>", "</strong>"
        if etype == "MessageEntityItalic":
            return "<em>", "</em>"
        if etype == "MessageEntityUnderline":
            return "<u>", "</u>"
        if etype == "MessageEntityStrike":
            return "<s>", "</s>"
        if etype == "MessageEntitySpoiler":
            return '<span class="tg-spoiler">', "</span>"
        if etype == "MessageEntityCode":
            return "<code>", "</code>"
        if etype == "MessageEntityPre":
            return "<pre><code>", "</code></pre>"
        if etype == "MessageEntityBlockquote":
            return "<blockquote>", "</blockquote>"
        if etype == "MessageEntityUrl":
            href = html_mod.escape(substr, quote=True)
            return f'<a href="{href}" rel="noopener noreferrer">', "</a>"
        if etype == "MessageEntityTextUrl":
            href = html_mod.escape(getattr(ent, "url", "") or "", quote=True)
            return f'<a href="{href}" rel="noopener noreferrer">', "</a>"
        if etype == "MessageEntityMention":
            handle = substr.lstrip("@")
            href = html_mod.escape(f"https://t.me/{handle}", quote=True)
            return f'<a href="{href}" rel="noopener noreferrer">', "</a>"
        if etype == "MessageEntityMentionName":
            user_id = getattr(ent, "user_id", None)
            if user_id:
                href = html_mod.escape(f"tg://user?id={user_id}", quote=True)
                return f'<a href="{href}">', "</a>"
            return "", ""
        if etype == "MessageEntityHashtag":
            href = html_mod.escape(f"https://t.me/s/{substr.lstrip('#')}", quote=True)
            return f'<a href="{href}" rel="noopener noreferrer">', "</a>"
        if etype == "MessageEntityCashtag":
            return "<span>", "</span>"
        if etype == "MessageEntityEmail":
            href = html_mod.escape(f"mailto:{substr}", quote=True)
            return f'<a href="{href}">', "</a>"
        if etype in {"MessageEntityBotCommand", "MessageEntityPhone"}:
            return "<span>", "</span>"
        return "", ""

    async def _build_media(
        self,
        client,
        message,
        *,
        channel_id: int | None,
        media_types: set[str],
        max_size_mb: int,
    ) -> ParsedMedia | None:
        """Download media to disk and return a ParsedMedia pointing at our serving route."""
        media = getattr(message, "media", None)
        if media is None:
            return None

        # Categorize.
        kind, mime_type, ext = self._classify_media(message)
        if kind is None:
            return None
        if kind not in media_types:
            return None

        file_size = getattr(getattr(message, "file", None), "size", None)
        if file_size and file_size > max_size_mb * 1024 * 1024:
            logger.info(
                "Skipping oversized telegram media (%s bytes > %s MB cap) on message %s",
                file_size,
                max_size_mb,
                getattr(message, "id", "?"),
            )
            return None

        if not channel_id:
            return None

        msg_id = int(getattr(message, "id", 0) or 0)
        base_dir = os.path.join(settings.telegram_media_dir, str(channel_id))
        os.makedirs(base_dir, exist_ok=True)
        filename = f"{msg_id}{ext}"
        target = os.path.join(base_dir, filename)

        if not os.path.exists(target):
            try:
                await client.download_media(message, file=target)
            except Exception:
                logger.warning("Failed to download telegram media for message %s", msg_id, exc_info=True)
                return None

        thumbnail_url: str | None = None
        if kind == "video":
            thumb_target = os.path.join(base_dir, f"{msg_id}.thumb.jpg")
            if not os.path.exists(thumb_target):
                try:
                    await client.download_media(message, file=thumb_target, thumb=-1)
                except Exception:
                    logger.debug("No video thumbnail available for message %s", msg_id)
            if os.path.exists(thumb_target):
                thumbnail_url = f"/api/telegram-media/{channel_id}/{msg_id}.thumb.jpg"

        duration_seconds = None
        file_obj = getattr(message, "file", None)
        if file_obj is not None:
            duration_seconds = getattr(file_obj, "duration", None)

        url = f"/api/telegram-media/{channel_id}/{filename}"

        meta: dict = {}
        grouped = getattr(message, "grouped_id", None)
        if grouped:
            meta["telegram_grouped_id"] = int(grouped)
        # Voice notes: voice=True attribute on document
        if file_obj is not None and getattr(file_obj, "name", None):
            meta["original_filename"] = file_obj.name

        return ParsedMedia(
            media_type=kind,
            url=url,
            mime_type=mime_type,
            file_size=int(file_size) if file_size else None,
            duration_seconds=int(duration_seconds) if duration_seconds else None,
            thumbnail_url=thumbnail_url,
            metadata=meta,
        )

    @staticmethod
    def _classify_media(message) -> tuple[str | None, str | None, str]:
        """Return (media_type, mime_type, extension) — or (None, None, '') if unsupported."""
        media = getattr(message, "media", None)
        media_cls = type(media).__name__ if media else ""
        file_obj = getattr(message, "file", None)
        mime = getattr(file_obj, "mime_type", None) if file_obj else None

        if media_cls == "MessageMediaPhoto":
            return "photo", mime or "image/jpeg", ".jpg"

        if media_cls == "MessageMediaDocument":
            ext = ""
            if file_obj is not None:
                ext = getattr(file_obj, "ext", "") or ""
                if not ext and getattr(file_obj, "name", None):
                    _, ext = os.path.splitext(file_obj.name)
            ext = ext.lower() or ".bin"
            if mime:
                if mime.startswith(_MEDIA_VIDEO_MIMES_PREFIX):
                    return "video", mime, ext
                if mime.startswith(_MEDIA_AUDIO_MIMES_PREFIX):
                    return "audio", mime, ext
                if mime.startswith(_MEDIA_IMAGE_MIMES_PREFIX):
                    return "photo", mime, ext
            return "document", mime, ext

        # WebPage previews and other media types — skip
        return None, None, ""
