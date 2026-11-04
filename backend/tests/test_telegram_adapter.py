"""Tests for the Telegram channel adapter.

We mock the Telethon TelegramClient so no real Telegram traffic occurs.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.adapters.telegram import TelegramAdapter


def _make_message(
    *,
    msg_id: int,
    text: str = "",
    date: datetime | None = None,
    media=None,
    entities: list | None = None,
    fwd_from=None,
    grouped_id=None,
    reactions=None,
    views: int | None = None,
    file=None,
    edit_date=None,
):
    return SimpleNamespace(
        id=msg_id,
        message=text,
        date=date or datetime.now(UTC),
        media=media,
        entities=entities or [],
        fwd_from=fwd_from,
        grouped_id=grouped_id,
        reactions=reactions,
        views=views,
        file=file,
        edit_date=edit_date,
    )


def _async_iter(items):
    async def gen():
        for item in items:
            yield item

    return gen()


def _setup_client(monkeypatch, *, messages, entity=None):
    if entity is None:
        entity = SimpleNamespace(id=-1001234567890, username="testchannel", title="Test", about=None)
    client = MagicMock()
    client.is_connected = MagicMock(return_value=True)
    client.is_user_authorized = AsyncMock(return_value=True)
    client.connect = AsyncMock()
    client.get_entity = AsyncMock(return_value=entity)
    client.iter_messages = MagicMock(side_effect=lambda *a, **kw: _async_iter(messages))
    client.download_media = AsyncMock()
    monkeypatch.setattr(TelegramAdapter, "_get_client", AsyncMock(return_value=client))
    # Ensure per-session client cache is reset between tests
    monkeypatch.setattr(TelegramAdapter, "_clients", {}, raising=False)
    return client, entity


@pytest.mark.asyncio
async def test_first_fetch_returns_recent_messages(monkeypatch):
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_id", 12345, raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_hash", "abc", raising=False)
    now = datetime.now(UTC)
    messages = [
        _make_message(msg_id=100, text="First post", date=now - timedelta(days=1)),
        _make_message(msg_id=101, text="Second post", date=now - timedelta(hours=1)),
    ]
    _setup_client(monkeypatch, messages=messages)

    adapter = TelegramAdapter()
    config = {"channel": "@testchannel", "max_messages_per_fetch": 50, "include_media": False}
    meta, entries = await adapter.fetch_entries(config, since=None)

    assert len(entries) == 2
    assert entries[0].title == "First post"
    assert entries[0].guid == "telegram:-1001234567890:100"
    assert entries[0].url == "https://t.me/testchannel/100"
    assert entries[0].author == "@testchannel"
    assert entries[0].metadata["message_id"] == 100
    # Watermark advanced
    assert meta.extra["last_seen_id"] == 101
    assert meta.extra["channel_username"] == "testchannel"
    assert meta.extra["channel_id"] == -1001234567890


@pytest.mark.asyncio
async def test_age_filter_skips_old_messages(monkeypatch):
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_id", 1, raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_hash", "x", raising=False)
    now = datetime.now(UTC)
    messages = [
        _make_message(msg_id=10, text="Ancient", date=now - timedelta(days=120)),
        _make_message(msg_id=11, text="Recent", date=now - timedelta(days=2)),
    ]
    _setup_client(monkeypatch, messages=messages)

    adapter = TelegramAdapter()
    config = {"channel": "@x", "max_message_age_days": 30, "include_media": False}
    _, entries = await adapter.fetch_entries(config, since=None)

    assert [e.title for e in entries] == ["Recent"]


@pytest.mark.asyncio
async def test_media_only_message_uses_id_title(monkeypatch):
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_id", 1, raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_hash", "x", raising=False)
    msg = _make_message(msg_id=42, text="")
    _setup_client(monkeypatch, messages=[msg])

    adapter = TelegramAdapter()
    _, entries = await adapter.fetch_entries({"channel": "@x", "include_media": False}, since=None)

    assert entries[0].title == "Message 42"


class MessageEntityBold:
    def __init__(self, offset, length):
        self.offset = offset
        self.length = length


class MessageEntityTextUrl:
    def __init__(self, offset, length, url):
        self.offset = offset
        self.length = length
        self.url = url


class MessageMediaPhoto:
    pass


class MessageMediaDocument:
    pass


@pytest.mark.asyncio
async def test_entity_to_html_bold_link(monkeypatch):
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_id", 1, raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_hash", "x", raising=False)

    text = "Bold link"
    bold = MessageEntityBold(offset=0, length=4)
    link = MessageEntityTextUrl(offset=5, length=4, url="https://example.com/")

    msg = _make_message(msg_id=1, text=text, entities=[bold, link])
    _setup_client(monkeypatch, messages=[msg])

    adapter = TelegramAdapter()
    _, entries = await adapter.fetch_entries({"channel": "@x", "include_media": False}, since=None)

    html = entries[0].content_html or ""
    assert "<strong>Bold</strong>" in html
    assert 'href="https://example.com/"' in html


@pytest.mark.asyncio
async def test_forward_attribution_in_html_and_metadata(monkeypatch):
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_id", 1, raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_hash", "x", raising=False)
    fwd = SimpleNamespace(from_name="OriginalChannel", from_id=None, date=datetime(2026, 4, 1, tzinfo=UTC))
    msg = _make_message(msg_id=5, text="forwarded text", fwd_from=fwd)
    _setup_client(monkeypatch, messages=[msg])

    adapter = TelegramAdapter()
    _, entries = await adapter.fetch_entries(
        {"channel": "@x", "include_media": False, "extract_forwards": True}, since=None
    )

    assert "Forwarded from OriginalChannel" in (entries[0].content_html or "")
    assert entries[0].metadata["forwarded_from"]["from_name"] == "OriginalChannel"


@pytest.mark.asyncio
async def test_oversized_media_skipped(monkeypatch):
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_id", 1, raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_hash", "x", raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_max_media_size_mb", 1, raising=False)

    media = MessageMediaDocument()
    file_obj = SimpleNamespace(size=10 * 1024 * 1024, mime_type="video/mp4", duration=30, ext=".mp4", name="big.mp4")
    msg = _make_message(msg_id=7, text="big video", media=media, file=file_obj)
    client, _ = _setup_client(monkeypatch, messages=[msg])

    adapter = TelegramAdapter()
    _, entries = await adapter.fetch_entries({"channel": "@x", "include_media": True}, since=None)

    assert entries[0].media is None
    client.download_media.assert_not_called()


@pytest.mark.asyncio
async def test_get_feed_meta_static():
    adapter = TelegramAdapter()
    meta = adapter.get_feed_meta({"channel": "@somechan"})
    assert "somechan" in (meta.title or "")


@pytest.mark.asyncio
async def test_incremental_fetch_uses_last_seen_id(monkeypatch):
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_id", 1, raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_hash", "x", raising=False)

    msg = _make_message(msg_id=205, text="newer")
    client, _ = _setup_client(monkeypatch, messages=[msg])

    adapter = TelegramAdapter()
    config = {"channel": "@x", "include_media": False, "last_seen_id": 200}
    meta, entries = await adapter.fetch_entries(config, since=None)

    # client.iter_messages was called with min_id=200 (last_seen_id)
    _args, kwargs = client.iter_messages.call_args
    assert kwargs.get("min_id") == 200
    assert len(entries) == 1
    assert meta.extra["last_seen_id"] == 205


@pytest.mark.asyncio
async def test_channel_resolution_writes_back(monkeypatch):
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_id", 1, raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_hash", "x", raising=False)

    entity = SimpleNamespace(id=-1009999, username="resolved", title="Resolved", about="desc")
    _setup_client(monkeypatch, messages=[], entity=entity)
    adapter = TelegramAdapter()
    meta, _ = await adapter.fetch_entries({"channel": "@resolved", "include_media": False}, since=None)

    assert meta.extra["channel_id"] == -1009999
    assert meta.extra["channel_username"] == "resolved"


@pytest.mark.asyncio
async def test_media_photo_creates_parsed_media(monkeypatch, tmp_path):
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_id", 1, raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_hash", "x", raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_max_media_size_mb", 25, raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_media_dir", str(tmp_path), raising=False)

    media = MessageMediaPhoto()
    file_obj = SimpleNamespace(size=1024, mime_type="image/jpeg", duration=None, ext=".jpg", name=None)
    msg = _make_message(msg_id=77, text="photo post", media=media, file=file_obj)
    client, _ = _setup_client(monkeypatch, messages=[msg])

    async def _fake_download(_msg, file=None, thumb=None):
        with open(file, "wb") as fh:
            fh.write(b"\xff\xd8\xff fake")

    client.download_media = AsyncMock(side_effect=_fake_download)

    adapter = TelegramAdapter()
    _, entries = await adapter.fetch_entries({"channel": "@x", "include_media": True}, since=None)

    assert entries[0].media is not None
    assert entries[0].media.media_type == "photo"
    assert entries[0].media.url == "/api/telegram-media/-1001234567890/77.jpg"
    assert entries[0].media.mime_type == "image/jpeg"
    client.download_media.assert_called()


@pytest.mark.asyncio
async def test_flood_wait_above_threshold_does_not_advance_watermark(monkeypatch):
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_id", 1, raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_hash", "x", raising=False)

    from telethon import errors as tg_errors

    class _FloodIter:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise tg_errors.FloodWaitError(request=None)

    flood = tg_errors.FloodWaitError(request=None)
    flood.seconds = 600

    client = MagicMock()
    client.is_connected = MagicMock(return_value=True)
    client.is_user_authorized = AsyncMock(return_value=True)
    client.connect = AsyncMock()
    entity = SimpleNamespace(id=-1001234567890, username="x", title="X", about=None)
    client.get_entity = AsyncMock(return_value=entity)

    async def _raise_flood(*_args, **_kwargs):
        yield None  # type: ignore[unreachable]
        raise flood

    def _flood_iter(*_args, **_kwargs):
        async def gen():
            raise flood
            yield  # pragma: no cover

        return gen()

    client.iter_messages = MagicMock(side_effect=_flood_iter)
    monkeypatch.setattr(TelegramAdapter, "_get_client", AsyncMock(return_value=client))
    monkeypatch.setattr(TelegramAdapter, "_client", None, raising=False)

    adapter = TelegramAdapter()
    config = {"channel": "@x", "include_media": False, "last_seen_id": 100}
    meta, entries = await adapter.fetch_entries(config, since=None)

    assert entries == []
    # Watermark NOT advanced — must equal incoming last_seen_id
    assert meta.extra["last_seen_id"] == 100
    assert meta.extra.get("telegram_flood_wait_seconds") == 600


@pytest.mark.asyncio
async def test_channel_private_error_raises(monkeypatch):
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_id", 1, raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_hash", "x", raising=False)

    from telethon import errors as tg_errors

    client = MagicMock()
    client.is_connected = MagicMock(return_value=True)
    client.is_user_authorized = AsyncMock(return_value=True)
    client.connect = AsyncMock()
    client.get_entity = AsyncMock(side_effect=tg_errors.ChannelPrivateError(request=None))
    monkeypatch.setattr(TelegramAdapter, "_get_client", AsyncMock(return_value=client))
    monkeypatch.setattr(TelegramAdapter, "_client", None, raising=False)

    adapter = TelegramAdapter()
    with pytest.raises(RuntimeError, match="channel unavailable"):
        await adapter.fetch_entries({"channel": "@x", "include_media": False}, since=None)


@pytest.mark.asyncio
async def test_auth_key_unregistered_drops_client_and_signals_relogin(monkeypatch):
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_id", 1, raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_hash", "x", raising=False)

    from telethon import errors as tg_errors

    client = MagicMock()
    client.is_connected = MagicMock(return_value=True)
    client.is_user_authorized = AsyncMock(return_value=True)
    client.connect = AsyncMock()
    client.get_entity = AsyncMock(side_effect=tg_errors.AuthKeyUnregisteredError(request=None))
    monkeypatch.setattr(TelegramAdapter, "_get_client", AsyncMock(return_value=client))
    # Pre-populate the client cache so we can assert it gets dropped
    monkeypatch.setattr(TelegramAdapter, "_clients", {"": client}, raising=False)

    adapter = TelegramAdapter()
    with pytest.raises(RuntimeError, match="session revoked"):
        await adapter.fetch_entries({"channel": "@x", "include_media": False}, since=None)
    assert "" not in TelegramAdapter._clients


@pytest.mark.asyncio
async def test_session_path_resolution(monkeypatch):
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_session_path", "/data/telegram.session", raising=False)
    assert TelegramAdapter._resolve_session_path("") == "/data/telegram.session"
    assert TelegramAdapter._resolve_session_path("osint") == "/data/osint.session"
    assert TelegramAdapter._resolve_session_path("dark-side") == "/data/dark-side.session"
    with pytest.raises(RuntimeError, match="Invalid telegram session_name"):
        TelegramAdapter._resolve_session_path("../etc/passwd")


@pytest.mark.asyncio
async def test_unconfigured_raises(monkeypatch):
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_id", 0, raising=False)
    monkeypatch.setattr("app.adapters.telegram.settings.telegram_api_hash", "", raising=False)
    adapter = TelegramAdapter()
    with pytest.raises(RuntimeError, match="not configured"):
        await adapter.fetch_entries({"channel": "@x"}, since=None)


@pytest.mark.parametrize(("window", "probed"), [(0, False), (-1, False), (None, True), ("", True), (5, True)])
async def test_edit_probe_window_zero_turns_the_probe_off(window, probed):
    from app.workers.feed_tasks import _probe_telegram_edits_and_deletes

    db = MagicMock()
    db.execute = AsyncMock(side_effect=RuntimeError("probed"))
    feed = SimpleNamespace(id="f1", adapter_config={"edit_probe_window": window})
    if probed:
        with pytest.raises(RuntimeError, match="probed"):
            await _probe_telegram_edits_and_deletes(db, feed, MagicMock(), {})
    else:
        await _probe_telegram_edits_and_deletes(db, feed, MagicMock(), {})
        db.execute.assert_not_called()
