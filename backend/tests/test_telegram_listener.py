"""The Telegram listener runs outside Celery, so it checks the engine switch itself."""

from app.services import engine_switch
from app.workers import feed_tasks, telegram_listener


async def test_a_stopped_engine_skips_the_dispatch(monkeypatch):
    sent = []
    monkeypatch.setattr(feed_tasks.fetch_feed, "delay", lambda feed_id: sent.append(feed_id))
    state = {"stopped": True}

    async def is_stopped_async(*, fresh=False):
        return state["stopped"]

    monkeypatch.setattr(engine_switch, "is_stopped_async", is_stopped_async)
    dispatcher = telegram_listener._ChannelDispatcher()

    await dispatcher._dispatch("feed-1")
    assert sent == [], "the feed's own poll picks the messages up after the start"

    state["stopped"] = False
    await dispatcher._dispatch("feed-1")
    assert sent == ["feed-1"]
