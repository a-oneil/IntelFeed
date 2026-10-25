"""Relevance filter: word-start keyword matching and the one shared threshold."""

import contextlib
import uuid
from datetime import UTC, datetime

import pytest

from app.intelligence.relevance_filter import (
    DEFAULT_RELEVANCE_THRESHOLD,
    get_relevance_threshold,
    score_relevance,
)

# Off-topic text whose words used to contain a keyword: "laptop" ⊃ apt,
# "percent" ⊃ rce, "https" ⊃ ttp, "pocket" ⊃ poc, "kudos" ⊃ dos.
OFF_TOPIC = [
    ("Best laptop deals this week", None, None),
    ("Apple announces new MacBook laptop", None, None),
    ("Quarterly results", "Company earnings grew 12 percent on strong commerce demand", None),
    ("Open source resource roundup", "Read more at https://example.com/chapter-3", None),
    ("Kudos to the team", "A pocket guide to adapting your workforce", None),
    ("Siemens reports quarterly results", None, None),
]

# Real security headlines (and one summary) that must keep passing.
SECURITY = [
    ("APT29 targets European diplomats with new lure", None, None),
    ("Attackers exploited a flaw in Ivanti Connect Secure", None, None),
    ("Microsoft fixes actively exploited zero-days in Patch Tuesday", None, None),
    ("New DDoS botnet hijacks unpatched routers", None, None),
    ("Cyberattack disrupts hospital systems across the region", None, None),
    ("Hackers breached the network of a major telecom", None, None),
    ("IOCs for the latest spearphishing campaign", None, None),
    ("Infostealers sold on Telegram", None, None),
    ("Weekly roundup", "Researchers detail a ransomware operation's lateral movement", None),
    ("Fortinet advisory", "FortiOS CVE-2026-1234 allows remote code execution", None),
    # Headlines that only passed by accident under substring matching
    # ("hacked" never hit a keyword; https/source/force did).
    ("Hackers drain $320M in Bitcoin from Liquid Network", None, None),
    ("US officials backpedal on claims that government agencies were hacked by Chinese", None, None),
    ("Malicious Twitch Browser Extension Leaks OAuth Tokens From Nearly 31,000 Users", None, None),
    ("Hiding Prompt Injection in Legal Filing", None, None),
    ("Cookie Hijacking: What Secure, HttpOnly, and SameSite Actually Stop", None, None),
    ("Multiple vulnerabilities in Ivanti EPMM", None, None),
]


@pytest.mark.parametrize(("title", "summary", "content"), OFF_TOPIC)
def test_keywords_inside_other_words_do_not_count(title, summary, content):
    assert score_relevance(title, summary, content) < DEFAULT_RELEVANCE_THRESHOLD


@pytest.mark.parametrize(("title", "summary", "content"), SECURITY)
def test_real_security_text_still_passes(title, summary, content):
    assert score_relevance(title, summary, content) >= DEFAULT_RELEVANCE_THRESHOLD


def test_short_keywords_allow_plural_and_digits_only():
    assert score_relevance("APT41 and other APTs", None, None) > 0
    assert score_relevance("He aptly described it", None, None) == 0.0
    assert score_relevance("A DoS in the parser", None, None) > 0
    assert score_relevance("The right dose", None, None) == 0.0


# --- One threshold for both gates -------------------------------------------

MIDDLING_TITLE = "Phishing wave hits retailers"  # one incident keyword + title bonus


@pytest.mark.asyncio
async def test_threshold_comes_from_the_setting(db_session, monkeypatch):
    from app.config import settings as env_settings

    monkeypatch.setattr(env_settings, "ai_analysis_relevance_threshold", 0.7)
    assert await get_relevance_threshold(db_session) == 0.7


async def _selective_entry(db_session):
    from app.models.entry import Entry
    from app.models.feed import Feed

    feed = Feed(
        title="Selective",
        url=f"https://sel-{uuid.uuid4().hex}.example.com/rss",
        feed_type="rss",
        intel_extraction_mode="selective",
    )
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(
        feed_id=feed.id,
        title=MIDDLING_TITLE,
        guid=uuid.uuid4().hex,
        content_text="Shoppers were sent fake delivery notices.",
        published_at=datetime.now(UTC),
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


@pytest.mark.parametrize(("threshold", "gated"), [(0.15, False), (0.9, True)])
@pytest.mark.asyncio
async def test_selective_autolink_and_junk_gate_share_the_threshold(db_session, monkeypatch, threshold, gated):
    from app.config import settings as env_settings
    from app.intelligence import autolinker
    from app.models.ai_task import AITask
    from app.services.entry_analysis import enqueue_entry_analysis
    from app.workers import intel_feed_tasks

    score = score_relevance(MIDDLING_TITLE, None, "Shoppers were sent fake delivery notices.")
    assert 0.15 <= score < 0.9  # the entry sits between the two thresholds

    monkeypatch.setattr(env_settings, "ai_analysis_relevance_threshold", threshold)
    monkeypatch.setattr(env_settings, "ai_one_pass_enabled", True)
    db_session.add(
        AITask(
            name="entry_analysis",
            display_name="One-Pass Entry Analysis",
            category="extraction",
            default_prompt_template="{{ entry.title }}",
            is_system=True,
        )
    )
    entry = await _selective_entry(db_session)

    @contextlib.asynccontextmanager
    async def session_on():
        yield db_session

    calls = []

    async def fake_autolink(**kwargs):
        calls.append(kwargs["entry_id"])
        return []

    monkeypatch.setattr(intel_feed_tasks, "_get_worker_session", session_on)
    monkeypatch.setattr(autolinker, "autolink_entry", fake_autolink)

    await intel_feed_tasks._autolink_entry(str(entry.id))
    status = await enqueue_entry_analysis(db_session, entry.id)

    assert (calls == []) is gated
    assert (status == "skipped_junk") is gated
