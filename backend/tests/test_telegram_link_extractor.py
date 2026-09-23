"""Tests for the telegram link extractor service.

Pure-function unit tests, no DB or network. Verifies URL classification, dedup,
and rejection of Telegram service paths that aren't channel handles.
"""

from app.services.telegram_link_extractor import extract_links, unique_handles


def test_plain_channel_link():
    links = extract_links("Check out https://t.me/breachintelligence for leaks.")
    assert len(links) == 1
    assert links[0].handle == "breachintelligence"
    assert links[0].link_type == "channel"
    assert links[0].url == "https://t.me/breachintelligence"


def test_message_link_extracts_message_id():
    links = extract_links("https://t.me/lockbit/12345")
    assert links[0].link_type == "message"
    assert links[0].handle == "lockbit"
    assert links[0].message_id == 12345


def test_invite_link_plus_form():
    links = extract_links("Join via https://t.me/+abcdefghij1234567")
    assert len(links) == 1
    assert links[0].link_type == "invite"
    assert links[0].handle == "invite:abcdefghij1234567"
    assert links[0].invite_hash == "abcdefghij1234567"


def test_invite_link_joinchat_form():
    links = extract_links("https://t.me/joinchat/abcdefghij1234567")
    assert len(links) == 1
    assert links[0].link_type == "invite"


def test_telegram_me_alias():
    links = extract_links("https://telegram.me/somechannel")
    assert links[0].handle == "somechannel"


def test_web_preview_s_prefix():
    links = extract_links("https://t.me/s/somechannel/42")
    assert links[0].handle == "somechannel"
    assert links[0].link_type == "message"
    assert links[0].message_id == 42


def test_tg_deep_link():
    links = extract_links("Open in app: tg://resolve?domain=akira_leaks")
    assert links[0].handle == "akira_leaks"
    assert links[0].link_type == "deep_link"


def test_reserved_paths_rejected():
    body = """
    https://t.me/share/url?url=foo
    https://t.me/iv?url=bar
    https://t.me/proxy?server=x
    https://t.me/joinchat/   (no hash)
    https://t.me/setlanguage/en
    """
    links = extract_links(body)
    assert links == []


def test_dedup_by_canonical_url():
    body = "https://t.me/lockbit and again https://t.me/lockbit/  in one body"
    links = extract_links(body)
    handles = [link.handle for link in links]
    # 'lockbit' shouldn't appear twice
    assert handles.count("lockbit") == 1


def test_unique_handles_prefers_message_over_channel():
    body = "https://t.me/leakgroup and https://t.me/leakgroup/100"
    links = extract_links(body)
    reduced = unique_handles(links)
    assert reduced["leakgroup"].link_type == "message"


def test_html_href_extraction():
    body = '<a href="https://t.me/breachgroup">Telegram</a> mentions <a href="https://t.me/+xyzabc1234567890">here</a>'
    links = extract_links(body)
    handles = sorted({link.handle for link in links})
    assert "breachgroup" in handles
    assert "invite:xyzabc1234567890" in handles


def test_handle_too_short_rejected():
    # Telegram requires 5+ char usernames; we accept 3+ but reject reserved short paths
    links = extract_links("https://t.me/ab")
    assert links == []


def test_url_in_markdown_paren_doesnt_grab_closing_paren():
    body = "[link](https://t.me/somechannel)"
    links = extract_links(body)
    assert len(links) == 1
    assert links[0].handle == "somechannel"


def test_punctuation_after_url_stripped():
    body = "see https://t.me/somechannel."
    links = extract_links(body)
    assert links[0].handle == "somechannel"
