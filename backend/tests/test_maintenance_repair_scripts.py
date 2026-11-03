"""Pure helpers of the one-off repair scripts in scripts/maintenance/ (no database)."""

import importlib.util
import uuid
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts" / "maintenance"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"maint_{name}", SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def sweep():
    return _load("sweep_cooccurrence_edges")


@pytest.fixture(scope="module")
def audit():
    return _load("audit_auto_removals")


@pytest.fixture(scope="module")
def recount():
    return _load("recount_article_counts")


A = ("threat_actor", uuid.uuid4())
M = ("malware", uuid.uuid4())


def _refs(*items):
    return [(k[0], k[1], paras) for k, paras in items]


# --------------------------------------------------------------------------- sweep


def test_same_body_paragraph_qualifies(sweep):
    profile = sweep.entry_profile(_refs((A, [3]), (M, [3, 5])), set())
    assert sweep.pair_qualifies(profile, A, M)


def test_different_paragraphs_do_not_qualify(sweep):
    profile = sweep.entry_profile(_refs((A, [3]), (M, [4])), set())
    assert not sweep.pair_qualifies(profile, A, M)


def test_link_without_position_does_not_qualify(sweep):
    profile = sweep.entry_profile(_refs((A, None), (M, [3])), set())
    assert not sweep.pair_qualifies(profile, A, M)


def test_boilerplate_paragraph_does_not_qualify(sweep):
    profile = sweep.entry_profile(_refs((A, [3]), (M, [3])), {3})
    assert not sweep.pair_qualifies(profile, A, M)


def test_crowded_paragraph_does_not_qualify(sweep):
    others = [((f"t{i}", uuid.uuid4()), [3]) for i in range(sweep._CROWDED_PARAGRAPH_ENTITIES - 2)]
    profile = sweep.entry_profile(_refs((A, [3]), (M, [3]), *others), set())
    assert not sweep.pair_qualifies(profile, A, M)
    # One fewer entity and it is a statement again.
    profile = sweep.entry_profile(_refs((A, [3]), (M, [3]), *others[:-1]), set())
    assert sweep.pair_qualifies(profile, A, M)


def test_dense_article_is_skipped(sweep):
    many = [((f"t{i}", uuid.uuid4()), [9]) for i in range(sweep._MAX_ENTITIES_PER_ENTRY)]
    assert sweep.entry_profile(_refs((A, [3]), (M, [3]), *many), set()) is None


def test_boilerplate_indices_uses_builder_regex(sweep):
    idx = sweep.boilerplate_indices("Title", "", "APT28 uses X-Agent.\n\nRelated: APT28 and X-Agent news")
    assert idx == {2}


def test_judge_edge_drops_and_rejects(sweep):
    e1, e2, e3 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    remaining, dropped, reject = sweep.judge_edge([e1, e2], [], lambda e: e == e1)
    assert (remaining, dropped, reject) == ([e1], [e2], False)
    remaining, dropped, reject = sweep.judge_edge([e1, e2], [], lambda e: False)
    assert reject and dropped == [e1, e2]
    # Reviewer-kept evidence always stays.
    remaining, dropped, reject = sweep.judge_edge([e3], [e3], lambda e: False)
    assert remaining == [e3] and not reject


# --------------------------------------------------------------------------- audit


def test_html_context_prefers_table(audit):
    h = "d41d8cd98f00b204e9800998ecf8427e"
    assert audit.html_context(f"<p>x</p><table><tr><td>{h}</td></tr></table>", h) == "table"
    assert audit.html_context(f"<ul><li>{h.upper()}</li></ul>", h) == "list"
    assert audit.html_context(f"<pre>{h}</pre>", h) == "pre"
    assert audit.html_context(f"<p>the hash {h}</p>", h) == "text"
    assert audit.html_context("<p>nothing</p>", h) is None
    assert audit.html_context(None, h, text=f"plain {h}") == "text"


def test_technique_pattern(audit):
    pat = audit.technique_pattern("T1059")
    assert pat.search("tags: attack.t1059.001")
    assert pat.search("T1059 Command and Scripting")
    assert not pat.search("T10590")
    assert not audit.technique_pattern("T1059.001").search("T1059.0012")


def test_classify_patterns(audit):
    assert audit.classify("sector", "not the victims")[0][0] == "sector"
    pats, detail = audit.classify("tool", "used by defenders", tool_type="defensive")
    assert pats == ["legit_tool"] and detail == "tool_type=defensive"
    assert audit.classify("tool", "name collision with a word", tool_type="c2_framework")[0] == []
    pats, _ = audit.classify("ttp", "metadata only", technique_id="T1059", rule_text="attack.t1059")
    assert "ttp_rule_mapping" in pats and "bystander_reason" in pats
    pats, detail = audit.classify(
        "ttp", "x", technique_id="T1566", entry_html="<table><tr><td>T1566.001</td></tr></table>"
    )
    assert pats == ["ttp_attack_table"] and detail == "T1566 in table"
    h = "a" * 64
    pats, _ = audit.classify("observable", "system file", ioc_kind="sha256", ioc_value=h, entry_html=f"<pre>{h}</pre>")
    assert "ioc_hash" in pats
    pats, _ = audit.classify("observable", "x", ioc_kind="sha256", ioc_value=h, entry_html=f"<p>{h}</p>")
    assert pats == ["ioc_hash_text"]
    assert audit.classify("observable", "x", ioc_kind="domain", ioc_value="evil.com")[0] == []
    assert audit.classify("vendor", "this is the victim, not an adversary")[0] == ["bystander_reason"]


def test_prefill_restore(audit):
    assert audit.prefill_restore(["sector"]) == "y"
    assert audit.prefill_restore(["ioc_hash_text"]) == ""
    assert audit.prefill_restore(["bystander_reason"]) == ""


# --------------------------------------------------------------------------- recount


def test_countable_types(recount):
    types = set(recount.countable_types())
    assert {"threat_actor", "malware", "tool", "ttp", "sector", "vendor", "product", "country"} <= types
    assert "observable" not in types  # owned by reconcile_observable_counters
    assert "cve" not in types  # no stored count


def test_keeps_probable(sweep):
    assert sweep.keeps_probable(3, 3, 2, True, True)
    assert not sweep.keeps_probable(2, 3, 2, True, True)  # trimmed below the count
    assert not sweep.keeps_probable(3, 3, 1, True, True)  # one feed
    assert not sweep.keeps_probable(3, 3, 2, False, True)
    assert not sweep.keeps_probable(3, 3, 2, True, False)


# --------------------------------------------------------------------------- rederive


@pytest.fixture(scope="module")
def rederive():
    return _load("rederive_content_text")


def test_split_tail(rederive):
    assert rederive.split_tail("body") == ("body", "")
    assert rederive.split_tail(None) == ("", "")
    assert rederive.split_tail("body\n\nTranscript:\nhello") == ("body", "\n\nTranscript:\nhello")
    # The first tail wins, so OCR after a transcript stays inside the tail.
    text = "body\n\nTranscript:\nhi\n\n[Image OCR]\nocr"
    assert rederive.split_tail(text) == ("body", "\n\nTranscript:\nhi\n\n[Image OCR]\nocr")
    assert rederive.split_tail("body\n\n[Image OCR]\nocr") == ("body", "\n\n[Image OCR]\nocr")


def test_rederive_separates_glued_text(rederive):
    html = "<ul><li>46.233.40.20</li><li>4.4.4.4</li></ul>"
    status, new = rederive.rederive(html, "46.233.40.204.4.4.4")
    assert status == "changed"
    assert "46.233.40.20\n4.4.4.4" in new


def test_rederive_keeps_ocr_tail(rederive):
    html = "<p>power</p><p>Source: x</p>"
    stored = "powerSource: x\n\n[Image OCR]\nscanned words"
    status, new = rederive.rederive(html, stored)
    assert status == "changed"
    assert new.endswith("\n\n[Image OCR]\nscanned words")
    assert new.startswith("power\n\nSource: x")


def test_rederive_drops_transcript_div_and_keeps_tail(rederive):
    html = '<p>a</p><p>b</p><div class="transcript"><h3>Transcript</h3><p>said things</p></div>'
    stored = "ab\n\nTranscript:\nsaid things"
    status, new = rederive.rederive(html, stored)
    assert status == "changed"
    assert new == "a\n\nb\n\nTranscript:\nsaid things"
    # Idempotent: the rewritten text derives to itself.
    assert rederive.rederive(html, new) == ("unchanged", None)


def test_rederive_reports_text_not_from_this_html(rederive):
    status, new = rederive.rederive("<p>short teaser</p>", "the full article fetched separately")
    assert status == "differs" and new == "short teaser"


def test_rederive_fill_and_no_html(rederive):
    assert rederive.rederive(None, "text") == ("no_html", None)
    assert rederive.rederive("<p>x</p>", "") == ("filled", "x")
    assert rederive.rederive("<p>x</p>", "x") == ("unchanged", None)
