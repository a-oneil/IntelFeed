"""The indicator-aware analysis window: HTML rendering that keeps table rows,
indicator-section detection, head+appendix composition, and hint ranking."""

import json
from pathlib import Path

import pytest

from app.services.analysis_window import (
    TRUNCATION_MARKER,
    analysis_content_window,
    compress_appendix,
    find_indicator_section,
    html_to_analysis_text,
    rank_candidate_hints,
)

# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------


def test_html_tables_render_as_pipe_rows_even_with_paragraph_cells():
    html = """
    <h2>IoCs</h2>
    <table><tbody>
      <tr><td><p><strong>MD5</strong></p></td><td colspan="2"><p>Description</p></td></tr>
      <tr><td><p>4bdaf7792e908f163ebef137854c571d</p></td><td><p>archive containing fake installer</p></td></tr>
    </tbody></table>
    <p>After the table.</p>
    """
    text = html_to_analysis_text(html)
    assert "## IoCs" in text
    assert "MD5 | Description" in text
    assert "4bdaf7792e908f163ebef137854c571d | archive containing fake installer" in text
    assert "After the table." in text


def test_html_block_boundaries_never_glue_text():
    html = (
        "<ul><li><p>46.233.40[.]20</p></li><li>46.233.40[.]21</li></ul>"
        "foo<div>bar</div><figure><figcaption>the power</figcaption></figure>Source: x"
        "<table><tr><td><table><tr><td>inner</td></tr></table></td><td>y</td><td>z</td></tr></table>"
    )
    text = html_to_analysis_text(html)
    assert "- 46.233.40[.]20\n\n- 46.233.40[.]21" in text
    assert "foo\nbar" in text
    assert "power\n\nSource: x" in text
    assert "y | z" in text


def test_html_empty_heading_renders_its_anchor_id():
    text = html_to_analysis_text(
        '<p>x</p><h2 id="indicators-of-compromise"></h2><table><tr><th>Type</th><th>Indicator</th></tr></table>'
    )
    assert "## indicators of compromise" in text
    assert "Type | Indicator" in text


def test_html_pre_blocks_keep_line_breaks_and_headings_get_own_line():
    html = "<p>Intro.</p><pre>cmd.exe /c whoami\nreg add HKCU\\x /v y</pre><h3>Indicators of compromise</h3><p>a</p>"
    text = html_to_analysis_text(html)
    assert "cmd.exe /c whoami\nreg add HKCU\\x /v y" in text
    assert "\n## Indicators of compromise\n" in text
    assert "&nbsp;" not in text


# ---------------------------------------------------------------------------
# Section detection
# ---------------------------------------------------------------------------


def _body(prefix_chars: int, section: str) -> str:
    return ("Narrative paragraph about the campaign. " * (prefix_chars // 40)) + "\n\n" + section


def test_find_indicator_section_heading_variants():
    for heading in (
        "## Indicators of compromise (IOCs)",
        "IOCs",
        "IoCs",
        "Indicators of Compromise",
        "TELEPUZ indicators of compromise",
        "Appendix A: Indicators",
        "Atomic Indicators",
    ):
        text = _body(4000, f"{heading}\n\nevil[.]com\n\n1.2.3.4")
        sec = find_indicator_section(text)
        assert sec is not None, heading
        assert text[sec[0] :].lstrip().startswith(heading)


def test_find_indicator_section_tolerates_glued_heading_and_trims_footer():
    # nh3's tag strip glues the heading to the previous sentence.
    text = _body(4000, "reduce the risk of infection.IoCs\n\n" + "deadbeef " * 60 + "\n\nReferences\n\nhttps://x")
    sec = find_indicator_section(text)
    assert sec is not None
    assert text[sec[0] : sec[0] + 4] == "IoCs"
    assert text[sec[0] : sec[1]].rstrip().endswith("deadbeef")


def test_find_indicator_section_falls_back_to_table_header_row():
    text = _body(
        4000,
        "##\n\nType | Indicator | Context\n\nIPv4 | 209.99.186.73 | Reported controller\n\n"
        "Domain | cdnorigin.net | TLS-fronted C2",
    )
    sec = find_indicator_section(text)
    assert sec is not None
    assert "Type | Indicator | Context" in text[sec[0] : sec[0] + 40]


def test_find_indicator_section_ignores_early_mentions():
    # An intro line saying where IOCs are must not start the appendix.
    text = "IOCs\n\n" + ("x " * 3000) + "\n\nIndicators of compromise\n\nevil[.]com"
    sec = find_indicator_section(text)
    assert sec is not None and sec[0] > 3000


# ---------------------------------------------------------------------------
# Window composition
# ---------------------------------------------------------------------------


def test_window_unchanged_when_body_fits():
    assert analysis_content_window("short body", 100) == "short body"


def test_window_appends_tail_section_with_marker():
    head = "Narrative sentence number one. " * 400  # ~12.4k chars
    section = "## Indicators of compromise\n\n" + "\n".join(f"evil{i}[.]com (C2)" for i in range(40))
    text = head + "\n\n" + section
    win = analysis_content_window(text, 8000, tail_reserve=0.4)
    assert len(win) <= 8000
    assert TRUNCATION_MARKER in win
    assert "## Indicators of compromise" in win
    assert "evil39[.]com" in win
    assert win.startswith("Narrative sentence")


def test_window_falls_back_to_candidate_tail_without_heading():
    head = "Narrative sentence number one. " * 400
    tail = "Final section.\n\nThe actor used 45.33.32.156 and hxxp://bad[.]example-c2[.]net and 185.199.108.153 for C2."
    text = head + "\n\n" + tail
    win = analysis_content_window(text, 8000, tail_reserve=0.4)
    assert TRUNCATION_MARKER in win
    assert "185.199.108.153" in win


def test_window_plain_slice_when_tail_has_nothing():
    text = "Narrative sentence number one. " * 400
    assert analysis_content_window(text, 8000) == text[:8000]


def test_window_contiguous_when_section_starts_inside_head():
    head = "Narrative. " * 300  # 3.3k
    section = "## IOCs\n\n" + "\n".join(f"evil{i}[.]com" for i in range(300))  # ~4.2k
    text = head + "\n\n" + section
    win = analysis_content_window(text, 6000, tail_reserve=0.4)
    assert TRUNCATION_MARKER not in win
    assert len(win) <= 6000
    assert "## IOCs" in win and "evil0[.]com" in win


def test_compress_appendix_quotas_every_indicator_kind():
    urls = "\n".join(f"hxxp://pub-{i:02d}[.]r2[.]dev/stage2 (Antino-chain Stage 2 URL)" for i in range(70))
    section = "## IOCs\n\n" + urls + "\n\nDomains\n\nosc-cdn[.]com (CloudFront staging domain)\n\n1.2.3.4 (C2)"
    out = compress_appendix(section, 2500)
    assert "osc-cdn[.]com" in out and "1.2.3.4" in out
    assert "55 more URLs" in out
    assert out.count("r2[.]dev") == 15


def test_compress_appendix_keeps_variety_over_hash_dump():
    hashes = "\n".join(("a" * 63 + chr(48 + i % 10)) + f" (loader {i})" for i in range(60))
    section = "## IOCs\n\n" + hashes + "\n\nDomains\n\nc2[.]example-bad[.]net\nhxxp://drop[.]example-bad[.]org/x"
    out = compress_appendix(section, 1200)
    assert "c2[.]example-bad[.]net" in out
    assert "more SHA256 hashes" in out
    assert len(out) <= 1200


# ---------------------------------------------------------------------------
# Hint ranking
# ---------------------------------------------------------------------------


def test_rank_candidate_hints_excludes_scan_host_kinds_and_caps_per_kind():
    cands = [{"kind": "cmdline", "value": f"Operating System: Red Hat {i}", "origin": "scan"} for i in range(50)]
    cands += [{"kind": "sha256", "value": "f" * 63 + str(i % 10), "origin": "scan"} for i in range(30)]
    cands += [{"kind": "domain", "value": "evil[.]com", "origin": "scan", "was_defanged": True}]
    cands += [{"kind": "cmdline", "value": "certutil -urlcache -f http://x/a.exe", "origin": "ai"}]
    out = rank_candidate_hints(cands, limit=40)
    kinds = [c["kind"] for c in out]
    assert out[0]["origin"] == "ai"  # AI stagings first
    assert out[1]["kind"] == "domain"  # then defanged tokens
    assert kinds.count("sha256") == 15  # per-kind cap
    assert all(c["origin"] == "ai" for c in out if c["kind"] == "cmdline")  # scan cmdlines excluded
    assert len(out) <= 40


# --- Acceptance on real bodies (plan §0.1): the rendered prompt text must carry
# the article's golden indicators even though every one of these bodies blows
# past the content cap with its IOC section at the end. Two regimes:
#   * the appendix fits the tail reserve (Xeno, N4D) → ≥95% of the golden
#     values the article actually prints survive the window;
#   * a hash dump that cannot fit (Talos UAT-11587: 16k chars of IOCs) → the
#     per-kind line quotas bound it by design (the model's output budget), so
#     the window must carry the quota's worth of every kind the article lists
#     and say how many it dropped. The publisher door covers the rest.
_FIXTURES = Path(__file__).parent / "fixtures" / "observables"
_REAL_BODIES = ["talos-uat-11587", "bitdefender-xeno-roblox", "datadog-n4d-mesh"]


def _present(values, text):
    from app.intelligence.observables import refang

    hay = refang(text).lower()
    return [v for v in values if refang(v).lower() in hay]


#: (cap, floor): the default cap keeps ≥90% of an article's in-text golden
#: values; the plan's recommended prod cap (20–24k) clears the 95% target.
#: What the default misses are indicators mentioned in prose mid-article —
#: outside both the head and the appendix — which only a larger head covers.
_CAP_FLOORS = [(12000, 0.90), (24000, 0.95)]


@pytest.mark.parametrize("cap,floor", _CAP_FLOORS)
@pytest.mark.parametrize("slug", _REAL_BODIES)
def test_window_keeps_golden_indicators_of_real_articles(slug, cap, floor):
    from app.services.analysis_window import (
        _LINE_QUOTAS,
        TRUNCATION_MARKER,
        analysis_content_window,
        find_indicator_section,
        html_to_analysis_text,
    )

    html = (_FIXTURES / "bodies" / f"{slug}.html").read_text()
    case = json.loads((_FIXTURES / "cases" / f"{slug}.json").read_text())
    text = html_to_analysis_text(html)
    if len(text) <= cap:
        pytest.skip("body fits this cap outright — nothing to window")
    section = find_indicator_section(text)
    assert section is not None, "every body has an indicator section"
    window = analysis_content_window(text, cap, tail_reserve=0.4)
    assert len(window) <= cap + len(TRUNCATION_MARKER) + 1
    assert TRUNCATION_MARKER in window

    by_kind: dict[str, list[str]] = {}
    for e in case["expected"]:
        by_kind.setdefault(e["kind"], []).append(e["value"])
    # Only what the article itself prints can be expected of the window (the
    # fixture also carries values seeded from the publisher's IOC file).
    in_text = {k: _present(vs, text) for k, vs in by_kind.items()}
    in_window = {k: _present(vs, window) for k, vs in in_text.items()}
    golden = sum(len(v) for v in in_text.values())
    kept = sum(len(v) for v in in_window.values())
    assert golden > 0

    appendix_fits = (section[1] - section[0]) <= int(cap * 0.4)
    if appendix_fits:
        assert kept / golden >= floor, f"{slug} @ {cap}: {kept}/{golden} in-text golden indicators in the window"
    else:
        for kind, vals in in_text.items():
            if not vals:
                continue
            floor = min(len(vals), _LINE_QUOTAS.get(kind, len(vals)))
            assert len(in_window[kind]) >= floor, f"{slug}: {kind} {len(in_window[kind])}/{len(vals)} (quota {floor})"
        assert "more" in window.lower(), "the compressed appendix says what it dropped"
