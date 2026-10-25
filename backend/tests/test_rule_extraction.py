"""Rule extraction from article text: KQL, EQL, ES|QL and SPL code blocks.

The snippets are shaped like what the feeds that publish rules actually ship:
WordPress `<pre class="wp-block-code"><code>` blocks (Microsoft), highlighted
`<pre><code class="language-…">` blocks (Elastic Security Labs), and Markdown
fences (Reddit / raw files). Article HTML arrives sanitized, with `>` `<` `&`
still escaped as entities.
"""

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.rule_extraction import extract_rules_from_content, store_extracted_rules
from app.intelligence.rule_validation import validate_elastic_ql, validate_kql
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.feed import Feed
from app.services.sanitizer import html_to_text, sanitize_html

DEFENDER_KQL_HTML = """
<p>The following query surfaces the loader. Use it where Defender for Endpoint is deployed.</p>
<pre class="wp-block-code"><code>// Finds rundll32 launching from Office apps that don't normally spawn it
DeviceProcessEvents
| where Timestamp &gt; ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe")
| where FileName =~ "rundll32.exe" and ProcessCommandLine has_any ("javascript:", "&amp;")
| summarize count() by DeviceName, AccountName</code></pre>
<p>Defender customers can also check <code>DeviceNetworkEvents</code> for the C2.</p>
"""

EQL_SEQUENCE_HTML = """
<p>The sequence below catches the dropper writing then executing its payload.</p>
<pre><code class="language-eql">sequence by host.id with maxspan=1m
  [file where event.action == "creation" and file.extension == "dll"]
  [process where process.name == "rundll32.exe" and process.args : "*.dll,*"]
</code></pre>
"""

ESQL_HTML = """
<pre><code class="language-sql">FROM logs-endpoint.events.process-*
| WHERE process.name == "powershell.exe" AND process.command_line LIKE "*-enc*"
| STATS executions = COUNT(*) BY host.name
| WHERE executions &gt; 5
| SORT executions DESC</code></pre>
"""

TWO_SPL_TEXT = """Hunting for the loader in Splunk

The first query finds the scheduled task:

```spl
index=wineventlog EventCode=4698 TaskContent="*rundll32*"
| stats count by host, TaskName
```

The second one looks for the beacon:

```
index=proxy sourcetype=bluecoat dest_port=8443
| stats dc(dest) as dests by src
| where dests > 20
```
"""

ARTICLE_TITLE = "Hunting the loader"


def _by_type(rules: list[dict], rule_type: str) -> list[dict]:
    return [r for r in rules if r["rule_type"] == rule_type]


def _extract_html(html: str, title: str = ARTICLE_TITLE) -> list[dict]:
    """Run the extractor the way the pipeline does on an HTML article."""
    clean = sanitize_html(html)
    return extract_rules_from_content(title + "\n" + html_to_text(clean), html=clean, article_title=title)


def test_defender_kql_hunting_query_is_extracted_and_unescaped():
    rules = _extract_html(DEFENDER_KQL_HTML)

    kql = _by_type(rules, "kql")
    assert len(kql) == 1, rules
    content = kql[0]["rule_content"]
    assert content.startswith("DeviceProcessEvents")
    assert "Timestamp > ago(7d)" in content
    assert '"&"' in content
    assert "&gt;" not in content and "&amp;" not in content
    assert kql[0]["title"] == "Hunting the loader — KQL query 1"
    # The inline <code>DeviceNetworkEvents</code> mention is not a query.
    assert all("DeviceNetworkEvents" not in r["rule_content"] for r in rules)


def test_elastic_eql_sequence_is_extracted_as_elastic_ql():
    rules = _extract_html(EQL_SEQUENCE_HTML)

    eql = _by_type(rules, "elastic_ql")
    assert len(eql) == 1, rules
    assert eql[0]["rule_content"].startswith("sequence by host.id with maxspan=1m")
    assert eql[0]["title"] == "Hunting the loader — EQL query 1"


def test_esql_query_is_extracted_as_elastic_ql():
    rules = _extract_html(ESQL_HTML)

    esql = _by_type(rules, "elastic_ql")
    assert len(esql) == 1, rules
    assert esql[0]["rule_content"].startswith("FROM logs-endpoint.events.process-*")
    assert "executions > 5" in esql[0]["rule_content"]
    assert esql[0]["title"] == "Hunting the loader — ES|QL query 1"


def test_two_spl_queries_in_one_article_get_distinct_numbered_titles():
    rules = extract_rules_from_content(TWO_SPL_TEXT, article_title="Hunting the loader in Splunk")

    spl = _by_type(rules, "splunk_spl")
    assert len(spl) == 2, rules
    assert [r["title"] for r in spl] == [
        "Hunting the loader in Splunk — SPL query 1",
        "Hunting the loader in Splunk — SPL query 2",
    ]
    assert spl[0]["rule_content"] != spl[1]["rule_content"]


def test_spl_in_html_pre_is_not_extracted_twice():
    """The query is read from its <pre> block and again from the flattened text."""
    html = (
        "<p>Run this:</p><pre>index=wineventlog EventCode=4698 TaskContent=&quot;*rundll32*&quot;<br>"
        "| stats count by host, TaskName</pre>"
    )
    spl = _by_type(_extract_html(html), "splunk_spl")
    assert len(spl) == 1, spl
    assert (
        spl[0]["rule_content"]
        == 'index=wineventlog EventCode=4698 TaskContent="*rundll32*"\n| stats count by host, TaskName'
    )


def test_escaped_html_entities_are_decoded_in_text_rules():
    text = (
        'rule Loader_Strings {\n  strings:\n    $a = "cmd.exe /c"\n'
        "  condition:\n    uint16(0) == 0x5A4D and filesize &lt; 200KB and $a\n}"
    )
    yara = _by_type(extract_rules_from_content(text), "yara")
    assert len(yara) == 1
    assert "filesize < 200KB" in yara[0]["rule_content"]


@pytest.mark.parametrize(
    "html",
    [
        # Prose that says "where" and even quotes an operator.
        "<p>Filter DeviceProcessEvents | where the parent is Office, then summarize by device.</p>",
        "<p>Look for process where the parent is winword.exe, and any where it beacons.</p>",
        "<p>Start FROM logs-* | WHERE the host matches and keep going.</p>",
        # A code block holding a table name, a file path or a shell command.
        "<pre><code>DeviceProcessEvents</code></pre>",
        "<pre><code>C:\\Windows\\System32\\rundll32.exe payload.dll,Start</code></pre>",
        "<pre><code>cat access.log | grep beacon | sort | uniq -c</code></pre>",
        '<pre><code>dir | where Name -like "*.dll" | sort Length</code></pre>',
    ],
)
def test_prose_and_non_query_code_do_not_become_rules(html):
    rules = _extract_html(html)
    assert [r for r in rules if r["rule_type"] in ("kql", "elastic_ql", "splunk_spl")] == []


def test_kql_shaped_prose_outside_a_code_block_is_not_extracted():
    """Query languages need a code block; flattened text alone is not enough."""
    text = "DeviceProcessEvents\n| where FileName =~ 'rundll32.exe'\n| summarize count() by DeviceName"
    assert _by_type(extract_rules_from_content(text, article_title="t"), "kql") == []


def test_kql_validator_ignores_apostrophes_in_comments():
    query = "// Office apps that don't spawn rundll32\nDeviceProcessEvents\n| where FileName == 'rundll32.exe'"
    assert validate_kql(query).valid
    assert not validate_kql("DeviceProcessEvents\n| where FileName == 'rundll32.exe").valid
    # A URL inside a string is not a comment.
    assert validate_kql('DeviceNetworkEvents\n| where RemoteUrl == "https://evil.example/x"').valid
    # Verbatim strings take no escapes: @"C:\Temp\" is a closed string.
    assert validate_kql('DeviceFileEvents\n| where FolderPath startswith @"C:\\Temp\\"').valid


def test_elastic_validator_accepts_esql_and_commented_eql():
    assert validate_elastic_ql('FROM logs-*\n| WHERE host.name == "x"').valid
    assert validate_elastic_ql("// isn't signed\nprocess where process.code_signature.trusted == false").valid


# ── Storage ──────────────────────────────────────────────────────────────


async def _entry(db: AsyncSession, title: str) -> Entry:
    feed = Feed(title=f"Feed {uuid.uuid4().hex[:6]}", url=f"https://{uuid.uuid4().hex}.example.com/rss")
    db.add(feed)
    await db.flush()
    entry = Entry(feed_id=feed.id, title=title, url=f"https://{uuid.uuid4().hex}.example.com/a", guid=uuid.uuid4().hex)
    db.add(entry)
    await db.flush()
    return entry


def _spl_article(query: str, title: str) -> list[dict]:
    return extract_rules_from_content(f"```spl\n{query}\n```", article_title=title)


@pytest.mark.asyncio
async def test_spl_from_two_articles_is_stored_twice_not_overwritten(db_session: AsyncSession, test_user):
    """A recurring column repeats its title; a title match must not overwrite the other article's query."""
    first = await _entry(db_session, "Weekly hunting queries")
    second = await _entry(db_session, "Weekly hunting queries")
    q1 = "index=wineventlog EventCode=4698 | stats count by host"
    q2 = "index=proxy sourcetype=bluecoat | stats dc(dest) by src"

    await store_extracted_rules(db_session, first.id, test_user.id, _spl_article(q1, first.title))
    await store_extracted_rules(db_session, second.id, test_user.id, _spl_article(q2, second.title))

    rows = (await db_session.execute(select(DetectionRule).where(DetectionRule.rule_type == "splunk_spl"))).scalars()
    by_entry = {r.entry_id: r for r in rows}
    assert by_entry[first.id].rule_content == q1
    assert by_entry[second.id].rule_content == q2
    assert by_entry[first.id].title == "Weekly hunting queries — SPL query 1"


@pytest.mark.asyncio
async def test_reprocessing_an_article_is_idempotent(db_session: AsyncSession, test_user):
    entry = await _entry(db_session, ARTICLE_TITLE)
    rules = _extract_html(DEFENDER_KQL_HTML + EQL_SEQUENCE_HTML + ESQL_HTML)
    assert len(rules) == 3

    stored = await store_extracted_rules(db_session, entry.id, test_user.id, rules)
    assert len(stored) == 3
    again = await store_extracted_rules(
        db_session, entry.id, test_user.id, _extract_html(DEFENDER_KQL_HTML + EQL_SEQUENCE_HTML + ESQL_HTML)
    )
    assert again == []

    count = (await db_session.execute(select(DetectionRule).where(DetectionRule.entry_id == entry.id))).scalars().all()
    assert len(count) == 3


@pytest.mark.asyncio
async def test_rule_edited_upstream_updates_in_place(db_session: AsyncSession, test_user):
    entry = await _entry(db_session, "Loader update")
    await store_extracted_rules(
        db_session, entry.id, test_user.id, _spl_article("index=main EventCode=1 | stats count by host", entry.title)
    )
    await store_extracted_rules(
        db_session,
        entry.id,
        test_user.id,
        _spl_article("index=main EventCode=1 | stats count by host, user", entry.title),
    )

    rows = (await db_session.execute(select(DetectionRule).where(DetectionRule.entry_id == entry.id))).scalars().all()
    assert len(rows) == 1
    assert rows[0].rule_content.endswith("by host, user")


@pytest.mark.asyncio
async def test_same_rule_from_another_extractor_user_is_not_duplicated(db_session: AsyncSession, test_user, admin_user):
    """A pipeline run (system user) and a bulk run (the admin who clicked) share auto-extracted rules."""
    entry = await _entry(db_session, ARTICLE_TITLE)
    rules = _extract_html(DEFENDER_KQL_HTML)
    await store_extracted_rules(db_session, entry.id, test_user.id, rules)
    assert await store_extracted_rules(db_session, entry.id, admin_user.id, _extract_html(DEFENDER_KQL_HTML)) == []


@pytest.mark.asyncio
async def test_ingest_stage_reads_code_blocks_from_content_html(db_session: AsyncSession, monkeypatch, test_user):
    """The pipeline passes the article HTML and title, not only the flattened text."""
    from app.workers import intel_feed_tasks
    from tests.test_feeds import _worker_session_on

    feed = Feed(
        title="Microsoft Security Blog",
        url=f"https://{uuid.uuid4().hex}.example.com/rss",
        feed_type="rss",
        auto_extract_on_ingest=False,
        extract_detection_rules=True,
    )
    db_session.add(feed)
    await db_session.flush()
    clean = sanitize_html(DEFENDER_KQL_HTML)
    entry = Entry(
        feed_id=feed.id,
        title=ARTICLE_TITLE,
        url=f"https://{uuid.uuid4().hex}.example.com/a",
        guid=uuid.uuid4().hex,
        content_html=clean,
        content_text=html_to_text(clean),
    )
    db_session.add(entry)
    await db_session.flush()

    monkeypatch.setattr(intel_feed_tasks, "_get_worker_session", lambda: _worker_session_on(db_session))
    monkeypatch.setattr(db_session, "commit", db_session.flush)
    stats = await intel_feed_tasks._extract_entry_intel(str(entry.id))

    assert stats["detection_rules"] == 1
    rule = (await db_session.execute(select(DetectionRule).where(DetectionRule.entry_id == entry.id))).scalar_one()
    assert rule.rule_type == "kql"
    assert rule.title == "Hunting the loader — KQL query 1"
