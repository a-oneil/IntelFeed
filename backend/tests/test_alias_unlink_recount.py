"""Removing an alias unlinks the articles only it matched, and the stored
article_count follows. TerminalFix kept showing 2,377 articles after its junk
'ClickFix' alias went and only 87 were still linked."""

import uuid

from app.models.entry import Entry
from app.models.feed import Feed
from app.models.tool import EntryTool, Tool


async def _entries(db_session, n: int) -> list[Entry]:
    feed = Feed(title="Blog", url=f"https://b{uuid.uuid4().hex[:6]}.example/f", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    rows = [
        Entry(feed_id=feed.id, title=f"t{i}", guid=f"g-{uuid.uuid4()}", url=f"https://e.example/{uuid.uuid4()}")
        for i in range(n)
    ]
    db_session.add_all(rows)
    await db_session.flush()
    return rows


async def test_removing_an_alias_recounts_the_entity(client, db_session, auth_headers):
    tool = Tool(name=f"TerminalFix{uuid.uuid4().hex[:4]}", aliases=["ClickFix"], article_count=3)
    db_session.add(tool)
    await db_session.flush()
    named, via_alias, via_alias_too = await _entries(db_session, 3)
    db_session.add_all(
        [
            EntryTool(entry_id=named.id, tool_id=tool.id, source="auto_link", matched_names=[tool.name]),
            EntryTool(entry_id=via_alias.id, tool_id=tool.id, source="auto_link", matched_names=["ClickFix"]),
            EntryTool(entry_id=via_alias_too.id, tool_id=tool.id, source="auto_link", matched_names=["clickfix"]),
        ]
    )
    await db_session.flush()

    res = await client.put(f"/api/entities/tools/{tool.id}", json={"aliases": []}, headers=auth_headers)
    assert res.status_code == 200
    await db_session.refresh(tool)
    assert tool.article_count == 1


async def test_alias_edit_that_unlinks_nothing_leaves_the_count(client, db_session, auth_headers):
    # The stored count can include links this edit has no business recounting
    # (it is maintained elsewhere); only an edit that unlinked something touches it.
    tool = Tool(name=f"Sliver{uuid.uuid4().hex[:4]}", aliases=["silver"], article_count=40)
    db_session.add(tool)
    await db_session.flush()

    res = await client.put(f"/api/entities/tools/{tool.id}", json={"aliases": []}, headers=auth_headers)
    assert res.status_code == 200
    await db_session.refresh(tool)
    assert tool.article_count == 40
