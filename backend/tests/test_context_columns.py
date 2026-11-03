"""Enrichment context as entity-table columns (app/enrichment/context_columns.py):
GET …/context-columns, POST …/context-values, and ctx:* sort/filter on the
entity list endpoints."""

from datetime import UTC, datetime, timedelta

import pytest

from app.config import settings
from app.enrichment.manifest import Egress
from app.enrichment.registry import SOURCE_REGISTRY
from app.models.cve import CVE
from app.models.enrichment import EnrichmentSource, EntityContext
from app.models.tool import Tool

NOW = datetime.now(UTC)
STARS = "ctx:github_repo:stars"
TOPICS = "ctx:github_repo:topics"
PUSHED = "ctx:github_repo:pushed_at"


def _source(source_type: str, is_enabled: bool = True) -> EnrichmentSource:
    cls = SOURCE_REGISTRY[source_type]
    return EnrichmentSource(
        source_type=source_type,
        display_name=cls.display_name,
        rate_limit_config=cls.quota.rate_limit_config,
        daily_budget=cls.quota.daily_budget,
        is_enabled=is_enabled,
        trigger_mode="manual",
    )


def _ctx(entity_type, entity_id, source_type, key, value) -> EntityContext:
    return EntityContext(
        entity_type=entity_type,
        entity_id=entity_id,
        source_type=source_type,
        key=key,
        value=value,
        observed_at=NOW,
        expires_at=NOW + timedelta(days=1),
    )


@pytest.fixture
async def tools(db_session):
    """Three tools: two looked up on GitHub, one not."""
    big, small, none = Tool(name="Sliver"), Tool(name="Tinyc2"), Tool(name="Unknown Tool")
    db_session.add_all([big, small, none, _source("github_repo")])
    await db_session.flush()
    db_session.add_all(
        [
            _ctx("tool", big.id, "github_repo", "stars", 9000),
            _ctx("tool", big.id, "github_repo", "topics", ["c2", "red-team", "golang"]),
            _ctx("tool", big.id, "github_repo", "pushed_at", "2026-10-01"),
            _ctx("tool", small.id, "github_repo", "stars", 40),
            _ctx("tool", small.id, "github_repo", "topics", ["c2"]),
            _ctx("tool", small.id, "github_repo", "pushed_at", "2023-02-11"),
        ]
    )
    await db_session.flush()
    return {"big": big, "small": small, "none": none}


async def _names(client, headers, **params):
    resp = await client.get("/api/tools", params={"limit": 50, **params}, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return [t["name"] for t in body["items"]], body["total"]


async def test_columns_list_the_table_sized_outputs_of_enabled_sources(client, auth_headers, tools):
    resp = await client.get("/api/entities/tool/context-columns", headers=auth_headers)
    assert resp.status_code == 200
    cols = {c["id"]: c for c in resp.json()}
    assert cols[STARS] == {
        "id": STARS,
        "source_type": "github_repo",
        "source_label": SOURCE_REGISTRY["github_repo"].display_name,
        "key": "stars",
        "label": "Stars",
        "display": "fact",
    }
    assert cols[TOPICS]["display"] == "chips"
    # A link isn't a column; a source with no row (malpedia) isn't enabled.
    assert "ctx:github_repo:repo" not in cols
    assert not any(c.startswith("ctx:malpedia:") for c in cols)


async def test_sorting_by_a_value_puts_the_blanks_last_both_ways(client, auth_headers, tools):
    desc, _ = await _names(client, auth_headers, sort_by=STARS, sort_order="desc")
    asc, _ = await _names(client, auth_headers, sort_by=STARS, sort_order="asc")
    assert desc == ["Sliver", "Tinyc2", "Unknown Tool"]
    assert asc == ["Tinyc2", "Sliver", "Unknown Tool"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (">100", ["Sliver"]),
        ("<=40", ["Tinyc2"]),
        ("=9000", ["Sliver"]),
        ("*", ["Sliver", "Tinyc2"]),
        ("!", ["Unknown Tool"]),
    ],
)
async def test_numeric_and_presence_filters(client, auth_headers, tools, value, expected):
    names, total = await _names(client, auth_headers, sort_by="name", **{STARS: value})
    assert names == expected
    assert total == len(expected)


async def test_text_filters_match_list_items_and_compare_dates_as_text(client, auth_headers, tools):
    assert (await _names(client, auth_headers, sort_by="name", **{TOPICS: "GOLANG"}))[0] == ["Sliver"]
    # A list compares by its length.
    assert (await _names(client, auth_headers, sort_by="name", **{TOPICS: ">1"}))[0] == ["Sliver"]
    assert (await _names(client, auth_headers, sort_by="name", **{PUSHED: ">2025-01"}))[0] == ["Sliver"]
    assert (await _names(client, auth_headers, sort_by="name", **{PUSHED: "=2023-02-11"}))[0] == ["Tinyc2"]


async def test_an_unknown_or_disabled_column_is_a_400(client, auth_headers, db_session, tools):
    resp = await client.get("/api/tools", params={"sort_by": "ctx:nope:stars"}, headers=auth_headers)
    assert resp.status_code == 400
    resp = await client.get("/api/tools", params={"ctx:malpedia:attribution": "x"}, headers=auth_headers)
    assert resp.status_code == 400


async def test_values_come_back_per_entity_and_column(client, auth_headers, tools):
    ids = [str(t.id) for t in tools.values()]
    resp = await client.post("/api/entities/tool/context-values", json={"ids": ids}, headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body[str(tools["big"].id)][STARS] == 9000
    assert body[str(tools["small"].id)][TOPICS] == ["c2"]
    assert str(tools["none"].id) not in body


async def test_cve_list_sorts_and_filters_on_context(client, auth_headers, db_session):
    hot, cold = CVE(cve_id="CVE-2026-0001"), CVE(cve_id="CVE-2026-0002")
    db_session.add_all([hot, cold, _source("epss")])
    await db_session.flush()
    db_session.add_all([_ctx("cve", hot.id, "epss", "epss", 0.94), _ctx("cve", cold.id, "epss", "epss", 0.01)])
    await db_session.flush()

    resp = await client.get(
        "/api/cves", params={"sort_by": "ctx:epss:epss", "sort_order": "desc"}, headers=auth_headers
    )
    assert [c["cve_id"] for c in resp.json()["items"]] == ["CVE-2026-0001", "CVE-2026-0002"]
    resp = await client.get("/api/cves", params={"ctx:epss:epss": ">0.5"}, headers=auth_headers)
    assert [c["cve_id"] for c in resp.json()["items"]] == ["CVE-2026-0001"]


async def test_visitors_cant_see_or_use_an_ioc_sharing_source(client, tools, monkeypatch):
    monkeypatch.setattr(settings, "public_read_only_enabled", True)
    monkeypatch.setattr(SOURCE_REGISTRY["github_repo"], "egress", Egress.SHARES_IOC)

    cols = (await client.get("/api/entities/tool/context-columns")).json()
    assert not any(c["source_type"] == "github_repo" for c in cols)
    assert (await client.get("/api/tools", params={"sort_by": STARS})).status_code == 400
    resp = await client.post("/api/entities/tool/context-values", json={"ids": [str(tools["big"].id)]})
    assert resp.status_code == 200
    assert resp.json() == {}
