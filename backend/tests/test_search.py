"""Tests for search API (mocked Meilisearch)."""

import uuid
from unittest.mock import patch

import pytest
from httpx import AsyncClient

MOCK_SEARCH_RESULT = {
    "hits": [
        {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "title": "FortiOS CVE-2024-21762",
            "content_text": "Critical vulnerability in FortiOS...",
            "author": "BleepingComputer",
            "feed_title": "BleepingComputer",
            "feed_id": "feed-1",
            "feed_type": "rss",
            "published_at": "2024-02-09T00:00:00Z",
            "url": "https://example.com/article",
            "tags": ["critical-cve"],
        }
    ],
    "query": "CVE-2024",
    "processingTimeMs": 12,
    "estimatedTotalHits": 1,
    "facetDistribution": {
        "feed_type": {"rss": 1},
        "tags": {"critical-cve": 1},
        "media_type": {},
    },
}


@pytest.mark.asyncio
@patch("app.api.search.meilisearch_client.search_entries", return_value=MOCK_SEARCH_RESULT)
async def test_search_basic(mock_search, client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/search?q=CVE-2024", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["query"] == "CVE-2024"
    assert len(data["hits"]) == 1
    assert data["hits"][0]["title"] == "FortiOS CVE-2024-21762"
    assert data["estimatedTotalHits"] == 1
    assert data["processingTimeMs"] == 12
    mock_search.assert_called_once()


@pytest.mark.asyncio
@patch("app.api.search.meilisearch_client.search_entries", return_value=MOCK_SEARCH_RESULT)
async def test_search_with_filters(mock_search, client: AsyncClient, auth_headers: dict):
    resp = await client.get(
        "/api/search?q=CVE&feed_type=rss&sort=newest&is_starred=true",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    mock_search.assert_called_once()
    call_kwargs = mock_search.call_args
    assert call_kwargs.kwargs.get("feed_type") == ["rss"]
    assert call_kwargs.kwargs.get("sort") == "newest"
    assert call_kwargs.kwargs.get("is_starred") is True


@pytest.mark.asyncio
@patch("app.api.search.meilisearch_client.search_entries", return_value=MOCK_SEARCH_RESULT)
async def test_advanced_search(mock_search, client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/search/advanced",
        json={"q": "exploit", "feed_type": ["rss", "youtube"], "sort": "newest", "limit": 50},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["query"] == "exploit"


@pytest.mark.asyncio
@patch("app.api.search.meilisearch_client.get_facets", return_value={"feed_type": {"rss": 10}})
async def test_search_facets(mock_facets, client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/search/facets?q=CVE", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "facets" in data
    assert data["facets"]["feed_type"]["rss"] == 10


class TestUnifiedHideRead:
    """Hide Read on the search page.

    Read state is per-user Postgres state the index cannot filter on, so the
    endpoint scans the matches and drops the read ones. Filtering the fetched
    page instead — which the results list used to do in the browser — reported
    "nothing matched" over a search whose only unread hit ranked past the page
    break, while the sidebar's saved-search count (a full scan) said 1 unread.
    """

    async def _entries(self, db_session, test_feed, count: int):
        from app.models.entry import Entry

        entries = []
        for i in range(count):
            e = Entry(
                feed_id=test_feed.id,
                title=f"device code phishing {i}",
                guid=f"hide-read-{i}",
                url=f"https://example.com/hide-read/{i}",
                content_text="device code phishing",
            )
            db_session.add(e)
            entries.append(e)
        await db_session.flush()
        return entries

    def _fake_search(self, ordered_ids: list[str]):
        """Stand-in for the index: serves the IDs in rank order."""

        def run(plan, entry_id_constraint=None, limit=20, offset=0, attributes_to_retrieve=None):
            if entry_id_constraint is None:
                ids = ordered_ids
            else:
                allowed = set(entry_id_constraint)
                ids = [i for i in ordered_ids if i in allowed]
            window = ids[offset : offset + limit]
            if attributes_to_retrieve == ["id"]:
                hits = [{"id": i} for i in window]
            else:
                hits = [{"id": i, "title": f"hit {i}", "content_text": "device code phishing"} for i in window]
            return {"hits": hits, "estimatedTotalHits": len(ids), "processingTimeMs": 1}

        return run

    @pytest.mark.asyncio
    async def test_returns_unread_hit_ranked_past_the_page(
        self, client: AsyncClient, auth_headers: dict, db_session, test_feed, test_user
    ):
        from app.models.entry_state import UserEntryState

        entries = await self._entries(db_session, test_feed, 5)
        for e in entries[:4]:
            db_session.add(UserEntryState(user_id=test_user.id, entry_id=e.id, is_read=True))
        await db_session.flush()
        ordered = [str(e.id) for e in entries]

        with patch("app.search.meili_builder.execute_entry_search", self._fake_search(ordered)):
            resp = await client.post(
                "/api/search/unified",
                json={"q": "device code phishing", "limit": 2, "hide_read": True},
                headers=auth_headers,
            )

        assert resp.status_code == 200
        data = resp.json()["entries"]
        # The one unread entry is the fifth by rank, well past a two-row page.
        assert [h["id"] for h in data["hits"]] == [ordered[4]]
        assert data["estimatedTotalHits"] == 1

    @pytest.mark.asyncio
    async def test_off_by_default(self, client: AsyncClient, auth_headers: dict, db_session, test_feed, test_user):
        from app.models.entry_state import UserEntryState

        entries = await self._entries(db_session, test_feed, 3)
        for e in entries:
            db_session.add(UserEntryState(user_id=test_user.id, entry_id=e.id, is_read=True))
        await db_session.flush()
        ordered = [str(e.id) for e in entries]

        with patch("app.search.meili_builder.execute_entry_search", self._fake_search(ordered)):
            resp = await client.post(
                "/api/search/unified",
                json={"q": "device code phishing", "limit": 10},
                headers=auth_headers,
            )

        assert resp.status_code == 200
        data = resp.json()["entries"]
        assert len(data["hits"]) == 3
        assert data["estimatedTotalHits"] == 3


class TestUnifiedConstraintRouting:
    """Where an entity join's ID constraint gets answered.

    The builder puts at most 500 IDs in a Meilisearch `id IN [...]` filter and
    drops the rest, so a constraint bigger than that has to be answered from
    Postgres — a 600-ID join used to go to the index and quietly match against
    the first 500.
    """

    @pytest.mark.asyncio
    async def test_constraint_over_the_filter_cap_goes_to_postgres(self, client: AsyncClient, auth_headers: dict):
        ids = [str(uuid.uuid4()) for _ in range(600)]
        entities = [{"type": "threat_actor", "id": str(uuid.uuid4()), "name": "APT29"}]

        async def fake_entities(db, nodes, limit=200, user_id=None):
            return entities, set(ids)

        async def fake_pg(db, entry_ids, limit=20, offset=0, sort="relevance", unread_for_user=None):
            fake_pg.seen = entry_ids
            return {"hits": [], "estimatedTotalHits": len(entry_ids), "processingTimeMs": 0}

        with (
            patch("app.search.entity_builder.execute_entity_queries", fake_entities),
            patch("app.api.search._fetch_entries_by_ids", fake_pg),
        ):
            resp = await client.post(
                "/api/search/unified",
                json={"q": "threat_actor:APT29 ransomware", "limit": 20},
                headers=auth_headers,
            )

        assert resp.status_code == 200
        # Every ID reached the query, not just the 500 a filter string holds.
        assert len(fake_pg.seen) == 600


class TestHideReadPostgresPath:
    """`sort:radar` orders by a Postgres column, so it never reaches the index.
    Hide Read has to be a SQL condition there rather than a filtered scan."""

    @pytest.mark.asyncio
    async def test_radar_sort_excludes_read_entries(
        self, client: AsyncClient, auth_headers: dict, db_session, test_feed, test_user
    ):
        from app.models.entry import Entry
        from app.models.entry_state import UserEntryState

        entries = []
        for i in range(3):
            e = Entry(
                feed_id=test_feed.id,
                title=f"radar hide read {i}",
                guid=f"radar-hide-read-{i}",
                url=f"https://example.com/radar/{i}",
                priority_score=10 - i,
                priority_raw=90 - i,
            )
            db_session.add(e)
            entries.append(e)
        await db_session.flush()
        db_session.add(UserEntryState(user_id=test_user.id, entry_id=entries[0].id, is_read=True))
        await db_session.flush()

        resp = await client.post(
            "/api/search/unified",
            json={"q": "sort:radar", "limit": 10, "hide_read": True},
            headers=auth_headers,
        )

        assert resp.status_code == 200
        ids = [h["id"] for h in resp.json()["entries"]["hits"]]
        assert str(entries[0].id) not in ids
        assert {str(entries[1].id), str(entries[2].id)} <= set(ids)


class TestAutocompleteCoverage:
    """A field the grammar offers should also complete its values.

    The header suggested `signal:` and `sector:` for months and then went blank
    after the colon, which reads as "this instance has none" rather than "the
    autocomplete was never taught this field".
    """

    # Values are free text or a range — `title:ransomware`, `words:>1500`,
    # `date:>2026-01-01`. Nothing to offer, and offering the ten most common
    # article titles would be noise.
    NO_VOCABULARY = {
        "title",
        "content",
        "author",
        "url",
        "words",
        "date",
        "cve.cvss",
        "cve.epss",
        "cve.epss_percentile",
        "cve.poc",
    }

    # Answered by a hand-written branch in `_get_dynamic_values`, because each
    # needs something the tables cannot say: a popularity ranking, two tables at
    # once, or a display form that differs from what gets inserted.
    BESPOKE = {
        "threat_actor",
        "threat_actor.country",
        "malware",
        "malware.type",
        "ttp",
        "ttp.tactic",
        "cve",
        "cve.product",
        "note",
        "tag",
        "feed",
        "country",
        "country.region",
        "pir",
        "signal",
    }

    def test_every_offered_field_can_complete_its_values(self):
        from app.api.search import (
            _ARRAY_VALUE_FIELDS,
            _DISTINCT_VALUE_FIELDS,
            _NAME_VALUE_FIELDS,
            FIELD_SUGGESTIONS,
            STATIC_VALUES,
        )
        from app.search.entity_builder import BOOLEAN_FIELDS

        sourced = (
            set(STATIC_VALUES)
            | set(_NAME_VALUE_FIELDS)
            | set(_DISTINCT_VALUE_FIELDS)
            | set(_ARRAY_VALUE_FIELDS)
            | set(BOOLEAN_FIELDS)
            | self.BESPOKE
            | self.NO_VOCABULARY
        )
        offered = {f["text"].rstrip(":") for f in FIELD_SUGGESTIONS}
        missing = sorted(offered - sourced)
        assert not missing, f"offered with no way to complete its values: {missing}"

    @pytest.mark.asyncio
    async def test_signal_values_are_the_engine_registry(self, client: AsyncClient, auth_headers: dict):
        from app.intelligence.signals import SIGNAL_FAMILIES

        resp = await client.get("/api/search/autocomplete?q=signal:epss", headers=auth_headers)
        assert resp.status_code == 200
        values = {s["text"] for s in resp.json() if s["type"] == "value"}
        assert values == {name for name in SIGNAL_FAMILIES if "epss" in name}

    @pytest.mark.asyncio
    async def test_sector_values_come_from_the_vocabulary(self, client: AsyncClient, auth_headers: dict, db_session):
        # `sector:` is an entity field: values are the seeded sector names, so
        # the completion matches what `sector:Healthcare` will resolve against.
        resp = await client.get("/api/search/autocomplete?q=sector:health", headers=auth_headers)
        assert resp.status_code == 200
        assert [s["text"] for s in resp.json() if s["type"] == "value"] == ["Healthcare"]

    @pytest.mark.asyncio
    async def test_array_column_values_are_offered_one_element_at_a_time(
        self, client: AsyncClient, auth_headers: dict, db_session, test_user
    ):
        from app.models.detection_rule import DetectionRule

        db_session.add(
            DetectionRule(
                title="Suspicious device code auth",
                rule_type="sigma",
                rule_content="title: x",
                created_by=test_user.id,
                data_sources=["Azure AD Sign-in Logs", "Process Creation"],
            )
        )
        await db_session.flush()

        resp = await client.get("/api/search/autocomplete?q=rule.data_source:azure", headers=auth_headers)
        assert resp.status_code == 200
        assert [s["text"] for s in resp.json() if s["type"] == "value"] == ["Azure AD Sign-in Logs"]
