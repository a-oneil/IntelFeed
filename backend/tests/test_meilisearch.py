"""Tests for app.services.meilisearch_client.

All tests mock the meilisearch.Client to avoid needing a running Meilisearch instance.
"""

import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.services import meilisearch_client


@pytest.fixture(autouse=True)
def reset_client():
    """Reset the module-level _client between tests."""
    meilisearch_client._client = None
    yield
    meilisearch_client._client = None


@pytest.fixture
def mock_meili_client():
    """Create a mock meilisearch Client with a mock index."""
    client = MagicMock()
    index = MagicMock()
    client.index.return_value = index

    # _ensure_index: pretend the index already exists
    client.get_index.return_value = MagicMock()

    return client, index


class TestIndexEntry:
    def test_index_entry(self, mock_meili_client):
        """index_entry upserts via update_documents (a re-index must keep tag fields)."""
        client, index = mock_meili_client

        entry_id = uuid.uuid4()
        feed_id = uuid.uuid4()

        with patch("app.services.meilisearch_client.meilisearch.Client", return_value=client):
            meilisearch_client.index_entry(
                entry_id=entry_id,
                feed_id=feed_id,
                title="SIGMA Rule: Detect PsExec",
                content_text="Full article text about PsExec detection.",
                summary="A summary of the detection rule.",
                author="Detection Engineer",
                published_at="2024-01-15T10:00:00Z",
                feed_type="rss",
            )

        index.update_documents.assert_called_once()
        call_args = index.update_documents.call_args[0][0]

        assert len(call_args) == 1
        doc = call_args[0]
        assert doc["id"] == str(entry_id)
        assert doc["feed_id"] == str(feed_id)
        assert doc["title"] == "SIGMA Rule: Detect PsExec"
        assert doc["content_text"] == "Full article text about PsExec detection."
        assert doc["summary"] == "A summary of the detection rule."
        assert doc["author"] == "Detection Engineer"
        # Stored as a Unix timestamp so Meilisearch can sort on it numerically.
        assert doc["published_at"] == 1705312800
        assert doc["feed_type"] == "rss"

    def test_index_entry_unparseable_published_at_becomes_zero(self, mock_meili_client):
        """A published_at that will not parse must not blow up indexing."""
        client, index = mock_meili_client

        with patch("app.services.meilisearch_client.meilisearch.Client", return_value=client):
            meilisearch_client.index_entry(
                entry_id=uuid.uuid4(),
                feed_id=uuid.uuid4(),
                title="Bad Date",
                content_text="body",
                summary=None,
                author=None,
                published_at="not-a-date",
            )

        doc = index.update_documents.call_args[0][0][0]
        assert doc["published_at"] == 0

    def test_index_entry_truncates_content(self, mock_meili_client):
        """content_text should be truncated to 50000 characters."""
        client, index = mock_meili_client

        long_content = "x" * 60000

        with patch("app.services.meilisearch_client.meilisearch.Client", return_value=client):
            meilisearch_client.index_entry(
                entry_id=uuid.uuid4(),
                feed_id=uuid.uuid4(),
                title="Long Article",
                content_text=long_content,
                summary=None,
                author=None,
                published_at=None,
            )

        doc = index.update_documents.call_args[0][0][0]
        assert len(doc["content_text"]) == 50000

    def test_index_entry_handles_none_fields(self, mock_meili_client):
        """None fields should be converted to empty strings."""
        client, index = mock_meili_client

        with patch("app.services.meilisearch_client.meilisearch.Client", return_value=client):
            meilisearch_client.index_entry(
                entry_id=uuid.uuid4(),
                feed_id=uuid.uuid4(),
                title="Minimal Entry",
                content_text=None,
                summary=None,
                author=None,
                published_at=None,
            )

        doc = index.update_documents.call_args[0][0][0]
        assert doc["content_text"] == ""
        assert doc["summary"] == ""
        assert doc["author"] == ""
        assert doc["published_at"] == 0


class TestDeleteEntry:
    def test_delete_entry(self, mock_meili_client):
        """delete_entry should call delete_document with the stringified UUID."""
        client, index = mock_meili_client
        entry_id = uuid.uuid4()

        with patch("app.services.meilisearch_client.meilisearch.Client", return_value=client):
            meilisearch_client.delete_entry(entry_id)

        index.delete_document.assert_called_once_with(str(entry_id))


class TestSearchEntries:
    def test_search_entries(self, mock_meili_client):
        """search_entries should return hits from Meilisearch."""
        client, index = mock_meili_client

        expected_result = {
            "hits": [
                {"id": "abc-123", "title": "CVE-2024-0001 Analysis", "content_text": "..."},
                {"id": "def-456", "title": "Threat Report Q1", "content_text": "..."},
            ],
            "estimatedTotalHits": 2,
        }
        index.search.return_value = expected_result

        with patch("app.services.meilisearch_client.meilisearch.Client", return_value=client):
            result = meilisearch_client.search_entries("CVE-2024")

        assert result == expected_result
        index.search.assert_called_once()

        # Verify search was called with correct query and default params
        call_args = index.search.call_args
        assert call_args[0][0] == "CVE-2024"
        params = call_args[0][1]
        assert params["limit"] == 20
        assert params["offset"] == 0
        # The default sort is "relevance", which leaves Meilisearch's own
        # ranking rules in charge — no explicit sort is sent.
        assert "sort" not in params
        assert "filter" not in params

    def test_search_sort_modes(self, mock_meili_client):
        """Named sort modes map onto Meilisearch sort expressions."""
        client, index = mock_meili_client
        index.search.return_value = {"hits": [], "estimatedTotalHits": 0}

        expected = {
            "newest": ["published_at:desc"],
            "oldest": ["published_at:asc"],
            "title_asc": ["title:asc"],
            "title_desc": ["title:desc"],
            "shortest": ["word_count:asc"],
            "longest": ["word_count:desc"],
        }

        with patch("app.services.meilisearch_client.meilisearch.Client", return_value=client):
            for mode, expression in expected.items():
                meilisearch_client.search_entries("apt", sort=mode)
                assert index.search.call_args[0][1]["sort"] == expression, mode

    def test_search_with_feed_filter(self, mock_meili_client):
        """search_entries with feed_id should include a filter parameter."""
        client, index = mock_meili_client

        feed_id = str(uuid.uuid4())
        index.search.return_value = {"hits": [], "estimatedTotalHits": 0}

        with patch("app.services.meilisearch_client.meilisearch.Client", return_value=client):
            meilisearch_client.search_entries("lateral movement", feed_id=feed_id)

        call_args = index.search.call_args
        params = call_args[0][1]
        assert params["filter"] == f'feed_id = "{feed_id}"'

    def test_search_with_pagination(self, mock_meili_client):
        """search_entries should pass limit and offset to Meilisearch."""
        client, index = mock_meili_client
        index.search.return_value = {"hits": [], "estimatedTotalHits": 100}

        with patch("app.services.meilisearch_client.meilisearch.Client", return_value=client):
            meilisearch_client.search_entries("phishing", limit=10, offset=20)

        params = index.search.call_args[0][1]
        assert params["limit"] == 10
        assert params["offset"] == 20

    def test_search_handles_exception(self, mock_meili_client):
        """When Meilisearch raises an error, return empty results flagged as degraded.

        ``searchUnavailable`` lets callers tell "nothing matched" apart from
        "the search backend is down" instead of silently showing zero results.
        """
        client, index = mock_meili_client
        index.search.side_effect = Exception("Meilisearch connection refused")

        with patch("app.services.meilisearch_client.meilisearch.Client", return_value=client):
            result = meilisearch_client.search_entries("ransomware")

        assert result == {
            "hits": [],
            "estimatedTotalHits": 0,
            "processingTimeMs": 0,
            "searchUnavailable": True,
        }


class TestEntityIndexing:
    def test_entity_indexes_defined(self):
        """ENTITY_INDEXES should define all 4 entity types."""
        assert "entities_cve" in meilisearch_client.ENTITY_INDEXES
        assert "entities_ttp" in meilisearch_client.ENTITY_INDEXES
        assert "entities_threat_actor" in meilisearch_client.ENTITY_INDEXES
        assert "entities_malware" in meilisearch_client.ENTITY_INDEXES

    def test_index_entity(self, mock_meili_client):
        """index_entity should call add_documents on the correct index."""
        client, index = mock_meili_client

        doc = {"id": str(uuid.uuid4()), "name": "APT29", "aliases": ["Cozy Bear"]}

        with patch("app.services.meilisearch_client.meilisearch.Client", return_value=client):
            meilisearch_client.index_entity("entities_threat_actor", doc)

        client.index.assert_called_with("entities_threat_actor")
        index.add_documents.assert_called_once_with([doc])

    def test_bulk_index_entities(self, mock_meili_client):
        """bulk_index_entities should batch documents."""
        client, index = mock_meili_client

        docs = [{"id": str(uuid.uuid4()), "cve_id": f"CVE-2024-{i:04d}"} for i in range(5)]

        with patch("app.services.meilisearch_client.meilisearch.Client", return_value=client):
            meilisearch_client.bulk_index_entities("entities_cve", docs)

        index.add_documents.assert_called_once_with(docs)

    def test_bulk_index_entities_empty(self, mock_meili_client):
        """bulk_index_entities with empty list should not call Meilisearch."""
        client, index = mock_meili_client

        with patch("app.services.meilisearch_client.meilisearch.Client", return_value=client):
            meilisearch_client.bulk_index_entities("entities_cve", [])

        index.add_documents.assert_not_called()

    def test_search_entities(self, mock_meili_client):
        """search_entities should query the correct index."""
        client, index = mock_meili_client

        expected = {
            "hits": [{"id": "abc", "name": "APT29", "aliases": ["Cozy Bear"]}],
            "estimatedTotalHits": 1,
            "processingTimeMs": 5,
        }
        index.search.return_value = expected

        with patch("app.services.meilisearch_client.meilisearch.Client", return_value=client):
            result = meilisearch_client.search_entities("entities_threat_actor", "APT29")

        assert result == expected
        client.index.assert_called_with("entities_threat_actor")
        call_args = index.search.call_args
        assert call_args[0][0] == "APT29"

    def test_search_entities_error(self, mock_meili_client):
        """search_entities should return empty on error."""
        client, index = mock_meili_client
        index.search.side_effect = Exception("connection refused")

        with patch("app.services.meilisearch_client.meilisearch.Client", return_value=client):
            result = meilisearch_client.search_entities("entities_ttp", "T1059")

        assert result["hits"] == []
        assert result["estimatedTotalHits"] == 0
