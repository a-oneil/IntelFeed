"""Unit tests for the Meilisearch builder.

The builder is where an OR across text terms stops being one search and becomes
a union assembled in Python, so these cover the merge, the paging and the
wildcard expansion without needing a live index.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.search.meili_builder import _merge_branch_hits, _resolve_facet_filters, execute_entry_search
from app.search.query_planner import ExecutionPlan, PendingFacetFilter, SearchBranch


def hit(i, published_at=0):
    return {"id": str(i), "published_at": published_at, "title": f"hit {i}"}


class FakeIndex:
    """Records the searches it is asked to run and replays canned hits."""

    def __init__(self, per_query=None, facets=None, total=100):
        self.per_query = per_query or {}
        self.facets = facets or {}
        self.total = total
        self.calls = []

    def search(self, query, params):
        self.calls.append((query, params))
        if params.get("limit") == 0:
            return {"hits": [], "facetDistribution": self.facets}
        hits = self.per_query.get(query, [])
        window = hits[params.get("offset", 0) : params.get("offset", 0) + params.get("limit", 20)]
        return {"hits": window, "estimatedTotalHits": self.total, "processingTimeMs": 1}


def run(plan, index, **kwargs):
    with patch("app.services.meilisearch_client._get_client") as client:
        client.return_value = MagicMock(index=MagicMock(return_value=index))
        return execute_entry_search(plan, **kwargs)


class TestMatchingStrategy:
    def test_terms_are_anded(self):
        # Meilisearch's default ("last") drops trailing words when strict
        # matching runs short, which made `a AND b` return what `a` returns.
        plan = ExecutionPlan(branches=[SearchBranch(query="ransomware APT29")])
        index = FakeIndex({"ransomware APT29": [hit(1)]})
        run(plan, index)
        assert index.calls[0][1]["matchingStrategy"] == "all"


class TestSingleBranch:
    def test_paging_is_left_to_the_index(self):
        plan = ExecutionPlan(branches=[SearchBranch(query="ransomware")])
        index = FakeIndex({"ransomware": [hit(i) for i in range(50)]})
        result = run(plan, index, limit=10, offset=20)
        query, params = index.calls[0]
        assert (params["limit"], params["offset"]) == (10, 20)
        assert result["estimatedTotalHits"] == 100

    def test_filters_are_anded_into_one_clause(self):
        plan = ExecutionPlan(branches=[SearchBranch(query="x", filters=['tags = "a"', "is_read = false"])])
        index = FakeIndex()
        run(plan, index, limit=5)
        assert index.calls[0][1]["filter"] == 'tags = "a" AND is_read = false'

    def test_no_filter_key_when_there_are_no_filters(self):
        index = FakeIndex()
        run(ExecutionPlan(branches=[SearchBranch(query="x")]), index, limit=5)
        assert "filter" not in index.calls[0][1]


class TestBranchUnion:
    def _plan(self):
        return ExecutionPlan(
            branches=[SearchBranch(query="APT28"), SearchBranch(query="APT29")],
            sort="relevance",
        )

    def test_limit_is_honoured(self):
        # The old merge appended every alternative's hits to the first page, so
        # a limit of 20 came back with 40 rows.
        index = FakeIndex({"APT28": [hit(i) for i in range(50)], "APT29": [hit(i) for i in range(100, 150)]})
        result = run(self._plan(), index, limit=20, offset=0)
        assert len(result["hits"]) == 20

    def test_pages_do_not_overlap(self):
        index = FakeIndex({"APT28": [hit(i) for i in range(50)], "APT29": [hit(i) for i in range(100, 150)]})
        first = {h["id"] for h in run(self._plan(), index, limit=20, offset=0)["hits"]}
        second = {h["id"] for h in run(self._plan(), index, limit=20, offset=20)["hits"]}
        assert first & second == set()

    def test_total_is_stable_across_pages(self):
        # A total that drifts as the user pages reads as a bug in the UI.
        index = FakeIndex({"APT28": [hit(i) for i in range(50)], "APT29": [hit(i) for i in range(100, 150)]})
        totals = {run(self._plan(), index, limit=20, offset=o)["estimatedTotalHits"] for o in (0, 20, 40)}
        assert totals == {200}

    def test_duplicates_across_branches_are_collapsed(self):
        index = FakeIndex({"APT28": [hit(1), hit(2)], "APT29": [hit(2), hit(3)]})
        ids = [h["id"] for h in run(self._plan(), index, limit=10)["hits"]]
        assert ids == sorted(set(ids), key=ids.index)
        assert set(ids) == {"1", "2", "3"}

    def test_branches_each_get_the_shared_filters(self):
        plan = ExecutionPlan(
            branches=[SearchBranch(query="APT28", filters=["is_read = false"]), SearchBranch(query="APT29")],
        )
        index = FakeIndex()
        run(plan, index, entry_id_constraint=["abc"])
        filters = [params.get("filter", "") for _, params in index.calls]
        assert all("id IN ['abc']" in f for f in filters)
        assert "is_read = false" in filters[0]


class TestMergeOrdering:
    def test_sorted_plans_merge_on_the_sort_key(self):
        a = {"hits": [hit(1, 300), hit(2, 100)]}
        b = {"hits": [hit(3, 200)]}
        assert [h["id"] for h in _merge_branch_hits([a, b], "newest")] == ["1", "3", "2"]

    def test_relevance_interleaves_branches(self):
        # Scores from separate searches are not comparable, so rank order is
        # taken turn by turn rather than trusting one branch over the other.
        a = {"hits": [hit(1), hit(2)]}
        b = {"hits": [hit(3), hit(4)]}
        assert [h["id"] for h in _merge_branch_hits([a, b], "relevance")] == ["1", "3", "2", "4"]


class TestFacetWildcards:
    def _index(self):
        return FakeIndex(facets={"tags": {"apt-report": 5, "apt29": 2, "ransomware": 9}})

    def test_pattern_expands_to_matching_values(self):
        clauses = _resolve_facet_filters(self._index(), [PendingFacetFilter("tags", "apt*")])
        assert clauses == ['(tags = "apt-report" OR tags = "apt29")']

    def test_single_match_needs_no_parentheses(self):
        clauses = _resolve_facet_filters(self._index(), [PendingFacetFilter("tags", "ransom*")])
        assert clauses == ['tags = "ransomware"']

    def test_matching_is_case_insensitive(self):
        clauses = _resolve_facet_filters(self._index(), [PendingFacetFilter("tags", "APT*")])
        assert clauses == ['(tags = "apt-report" OR tags = "apt29")']

    def test_no_match_filters_everything_out(self):
        clauses = _resolve_facet_filters(self._index(), [PendingFacetFilter("tags", "zzz*")])
        assert clauses == ['tags = "__no_match__"']

    def test_negated_pattern_excludes_the_matches(self):
        clauses = _resolve_facet_filters(self._index(), [PendingFacetFilter("tags", "apt*", negated=True)])
        assert clauses == ['NOT (tags = "apt-report" OR tags = "apt29")']

    def test_negated_no_match_excludes_nothing(self):
        assert _resolve_facet_filters(self._index(), [PendingFacetFilter("tags", "zzz*", negated=True)]) == []


class TestEmptyConstraint:
    def test_an_empty_id_constraint_short_circuits(self):
        plan = ExecutionPlan(branches=[SearchBranch(query="x")])
        result = execute_entry_search(plan, entry_id_constraint=[], limit=10)
        assert result == {"hits": [], "estimatedTotalHits": 0, "processingTimeMs": 0}


@pytest.mark.parametrize("sort,expected", [("newest", True), ("relevance", False)])
def test_sort_is_only_sent_when_it_maps(sort, expected):
    plan = ExecutionPlan(branches=[SearchBranch(query="x")], sort=sort)
    index = FakeIndex()
    run(plan, index)
    assert ("sort" in index.calls[0][1]) is expected


class TestUnresolvedPlaceholders:
    """A caller that skips the resolvers must degrade to "filter ignored", not
    hand Meilisearch a filter string it cannot parse."""

    def test_placeholder_clauses_are_dropped(self):
        plan = ExecutionPlan(branches=[SearchBranch(query="x", filters=["\x00pending:0\x00", 'tags = "a"'])])
        index = FakeIndex()
        run(plan, index, limit=5)
        assert index.calls[0][1]["filter"] == 'tags = "a"'

    def test_a_wholly_unresolved_branch_sends_no_filter(self):
        plan = ExecutionPlan(branches=[SearchBranch(query="x", filters=["(\x00pending:0\x00 OR \x00pending:1\x00)"])])
        index = FakeIndex()
        run(plan, index, limit=5)
        assert "filter" not in index.calls[0][1]


class TestAttributesToRetrieve:
    """An ID-only scan, which is how Hide Read finds unread matches past the
    fetched page. Entries index up to 50k characters of body text apiece, so
    the scan asks for IDs and nothing else."""

    def test_scan_asks_for_ids_only(self):
        plan = ExecutionPlan(branches=[SearchBranch(query="x")])
        index = FakeIndex({"x": [hit(i) for i in range(5)]})
        run(plan, index, limit=1000, attributes_to_retrieve=["id"])
        params = index.calls[0][1]
        assert params["attributesToRetrieve"] == ["id"]
        # Highlighting exists for a page someone reads, not for a scan.
        assert "attributesToHighlight" not in params
        assert "attributesToCrop" not in params

    def test_sort_attribute_survives_the_trim(self):
        # The union of a multi-branch query is sorted here, on the hits' own
        # values — without the attribute every hit sorts equal.
        plan = ExecutionPlan(branches=[SearchBranch(query="x")], sort="newest")
        index = FakeIndex({"x": [hit(1)]})
        run(plan, index, attributes_to_retrieve=["id"])
        assert index.calls[0][1]["attributesToRetrieve"] == ["id", "published_at"]

    def test_full_documents_by_default(self):
        plan = ExecutionPlan(branches=[SearchBranch(query="x")])
        index = FakeIndex({"x": [hit(1)]})
        run(plan, index)
        assert "attributesToRetrieve" not in index.calls[0][1]
        assert index.calls[0][1]["attributesToHighlight"] == ["title", "content_text"]
