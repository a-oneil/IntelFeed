"""Tests for the unified search query planner: OR grouping, NOT handling, and sort."""

import pytest

from app.search.query_parser import parse_query
from app.search.query_planner import build_execution_plan, to_sql_pattern


def plan_for(query: str):
    return build_execution_plan(parse_query(query))


# ── Same-type entity OR ───────────────────────────────────


class TestEntityOrGrouping:
    def test_same_type_or_shares_group(self):
        plan = plan_for("threat_actor:APT28 OR threat_actor:APT29")
        assert len(plan.entity_nodes) == 1
        group = plan.entity_nodes[0]
        assert group.entity_type == "threat_actor"
        assert len(group.conditions) == 2
        group_ids = {c.or_group for c in group.conditions}
        assert len(group_ids) == 1
        assert None not in group_ids

    def test_and_conditions_have_no_group(self):
        plan = plan_for("threat_actor:APT28 AND threat_actor.country:russia")
        conds = plan.entity_nodes[0].conditions
        assert all(c.or_group is None for c in conds)

    def test_grouped_or_with_and_property(self):
        plan = plan_for("(threat_actor:APT28 OR threat_actor:APT29) AND threat_actor.country:russia")
        conds = {c.value: c for c in plan.entity_nodes[0].conditions}
        assert conds["APT28"].or_group is not None
        assert conds["APT28"].or_group == conds["APT29"].or_group
        assert conds["russia"].or_group is None

    def test_nested_or_flattens_into_one_group(self):
        plan = plan_for("threat_actor:APT28 OR (threat_actor:APT29 OR threat_actor:Turla)")
        conds = plan.entity_nodes[0].conditions
        assert len(conds) == 3
        assert len({c.or_group for c in conds}) == 1

    def test_and_subexpression_inside_or_keeps_and_semantics(self):
        # (a AND b) OR c can't join a flat OR group — a and b stay AND'd
        plan = plan_for("(threat_actor:APT28 AND threat_actor.country:russia) OR threat_actor:APT29")
        conds = {c.value: c for c in plan.entity_nodes[0].conditions}
        assert conds["APT28"].or_group is None
        assert conds["russia"].or_group is None
        assert conds["APT29"].or_group is not None

    def test_separate_or_expressions_get_distinct_groups(self):
        plan = plan_for("(threat_actor:APT28 OR threat_actor:APT29) AND (threat_actor:Turla OR threat_actor:Sandworm)")
        conds = {c.value: c for c in plan.entity_nodes[0].conditions}
        assert conds["APT28"].or_group == conds["APT29"].or_group
        assert conds["Turla"].or_group == conds["Sandworm"].or_group
        assert conds["APT28"].or_group != conds["Turla"].or_group


# ── Meilisearch filter OR ─────────────────────────────────


class TestMeiliFilterOr:
    def test_tag_or(self):
        plan = plan_for("tag:a OR tag:b")
        assert plan.meili_filters == ['(tags = "a" OR tags = "b")']

    def test_tag_and_unchanged(self):
        plan = plan_for("tag:a tag:b")
        assert plan.meili_filters == ['tags = "a"', 'tags = "b"']

    def test_and_group_inside_or(self):
        plan = plan_for("(tag:a type:rss) OR tag:b")
        assert plan.meili_filters == ['((tags = "a" AND feed_type = "rss") OR tags = "b")']

    def test_or_group_ands_with_outer_filters(self):
        # Normal form distributes the outer AND across the disjunction:
        # (a OR b) AND s  ≡  (a AND s) OR (b AND s). Both sides must carry the
        # outer filter — dropping it from either is how an OR leaks rows.
        plan = plan_for("(tag:a OR tag:b) is:starred")
        assert plan.meili_filters == ['((tags = "a" AND is_starred = true) OR (tags = "b" AND is_starred = true))']

    def test_negated_or_applies_de_morgan(self):
        # NOT (a OR b) = NOT a AND NOT b
        plan = plan_for("NOT (tag:a OR tag:b)")
        assert plan.meili_filters == ['NOT tags = "a"', 'NOT tags = "b"']

    def test_negated_filter_inside_or(self):
        plan = plan_for("NOT tag:a OR tag:b")
        assert plan.meili_filters == ['(NOT tags = "a" OR tags = "b")']


# ── Negated free text ─────────────────────────────────────


class TestNegatedText:
    def test_negated_bare_text_dropped(self):
        plan = plan_for("ransomware NOT phishing")
        assert plan.meili_query == "ransomware"

    def test_negated_phrase_dropped(self):
        plan = plan_for('malware NOT "weekly recap"')
        assert plan.meili_query == "malware"

    def test_only_negated_text_searches_everything(self):
        # Meilisearch cannot negate a query term, so the term is dropped — but
        # the query still asked for entries. Planning it as "no entry search"
        # is what made `NOT phishing` return zero rows instead of everything.
        plan = plan_for("NOT phishing")
        assert plan.meili_query == ""
        assert plan.has_entry_queries is True

    def test_negated_title_field_dropped(self):
        plan = plan_for("exploit NOT title:podcast")
        assert plan.meili_query == "exploit"

    def test_double_negation_keeps_text(self):
        plan = plan_for("NOT NOT exploit")
        assert plan.meili_query == "exploit"

    def test_negated_filter_fields_still_work(self):
        plan = plan_for("exploit NOT tag:noise")
        assert plan.meili_query == "exploit"
        assert plan.meili_filters == ['NOT tags = "noise"']


# ── Sort options ──────────────────────────────────────────


class TestSort:
    @pytest.mark.parametrize(
        "value",
        ["newest", "oldest", "relevance", "title_asc", "title_desc", "shortest", "longest"],
    )
    def test_valid_sorts_accepted(self, value):
        plan = plan_for(f"ransomware sort:{value}")
        assert plan.sort == value

    def test_invalid_sort_ignored(self):
        plan = plan_for("ransomware sort:magic")
        assert plan.sort == "relevance"


# ── Entity builder execution (DB) ─────────────────────────


class TestEntityOrExecution:
    @pytest.mark.asyncio
    async def test_same_type_or_returns_union(self, db_session):
        from app.models.threat_actor import ThreatActor
        from app.search.entity_builder import execute_entity_queries

        db_session.add_all(
            [
                ThreatActor(name="APT28"),
                ThreatActor(name="APT29"),
                ThreatActor(name="Turla"),
            ]
        )
        await db_session.flush()

        plan = plan_for("threat_actor:APT28 OR threat_actor:APT29")
        results, _entry_ids = await execute_entity_queries(db_session, plan.entity_nodes)
        names = {r["name"] for r in results}
        assert names == {"APT28", "APT29"}

    @pytest.mark.asyncio
    async def test_or_group_ands_with_property_filter(self, db_session):
        from app.models.threat_actor import ThreatActor
        from app.search.entity_builder import execute_entity_queries

        db_session.add_all(
            [
                ThreatActor(name="APT28", country="Russia"),
                ThreatActor(name="Lazarus", country="North Korea"),
            ]
        )
        await db_session.flush()

        plan = plan_for("(threat_actor:APT28 OR threat_actor:Lazarus) AND threat_actor.country:russia")
        results, _entry_ids = await execute_entity_queries(db_session, plan.entity_nodes)
        names = {r["name"] for r in results}
        assert names == {"APT28"}

    @pytest.mark.asyncio
    async def test_same_type_and_still_intersects(self, db_session):
        from app.models.threat_actor import ThreatActor
        from app.search.entity_builder import execute_entity_queries

        db_session.add_all([ThreatActor(name="APT28"), ThreatActor(name="APT29")])
        await db_session.flush()

        plan = plan_for("threat_actor:APT28 AND threat_actor:APT29")
        results, _entry_ids = await execute_entity_queries(db_session, plan.entity_nodes)
        assert results == []


# ── Regressions: operators that silently did the wrong thing ──────────────
#
# Every case below is a query that used to return the wrong rows, the wrong
# count, or nothing at all, with no error to explain it.


class TestBranchExpansion:
    """`(a OR b) AND c` needs one search per disjunct — Meilisearch has no OR
    inside a query string, and flattening it turned the AND into a union."""

    def test_grouped_or_distributes_over_and(self):
        plan = plan_for("(APT28 OR APT29) AND ransomware")
        assert [b.query for b in plan.branches] == ["APT28 ransomware", "APT29 ransomware"]

    def test_plain_and_stays_one_branch(self):
        plan = plan_for("ransomware APT29")
        assert len(plan.branches) == 1
        assert plan.branches[0].query == "ransomware APT29"

    def test_filter_only_or_collapses_to_one_search(self):
        # Meilisearch filters *do* support OR, so this must not fan out.
        plan = plan_for("tag:a OR tag:b")
        assert len(plan.branches) == 1
        assert plan.branches[0].filters == ['(tags = "a" OR tags = "b")']

    def test_or_with_an_unconstrained_side_does_not_filter(self):
        # The entity half is answered from Postgres; the index must not narrow
        # the union down to only the text side.
        plan = plan_for("ransomware OR threat_actor:APT29")
        assert [(b.query, b.filters) for b in plan.branches] == [("", [])]

    def test_global_filters_apply_to_every_branch(self):
        plan = plan_for("(APT28 OR APT29) is:starred")
        assert len(plan.branches) == 2
        assert all("is_starred = true" in b.filters for b in plan.branches)

    def test_branch_count_is_bounded(self):
        plan = plan_for("(a OR b) (c OR d) (e OR f) (g OR h) (i OR j)")
        assert len(plan.branches) <= 16


class TestEntryIntent:
    """A query that constrains nothing still asks for entries."""

    def test_empty_query_searches_everything(self):
        assert plan_for("").has_entry_queries is True

    def test_sort_alone_searches_everything(self):
        plan = plan_for("sort:newest")
        assert plan.has_entry_queries is True
        assert plan.sort == "newest"


class TestUnknownFields:
    def test_unknown_field_value_falls_back_to_free_text(self):
        plan = plan_for("titel:ransomware")
        assert plan.branches[0].query == "ransomware"
        assert plan.unknown_fields == ["titel"]

    def test_known_field_is_not_reported_as_unknown(self):
        assert plan_for("tag:apt").unknown_fields == []


class TestWildcards:
    def test_attribute_wildcard_becomes_a_facet_filter(self):
        plan = plan_for("tag:apt*")
        assert [(f.attribute, f.pattern) for f in plan.pending_facet_filters] == [("tags", "apt*")]
        # and not an exact clause, which would match a tag literally named apt*
        assert plan.branches[0].filters == []

    def test_attribute_without_wildcard_stays_an_exact_filter(self):
        plan = plan_for("tag:apt")
        assert plan.branches[0].filters == ['tags = "apt"']
        assert plan.pending_facet_filters == []

    def test_trailing_wildcard_stripped_from_free_text(self):
        # Meilisearch has no wildcard operator and treats `*` as a separator,
        # which cancelled the automatic prefix match on the final term.
        assert plan_for("ransom*").branches[0].query == "ransom"

    def test_phrase_keeps_its_asterisk(self):
        assert plan_for('"ransom*"').branches[0].query == '"ransom*"'

    def test_sql_pattern_translates_wildcards(self):
        assert to_sql_pattern("Krebs") == "%Krebs%"
        assert to_sql_pattern("Krebs*") == "Krebs%"
        assert to_sql_pattern("*security*") == "%security%"

    def test_sql_pattern_escapes_sql_metacharacters(self):
        # A CVE id or a URL must not be able to smuggle in a pattern of its own.
        assert to_sql_pattern("100%") == r"%100\%%"
        assert to_sql_pattern("a_b") == r"%a\_b%"


class TestDateSpans:
    """Every `date:` literal names a span, not an instant."""

    def test_month_covers_the_whole_month(self):
        plan = plan_for("date:2026-08")
        lo, hi = _bounds(plan)
        assert (lo, hi) == (_ts(2026, 8, 1), _ts(2026, 9, 1))

    def test_month_equals_the_explicit_day_range(self):
        assert _bounds(plan_for("date:2026-08")) == _bounds(plan_for("date:2026-08-01..2026-08-31"))

    def test_range_includes_the_final_day(self):
        _, hi = _bounds(plan_for("date:2026-01-01..2026-06-30"))
        assert hi == _ts(2026, 7, 1)

    def test_year_covers_the_whole_year(self):
        assert _bounds(plan_for("date:2026")) == (_ts(2026, 1, 1), _ts(2027, 1, 1))

    def test_single_day(self):
        assert _bounds(plan_for("date:2026-08-15")) == (_ts(2026, 8, 15), _ts(2026, 8, 16))

    def test_strictly_after_excludes_the_named_day(self):
        plan = plan_for("date:>2026-08-01")
        assert plan.meili_filters == [f"published_at >= {_ts(2026, 8, 2)}"]

    def test_on_or_after_includes_the_named_day(self):
        plan = plan_for("date:>=2026-08-01")
        assert plan.meili_filters == [f"published_at >= {_ts(2026, 8, 1)}"]

    def test_on_or_before_includes_the_named_day(self):
        plan = plan_for("date:<=2026-08-01")
        assert plan.meili_filters == [f"published_at < {_ts(2026, 8, 2)}"]

    def test_unparseable_date_is_ignored(self):
        assert plan_for("date:soon").meili_filters == []


def _ts(year: int, month: int, day: int) -> float:
    from datetime import UTC, datetime

    return datetime(year, month, day, tzinfo=UTC).timestamp()


def _bounds(plan) -> tuple[float, float]:
    lo = next(float(f.split()[-1]) for f in plan.meili_filters if ">=" in f)
    hi = next(float(f.split()[-1]) for f in plan.meili_filters if "<" in f and ">=" not in f)
    return lo, hi


class TestDeferredFilterBranches:
    """`feed:` and `category:` are answered from Postgres *after* planning, so
    they hold a placeholder in the branch expansion. Without one they collapsed
    onto every branch as a single AND, and `feed:A OR feed:B` — two feeds no
    entry can both belong to — matched nothing."""

    def test_feed_or_stays_a_disjunction(self):
        plan = plan_for('feed:"Reddit Digest" OR feed:"Red Canary"')
        assert len(plan.pending_feed_filters) == 2
        tokens = [f.token for f in plan.pending_feed_filters]
        assert all(tokens)
        # One search, with the two placeholders OR'd rather than ANDed.
        assert len(plan.branches) == 1
        assert plan.branches[0].filters == [f"({tokens[0]} OR {tokens[1]})"]

    def test_repeated_feed_filters_still_and(self):
        plan = plan_for("feed:A feed:B")
        tokens = [f.token for f in plan.pending_feed_filters]
        assert plan.branches[0].filters == tokens

    def test_text_or_feed_becomes_two_searches(self):
        plan = plan_for('ransomware OR feed:"Red Canary"')
        token = plan.pending_feed_filters[0].token
        assert [(b.query, b.filters) for b in plan.branches] == [("ransomware", []), ("", [token])]

    def test_category_and_feed_share_one_or_group(self):
        plan = plan_for("category:News OR feed:X")
        assert len(plan.branches) == 1
        assert len(plan.pending_entry_filters) == 1
        assert len(plan.pending_feed_filters) == 1
        assert " OR " in plan.branches[0].filters[0]

    def test_entry_scoped_filters_have_no_placeholder(self):
        # `signal:` resolves to a set of entry IDs, which cannot sit inside a
        # Meilisearch filter string — it keeps ANDing globally.
        plan = plan_for("signal:kev_added OR signal:scoop")
        assert [f.token for f in plan.pending_entry_filters] == ["", ""]
        assert plan.branches[0].filters == []

    def test_tokens_are_unique_across_both_kinds(self):
        plan = plan_for("feed:A OR category:B OR feed:C")
        tokens = [f.token for f in plan.pending_feed_filters] + [f.token for f in plan.pending_entry_filters]
        assert len(set(tokens)) == len(tokens)


class TestPendingSubstitution:
    def test_resolution_rewrites_the_branch_in_place(self):
        from app.search.query_planner import resolve_pending_filter

        plan = plan_for("feed:A OR feed:B")
        a, b = (f.token for f in plan.pending_feed_filters)
        resolve_pending_filter(plan, a, 'feed_id = "1"')
        resolve_pending_filter(plan, b, 'feed_id = "2"')
        assert plan.branches[0].filters == ['(feed_id = "1" OR feed_id = "2")']
        assert plan.meili_filters == ['(feed_id = "1" OR feed_id = "2")']


class TestEntryIdOrGroups:
    """`signal:`, `sector:`, `url:` and `is:translated`/`is:image` resolve to
    sets of entry IDs rather than filter clauses. Combining those sets with the
    operator the user typed — rather than always intersecting — is what stopped
    `signal:a OR signal:b` from meaning `signal:a AND signal:b`."""

    def _resolve(self, query, sets):
        """Plan `query`, hand each pending filter a canned ID set, fold it in."""
        from app.search.query_planner import ExecutionPlan, _apply_entry_id_filters

        plan = plan_for(query)
        resolved = [(pf, set(sets[i])) for i, pf in enumerate(plan.pending_entry_filters)]
        folded = ExecutionPlan()
        _apply_entry_id_filters(folded, resolved)
        return folded

    def test_or_unions_the_sets(self):
        p = self._resolve("signal:a OR signal:b", [{"1", "2"}, {"2", "3"}])
        assert p.db_entry_ids == {"1", "2", "3"}

    def test_implicit_and_still_intersects(self):
        p = self._resolve("signal:a sector:b", [{"1", "2"}, {"2", "3"}])
        assert p.db_entry_ids == {"2"}

    def test_or_across_different_kinds_unions(self):
        p = self._resolve("signal:a OR sector:b", [{"1"}, {"2"}])
        assert p.db_entry_ids == {"1", "2"}

    def test_three_way_or_unions(self):
        p = self._resolve("signal:a OR signal:b OR signal:c", [{"1"}, {"2"}, {"3"}])
        assert p.db_entry_ids == {"1", "2", "3"}

    def test_or_group_intersects_with_an_ungrouped_filter(self):
        # `(a OR b) AND c` — the group unions, then narrows by the loner.
        p = self._resolve("(signal:a OR signal:b) sector:c", [{"1", "2"}, {"3"}, {"2", "3", "4"}])
        assert p.db_entry_ids == {"2", "3"}

    def test_negated_member_becomes_an_exclusion(self):
        # NOT a OR b  ≡  everything except (a minus b)
        p = self._resolve("NOT signal:a OR signal:b", [{"1", "2"}, {"2", "3"}])
        assert p.db_excluded_ids == {"1"}
        assert p.db_entry_ids is None

    def test_two_negated_members_exclude_the_intersection(self):
        # NOT a OR NOT b  ≡  everything except (a AND b)
        p = self._resolve("NOT signal:a OR NOT signal:b", [{"1", "2"}, {"2", "3"}])
        assert p.db_excluded_ids == {"2"}

    def test_ungrouped_negation_is_unchanged(self):
        p = self._resolve("signal:a NOT sector:b", [{"1", "2"}, {"2"}])
        assert p.db_entry_ids == {"1", "2"}
        assert p.db_excluded_ids == {"2"}

    def test_is_flags_or_together(self):
        p = self._resolve("is:translated OR is:image", [{"1"}, {"2"}])
        assert p.db_entry_ids == {"1", "2"}


class TestIsFilterOr:
    """`is:` used to be planned in the walk, outside the branch expansion, so it
    could not be a side of an OR. `is:muted OR tag:x` returned the muted set
    with the tag silently dropped."""

    def test_index_flags_or_into_one_clause(self):
        plan = plan_for("is:starred OR is:bookmarked")
        assert plan.branches[0].filters == ["(is_starred = true OR is_bookmarked = true)"]

    def test_negation_flips_the_flag(self):
        assert plan_for("NOT is:starred").branches[0].filters == ["is_starred = false"]
        assert plan_for("NOT is:unread").branches[0].filters == ["is_read = true"]

    def test_muted_holds_a_placeholder_so_it_can_or(self):
        plan = plan_for("is:muted OR tag:x")
        token = plan.pending_entry_filters[0].token
        assert plan.pending_entry_filters[0].kind == "is.muted"
        assert plan.branches[0].filters == [f'({token} OR tags = "x")']

    def test_muted_ors_with_an_index_flag(self):
        plan = plan_for("is:muted OR is:starred")
        token = plan.pending_entry_filters[0].token
        assert plan.branches[0].filters == [f"({token} OR is_starred = true)"]

    def test_repeated_is_filters_still_and(self):
        plan = plan_for("is:starred is:unread")
        assert plan.branches[0].filters == ["is_starred = true", "is_read = false"]
