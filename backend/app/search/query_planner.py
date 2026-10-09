"""
Query planner: walks the AST and separates into Meilisearch (entry) vs PostgreSQL (entity) execution plans.

The planner classifies each FieldNode by its field name, builds separate sub-trees
for entry search and entity search, and determines how to join them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, timedelta

from app.search.query_parser import ASTNode, BoolNode, FieldNode, NotNode, TextNode

# ── Field classification ─────────────────────────────────


ENTRY_FIELDS = frozenset(
    {
        "title",
        "content",
        "author",
        "feed",
        "tag",
        "type",
        "date",
        "is",
        "media",
        "lang",
        # Resolved against Postgres rather than Meilisearch — see
        # PendingEntryFilter. None of these are in the search index, and
        # resolving them here avoids re-indexing 94k documents to add them.
        "category",
        "signal",
        "url",
        "words",
        "feed.reliability",
        "feed.timeliness",
        "feed.relevance",
    }
)

META_FIELDS = frozenset({"sort"})

ENTITY_FIELD_ROOTS = frozenset(
    {
        "cve",
        "cwe",
        "ttp",
        "threat_actor",
        "malware",
        "country",
        "sector",
        "tool",
        "vendor",
        "product",
        "mitigation",
        "campaign",
        "ransomware_victim",
        "observable",
        "ioc",  # alias root for observable — same planner behavior, shorter to type
        "rule",
        "pir",
        "intel_report",
        "note",
    }
)

# All known entity fields (root and dotted)
ENTITY_FIELDS = frozenset(
    {
        "cve",
        "cve.severity",
        "cve.cvss",
        "cwe",
        "cwe.abstraction",
        "cwe.usage",
        "cwe.parent",
        "cwe.kind",
        "cwe.deprecated",
        "observable",
        "observable.kind",
        "observable.role",
        "observable.status",
        "ioc",
        "ioc.kind",
        "ioc.role",
        "ioc.status",
        "ttp",
        "ttp.tactic",
        "threat_actor",
        "threat_actor.country",
        "malware",
        "malware.type",
        "country",
        "country.region",
        "sector",
        "sector.slug",
        "tool",
        "tool.type",
        "vendor",
        "vendor.type",
        "product",
        "product.type",
        "mitigation",
        "campaign",
        "campaign.status",
        "ransomware_victim",
        "ransomware_victim.sector",
        "ransomware_victim.domain",
        "rule",
        "rule.type",
        "rule.severity",
        "pir",
        "pir.priority",
        "pir.category",
        # ── Exploitation signals. Severity and CVSS say how bad a flaw could be;
        # these say whether anyone is actually using it, which is the question a
        # responder is usually asking.
        "cve.kev",
        "cve.epss",
        "cve.epss_percentile",
        "cve.poc",
        "cve.exploit",
        "cve.product",
        # ── ATT&CK shape. Platform and data source are how a detection engineer
        # narrows a technique to the telemetry they actually have.
        "ttp.platform",
        "ttp.data_source",
        "ttp.domain",
        "ttp.subtechnique",
        "ttp.deprecated",
        # ── Rule content, including the data_sources the telemetry-coverage
        # view already reads but nothing could query.
        "rule.data_source",
        "rule.tactic",
        "rule.tag",
        "rule.draft",
        "rule.license",
        # ── Actor / malware / tool attributes beyond the one each had.
        "threat_actor.motivation",
        "threat_actor.sector",
        "threat_actor.type",
        "threat_actor.mitre",
        "malware.sector",
        "malware.mitre",
        "tool.platform",
        "tool.mitre",
        "country.iso",
        # ── The group that posted a victim: the obvious leak-site query, and
        # the one field the victim grammar was missing.
        "ransomware_victim.group",
        "product.vendor",
        # ── Reports were returned by search but had no field to filter them,
        # unlike campaigns, rules and PIRs.
        "intel_report",
        "intel_report.status",
        "intel_report.type",
        "intel_report.tlp",
        # ── Analyst notes, across both tables that hold them: entry/standalone
        # notes and notes on an entity. `note.about:` takes an entity type, or
        # `entry` / `standalone` for the other kind.
        "note",
        "note.tag",
        "note.type",
        "note.about",
        "note.pinned",
    }
    # Attributes every catalogued entity carries: how much has been written
    # about it, when it was last seen, and how it got here. Generated rather
    # than listed thirty times.
    | {
        f"{root}.{leaf}"
        for root in (
            "ttp",
            "threat_actor",
            "malware",
            "country",
            "sector",
            "tool",
            "vendor",
            "product",
            "mitigation",
            "cwe",
            "observable",
            "ioc",
        )
        for leaf in ("articles", "seen", "first_seen")
    }
    | {f"{root}.{leaf}" for root in ("threat_actor", "malware", "cve", "ttp", "tool") for leaf in ("review", "via")}
)


def classify_field(field_name: str) -> str:
    """Classify a field name as 'entry', 'entity', or 'meta'."""
    if field_name in META_FIELDS:
        return "meta"
    if field_name in ENTRY_FIELDS:
        return "entry"
    if field_name in ENTITY_FIELDS:
        return "entity"
    # Check root for dotted fields
    root = field_name.split(".")[0]
    if root in ENTITY_FIELD_ROOTS:
        return "entity"
    # Default: treat as entry text search
    return "entry"


# ── Parsed filter (for chip rendering) ───────────────────


@dataclass
class ParsedFilter:
    """One parsed filter, used for rendering chips in the UI."""

    field: str
    value: str
    exact: bool = False
    negated: bool = False
    raw: str = ""  # original text fragment


# ── Execution plan ───────────────────────────────────────


@dataclass
class PendingFeedFilter:
    """A feed name filter that needs DB resolution to feed IDs.

    `token` is the placeholder this filter occupies in the branch expansion.
    The clause is not known until Postgres has been asked, but its *position* in
    the boolean expression is known now — without holding that position,
    `feed:A OR feed:B` collapsed to `feed:A AND feed:B` and matched nothing.
    """

    value: str
    exact: bool = False
    negated: bool = False
    token: str = ""


@dataclass
class PendingEntryFilter:
    """A filter whose answer lives in Postgres, not the search index.

    Two shapes resolve differently: `feed`-scoped kinds narrow to a set of feed
    IDs (there are only a few hundred feeds, so they become Meilisearch filter
    clauses), while `entry`-scoped kinds produce a set of entry IDs that
    constrains the search the same way an entity join already does.
    """

    kind: str
    value: str
    negated: bool = False
    # Placeholder in the branch expansion, for the feed-scoped kinds that
    # resolve to a Meilisearch clause. Entry-scoped kinds resolve to a set of
    # entry IDs instead and cannot sit in a filter string, so they carry an
    # `or_group` and are combined as sets rather than as filter syntax.
    token: str = ""
    # Filters sharing an or_group are UNIONed; everything else intersects.
    or_group: int | None = None


@dataclass
class PendingFacetFilter:
    """A wildcard filter on a low-cardinality indexed attribute.

    Meilisearch filters compare exactly — `tags = "apt*"` matches a tag literally
    named `apt*`, which is nothing. The builder resolves the pattern against the
    attribute's facet distribution and expands it to an OR of the values that
    actually match.
    """

    attribute: str
    pattern: str
    negated: bool = False


@dataclass
class SearchBranch:
    """One Meilisearch search: a query string plus the filters that apply to it.

    Meilisearch has no OR operator *inside* a query string, so `(a OR b) AND c`
    cannot be one search. The planner expands the index-facing half of the
    expression into disjunctive normal form and the builder unions one search
    per branch, which is what keeps the grouping the user typed.
    """

    query: str = ""
    filters: list[str] = field(default_factory=list)


@dataclass
class ExecutionPlan:
    """The result of planning a parsed query."""

    # The full-text query string for Meilisearch (bare text terms + text-field values)
    meili_query: str = ""
    # Meilisearch filter clauses
    meili_filters: list[str] = field(default_factory=list)
    # Sort parameter extracted from sort: field
    sort: str = "relevance"
    # Entity sub-plans grouped by entity type root
    entity_nodes: list[EntityFilterGroup] = field(default_factory=list)
    # Whether entity results should constrain entry results (AND) or be independent (OR)
    join_mode: str = "AND"
    # All parsed filters for chip rendering
    parsed_filters: list[ParsedFilter] = field(default_factory=list)
    # Whether this plan has any entity queries
    has_entity_queries: bool = False
    # Whether this plan has any entry queries
    has_entry_queries: bool = False
    # Alternative meili queries for OR between text terms (each is a separate search)
    meili_query_alternatives: list[str] = field(default_factory=list)
    # Pending feed name filters that need DB resolution to feed_ids
    pending_feed_filters: list[PendingFeedFilter] = field(default_factory=list)
    # Filters answered from Postgres (categories, signals, feed ratings)
    pending_entry_filters: list[PendingEntryFilter] = field(default_factory=list)
    # Entry IDs these resolved to; None means "no entry-scoped filter applied"
    db_entry_ids: set[str] | None = None
    # Entry IDs a negated Postgres filter excluded
    db_excluded_ids: set[str] = field(default_factory=set)
    # Wildcard filters on indexed attributes, resolved against facet values
    pending_facet_filters: list[PendingFacetFilter] = field(default_factory=list)
    # One entry per disjunct of the index-facing expression. Single-branch plans
    # are the common case and mirror meili_query/meili_filters exactly.
    branches: list[SearchBranch] = field(default_factory=list)
    # Fields that parsed as `name:value` but are not in the vocabulary. Their
    # values fall back to free text; the API returns these so the UI can say so.
    unknown_fields: list[str] = field(default_factory=list)
    # Who is searching. `tag:` also matches their own personal tag assignments
    # (`user_tags`); without a viewer it matches global tags only.
    viewer_id: str | None = None
    # Internal counter for allocating OR-group IDs during planning
    _or_counter: int = field(default=0, repr=False)
    # Set when anything asks for entries at all — including a bare/negated text
    # term that contributes no query string. Without it, `NOT ransomware` and an
    # empty query planned to "no entry search" and returned zero rows.
    _entry_intent: bool = field(default=False, repr=False)


def resolve_pending_filter(plan: ExecutionPlan, token: str, clause: str) -> None:
    """Swap a placeholder for the clause Postgres just resolved.

    Substituting in place is what lets a deferred filter take part in an OR:
    the branch expansion already put the token inside whatever `(a OR b)` the
    user wrote, so the resolved clause inherits that structure instead of being
    ANDed onto everything.
    """
    plan.meili_filters = [f.replace(token, clause) for f in plan.meili_filters]
    for branch in plan.branches:
        branch.filters = [f.replace(token, clause) for f in branch.filters]


def add_global_filter(plan: ExecutionPlan, clause: str) -> None:
    """AND a filter clause onto every branch of a plan.

    Feed names, categories and feed ratings are resolved against Postgres after
    the plan is built, so they cannot be planned into the branches up front.
    Appending them to `meili_filters` alone would leave a multi-branch query
    unfiltered, and a single-branch one filtered by nothing at all.
    """
    plan.meili_filters.append(clause)
    for branch in plan.branches:
        branch.filters.append(clause)


@dataclass
class EntityFilterGroup:
    """A group of filters for one entity type query."""

    entity_type: str  # "cve", "ttp", "threat_actor", "malware", "rule"
    conditions: list[EntityCondition] = field(default_factory=list)


@dataclass
class EntityCondition:
    """A single condition for an entity query."""

    field: str  # full field name e.g. "ioc.type", "cve.severity"
    value: str
    exact: bool = False
    negated: bool = False
    op: str = "contains"  # "contains", "eq", "gt", "lt", "gte", "lte", "range"
    # Conditions sharing an or_group ID are OR'd together; None means AND with the rest
    or_group: int | None = None


# ── Planner ──────────────────────────────────────────────


def build_execution_plan(ast: ASTNode, viewer_id: object = None) -> ExecutionPlan:
    """Walk the AST and build an execution plan.

    `viewer_id` is the searching user's id (UUID or str); it lets `tag:` see
    their personal tag assignments.
    """
    plan = ExecutionPlan(viewer_id=str(viewer_id) if viewer_id else None)

    # The walk owns everything Meilisearch cannot express on its own: entity
    # sub-plans, Postgres-backed filters, sort, and the chips the UI renders.
    _walk_plan(ast, plan, negated=False)

    # The index-facing half is planned separately, in disjunctive normal form,
    # because `(a OR b) AND c` needs one search per disjunct. Flattening it into
    # a single query string is what silently turned that grouping into a union.
    global_filters = list(plan.meili_filters)
    plan.branches = _build_branches(ast, plan)
    for branch in plan.branches:
        branch.filters = global_filters + branch.filters
    plan.meili_query = plan.branches[0].query
    plan.meili_filters = list(plan.branches[0].filters)
    plan.meili_query_alternatives = [b.query for b in plan.branches[1:]]

    plan.has_entity_queries = len(plan.entity_nodes) > 0
    plan.has_entry_queries = (
        # A text node was present even if it contributed no query string — an
        # empty query and `NOT ransomware` both mean "entries, unconstrained".
        plan._entry_intent
        or any(b.query.strip() or b.filters for b in plan.branches)
        # Postgres-backed filters and the radar sort ask for entries too.
        or len(plan.pending_entry_filters) > 0
        or len(plan.pending_feed_filters) > 0
        or len(plan.pending_facet_filters) > 0
        or plan.sort == "radar"
    )

    return plan


# A single OR nested inside ANDs multiplies the branch count, and each branch is
# one round trip to the index. Past this, collapse to a single flattened AND
# rather than firing dozens of searches for one query box.
_MAX_BRANCHES = 16

# Entry fields whose value is matched by the index's own full-text search rather
# than by a filter clause.
_TEXT_ENTRY_FIELDS = frozenset({"title", "content", "author"})

# Entry fields that become a plain Meilisearch filter on an indexed attribute.
_FILTER_ENTRY_FIELDS = {"tag": "tags", "type": "feed_type", "media": "media_type", "lang": "language"}

# Entry fields answered from Postgres that still end up as a Meilisearch clause
# (they all narrow to a set of feed IDs). Because the clause is a filter string
# in the end, these can take part in an OR — they just need a placeholder until
# the lookup has run. The entry-scoped kinds (`signal:`, `url:`,
# `is:translated`, `is:image`) resolve to entry IDs instead and cannot.
_DEFERRED_FILTER_FIELDS = frozenset({"feed", "category", "feed.reliability", "feed.timeliness", "feed.relevance"})


# `is:` values that are a plain boolean on the index. Planned as branch filters
# so they can be a side of an OR, the same as `tag:` and `type:`.
_IS_INDEX_FLAGS = {
    "starred": ("is_starred", True),
    "unread": ("is_read", False),
    "read": ("is_read", True),
    "bookmarked": ("is_bookmarked", True),
    "noted": ("has_notes", True),
}


# Every value `is:` accepts: the index flags above, plus the three answered from
# Postgres. Public because autocomplete has to offer exactly this set — listing
# it separately is how the header came to suggest five of the eight.
IS_FILTER_VALUES: tuple[str, ...] = (*_IS_INDEX_FLAGS, "muted", "translated", "image")


def _pending_token(index: int) -> str:
    """Placeholder standing in for a not-yet-resolved filter clause.

    Wrapped in control characters so it cannot collide with anything the parser
    can produce from user input.
    """
    return f"\x00pending:{index}\x00"


def _text_term(value: str, *, phrase: bool) -> str:
    """Format one free-text term for the index.

    A trailing `*` is dropped: Meilisearch has no wildcard operator and treats
    the character as a separator, which cancelled the automatic prefix match on
    the final term — so `ransom*` matched *fewer* entries than `ransom`. Removing
    it restores the prefix behaviour the wildcard was reaching for.
    """
    if phrase:
        return f'"{value}"'
    stripped = value.rstrip("*")
    return stripped or value


def _field_text_term(node: FieldNode) -> str | None:
    """The full-text term a field node contributes, if it contributes one."""
    if node.field_name in _TEXT_ENTRY_FIELDS:
        return _text_term(node.value, phrase=node.exact)
    # An unrecognised field is not an error — the docs have always said its value
    # falls back to free text. Dropping it entirely is what made a typo like
    # `titel:ransomware` return zero rows with no explanation.
    if node.value and classify_field(node.field_name) == "entry" and node.field_name not in ENTRY_FIELDS:
        return _text_term(node.value, phrase=node.exact)
    return None


def _build_branches(node: ASTNode, plan: ExecutionPlan) -> list[SearchBranch]:
    """Expand the index-facing expression into one branch per disjunct."""
    disjuncts = _branch_dnf(node, plan, negated=False)

    # Collapse branches that share a query string: `tag:a OR tag:b` is one
    # search with an OR filter, not two searches. Meilisearch filters *do*
    # support OR — only the query string does not.
    merged: dict[str, list[list[str]]] = {}
    for terms, filters in disjuncts:
        merged.setdefault(" ".join(terms), []).append(filters)

    branches: list[SearchBranch] = []
    for query, filter_sets in merged.items():
        non_empty = [fs for fs in filter_sets if fs]
        if len(non_empty) != len(filter_sets):
            # One disjunct carried no filter, so the union is unfiltered.
            branches.append(SearchBranch(query=query, filters=[]))
        elif len(non_empty) == 1:
            branches.append(SearchBranch(query=query, filters=non_empty[0]))
        else:
            clauses = [f"({' AND '.join(fs)})" if len(fs) > 1 else fs[0] for fs in non_empty]
            branches.append(SearchBranch(query=query, filters=[f"({' OR '.join(clauses)})"]))

    return branches or [SearchBranch()]


def meili_quote(value: str) -> str:
    """`value` as a double-quoted Meilisearch filter string literal.

    Backslash and the double quote are escaped (Meilisearch's filter grammar
    accepts `\\"` inside a quoted string). Without this, a value from a request
    parameter can close the quote and append its own clause — with `user_tags`
    filterable, that would let one user query another's private assignments.
    """
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def tag_filter_clause(name: str, viewer_id: str | None) -> str:
    """The index filter for "this entry carries tag `name`" as `viewer_id` sees it.

    A global tag's name sits in the document's `tags` field. A personal
    assignment is indexed as `"<user_id>:<name>"` in `user_tags` (format:
    `app.services.entry_tags.personal_tag_token`), so the viewer's own token is
    ORed in; nobody else's can match. Without a viewer, global tags only.
    """
    clause = f"tags = {meili_quote(name)}"
    if viewer_id:
        clause = f"({clause} OR user_tags = {meili_quote(f'{viewer_id}:{name}')})"
    return clause


def _branch_dnf(node: ASTNode, plan: ExecutionPlan, *, negated: bool) -> list[tuple[list[str], list[str]]]:
    """Disjunctive normal form of the index-facing expression.

    Each disjunct is (full-text terms, filter clauses), both of which are ANDed
    within the disjunct. `([], [])` means "no index-side constraint", which is
    what a pure entity filter and a negated free-text term both reduce to.
    """
    if isinstance(node, TextNode):
        if not node.value or negated:
            # Negated free text is dropped: Meilisearch (v1.6) cannot negate
            # query terms, and adding the term positively would be worse.
            return [([], [])]
        return [([_text_term(node.value, phrase=node.phrase)], [])]

    if isinstance(node, FieldNode):
        term = _field_text_term(node)
        if term is not None:
            # Meilisearch cannot negate query terms, so a negated text field
            # drops to "unconstrained" rather than matching the wrong half.
            return [([], [])] if negated else [([term], [])]
        attribute = _FILTER_ENTRY_FIELDS.get(node.field_name)
        if attribute and "*" not in node.value:
            clause = (
                tag_filter_clause(node.value, plan.viewer_id)
                if attribute == "tags"
                else f'{attribute} = "{node.value}"'
            )
            return [([], [f"NOT {clause}" if negated else clause])]

        if node.field_name == "is":
            flag = _IS_INDEX_FLAGS.get(node.value)
            if flag:
                attribute, expected = flag
                return [([], [f"{attribute} = {str(expected != negated).lower()}"])]
            if node.value != "muted":
                # `is:translated` / `is:image` resolve to entry IDs; the walk
                # takes those, with an or_group to union them by.
                return [([], [])]

        if node.field_name in _DEFERRED_FILTER_FIELDS or node.field_name == "is":
            # Registered here rather than in the walk so it lands in the right
            # place in the boolean structure. The token is swapped for the real
            # clause once Postgres has resolved it.
            token = _pending_token(len(plan.pending_feed_filters) + len(plan.pending_entry_filters))
            if node.field_name == "feed":
                plan.pending_feed_filters.append(
                    PendingFeedFilter(value=node.value, exact=node.exact, negated=negated, token=token)
                )
            else:
                # `is:muted` narrows to feed IDs like `category:` does, so it is
                # a filter clause in the end and can hold a place in a branch.
                kind = "is.muted" if node.field_name == "is" else node.field_name
                plan.pending_entry_filters.append(
                    PendingEntryFilter(kind=kind, value=node.value, negated=negated, token=token)
                )
            return [([], [token])]

        # Wildcards on these attributes need the facet values to expand against,
        # which only the builder can see; entity fields and the entry-scoped
        # Postgres filters are the walk's business. No index-side constraint.
        return [([], [])]

    if isinstance(node, NotNode):
        return _branch_dnf(node.child, plan, negated=not negated)

    if isinstance(node, BoolNode):
        # De Morgan: a negated OR distributes as an AND of negations.
        op = node.op
        if negated:
            op = "AND" if op == "OR" else "OR"
        children = [_branch_dnf(c, plan, negated=negated) for c in node.children]

        if op == "OR":
            disjuncts = [d for child in children for d in child]
            # An unconstrained disjunct swallows the union: `ransomware OR
            # threat_actor:APT29` must not filter out the actor's entries.
            if any(not terms and not filters for terms, filters in disjuncts):
                return [([], [])]
            return disjuncts

        out: list[tuple[list[str], list[str]]] = [([], [])]
        for child in children:
            out = [(t1 + t2, f1 + f2) for t1, f1 in out for t2, f2 in child]
            if len(out) > _MAX_BRANCHES:
                terms = list(dict.fromkeys(t for ts, _ in out for t in ts))
                filters = list(dict.fromkeys(f for _, fs in out for f in fs))
                return [(terms, filters)]
        return out

    return [([], [])]


def _walk_plan(
    node: ASTNode,
    plan: ExecutionPlan,
    *,
    negated: bool,
    or_group: int | None = None,
) -> None:
    if isinstance(node, TextNode):
        # The query string itself is built by _build_branches; all this pass has
        # to record is that entries were asked for at all, which stays true for
        # an empty or negated term that contributes no text.
        plan._entry_intent = True

    elif isinstance(node, FieldNode):
        classification = classify_field(node.field_name)

        # Build ParsedFilter for chip rendering
        raw = f"{node.field_name}:{node.value}" if not node.exact else f'{node.field_name}:"{node.value}"'
        if negated:
            raw = f"NOT {raw}"
        plan.parsed_filters.append(
            ParsedFilter(
                field=node.field_name,
                value=node.value,
                exact=node.exact,
                negated=negated,
                raw=raw,
            )
        )

        if classification == "meta":
            _handle_meta(node, plan)
        elif classification == "entry":
            _handle_entry_field(node, plan, negated=negated, or_group=or_group)
        elif classification == "entity":
            _handle_entity_field(node, plan, negated=negated, or_group=or_group)

    elif isinstance(node, BoolNode):
        # Check if this is a top-level OR between entry and entity nodes
        if node.op == "OR":
            has_entry = any(_subtree_has_class(c, "entry") for c in node.children)
            has_entity = any(_subtree_has_class(c, "entity") for c in node.children)
            if has_entry and has_entity:
                plan.join_mode = "OR"

        # OR between filters: preserve the disjunction instead of flattening to AND.
        # (A negated OR falls through: NOT (a OR b) = NOT a AND NOT b by De Morgan.)
        if node.op == "OR" and not negated:
            # Reuse the parent's OR group for nested ORs (a OR (b OR c) is flat)
            if or_group is not None:
                group_id = or_group
            else:
                plan._or_counter += 1
                group_id = plan._or_counter

            or_clauses: list[str] = []
            for child in node.children:
                # AND sub-expressions can't join a flat entity OR group; their
                # entity conditions keep AND semantics (documented limitation).
                child_group = group_id if _entity_or_groupable(child) else None
                before = len(plan.meili_filters)
                _walk_plan(child, plan, negated=negated, or_group=child_group)
                new_clauses = plan.meili_filters[before:]
                if new_clauses:
                    # Pull this child's Meilisearch clauses out and OR them with
                    # its siblings' clauses instead of the default AND join.
                    del plan.meili_filters[before:]
                    if len(new_clauses) == 1:
                        or_clauses.append(new_clauses[0])
                    else:
                        or_clauses.append("(" + " AND ".join(new_clauses) + ")")
            if or_clauses:
                if len(or_clauses) == 1:
                    plan.meili_filters.append(or_clauses[0])
                else:
                    plan.meili_filters.append("(" + " OR ".join(or_clauses) + ")")
            return

        for child in node.children:
            _walk_plan(child, plan, negated=negated, or_group=or_group)

    elif isinstance(node, NotNode):
        _walk_plan(node.child, plan, negated=not negated, or_group=or_group)


def _entity_or_groupable(node: ASTNode) -> bool:
    """Whether an OR-child's conditions can join a flat OR group.

    Applies to entity conditions and to the Postgres-backed entry filters, both
    of which are held as flat lists rather than as a tree. An AND sub-expression
    inside an OR (e.g. ``(actor:A AND actor.country:x) OR actor:B``) cannot be
    represented that way, so it keeps the legacy AND semantics.
    """
    if isinstance(node, NotNode):
        return _entity_or_groupable(node.child)
    if isinstance(node, BoolNode):
        return node.op == "OR"
    return True


def _subtree_has_class(node: ASTNode, classification: str) -> bool:
    """Check if a subtree contains any nodes of a given classification."""
    if isinstance(node, FieldNode):
        return classify_field(node.field_name) == classification
    if isinstance(node, TextNode):
        return classification == "entry"
    if isinstance(node, BoolNode):
        return any(_subtree_has_class(c, classification) for c in node.children)
    if isinstance(node, NotNode):
        return _subtree_has_class(node.child, classification)
    return False


# "radar" is the signal engine's priority_score ordering — the same ranking the
# Priority Queue uses. It is served from Postgres, not the search index, which
# has no such attribute to sort on.
VALID_SORTS = frozenset({"relevance", "newest", "oldest", "title_asc", "title_desc", "shortest", "longest", "radar"})


def _handle_meta(node: FieldNode, plan: ExecutionPlan) -> None:
    # `sort:newest` on its own is a request to browse, not a no-op: without the
    # intent flag it planned to "no entry search" and returned nothing.
    plan._entry_intent = True
    if node.field_name == "sort" and node.value in VALID_SORTS:
        plan.sort = node.value


def _handle_entry_field(
    node: FieldNode,
    plan: ExecutionPlan,
    *,
    negated: bool,
    or_group: int | None = None,
) -> None:
    """Resolve entry field nodes that the branch expansion does not own.

    The full-text fields and the four exact-match attribute filters are planned
    by `_build_branches`, because they are the parts an OR has to split on. What
    is left here is everything that ANDs globally: Postgres-backed filters, the
    numeric and date ranges, and the wildcard forms of the attribute filters.
    """
    f = node.field_name
    v = node.value
    plan._entry_intent = True

    if f in _TEXT_ENTRY_FIELDS:
        return  # planned as a branch query term

    if f in _FILTER_ENTRY_FIELDS:
        if "*" in v:
            # `tags = "apt*"` compares exactly and matches a tag literally named
            # `apt*`. Hand the pattern to the builder, which can expand it
            # against the attribute's real facet values.
            plan.pending_facet_filters.append(
                PendingFacetFilter(attribute=_FILTER_ENTRY_FIELDS[f], pattern=v, negated=negated)
            )
        return  # exact form is planned as a branch filter

    if f in _DEFERRED_FILTER_FIELDS:
        return  # registered by the branch expansion, which knows where it sits

    if f in ("signal", "url"):
        # Entry-scoped: resolves to a set of entry IDs, which cannot live in a
        # Meilisearch filter string. The OR group travels with it so the sets
        # can be unioned at resolution time instead of always intersecting.
        plan.pending_entry_filters.append(PendingEntryFilter(kind=f, value=v, negated=negated, or_group=or_group))

    elif f == "words":
        _handle_words_filter(v, plan)

    elif f == "is":
        _handle_is_filter(v, plan, negated=negated, or_group=or_group)

    elif f == "date":
        _handle_date_filter(v, plan)

    else:
        # Not a field at all — `_build_branches` searches the value as free text;
        # record the name so the response can tell the user it was not a filter.
        if f not in plan.unknown_fields:
            plan.unknown_fields.append(f)


def _handle_is_filter(value: str, plan: ExecutionPlan, *, negated: bool, or_group: int | None = None) -> None:
    """Take the `is:` values that resolve to a set of entry IDs.

    The index-side flags and `is:muted` are planned as branch filters instead —
    see `_branch_dnf` — so that they can sit on one side of an OR.
    """
    if value in ("translated", "image"):
        plan.pending_entry_filters.append(
            PendingEntryFilter(kind=f"is.{value}", value=value, negated=negated, or_group=or_group)
        )
        plan.has_entry_queries = True


def _handle_words_filter(value: str, plan: ExecutionPlan) -> None:
    """`words:>1500` — word_count is indexed already, it just was not filterable."""

    def num(raw: str) -> int | None:
        try:
            return int(float(raw))
        except (TypeError, ValueError):
            return None

    if ".." in value:
        low, _, high = value.partition("..")
        if (lo := num(low)) is not None:
            plan.meili_filters.append(f"word_count >= {lo}")
        if (hi := num(high)) is not None:
            plan.meili_filters.append(f"word_count <= {hi}")
        return
    for prefix, op in ((">=", ">="), ("<=", "<="), (">", ">"), ("<", "<")):
        if value.startswith(prefix):
            if (n := num(value[len(prefix) :])) is not None:
                plan.meili_filters.append(f"word_count {op} {n}")
            return
    if (n := num(value)) is not None:
        plan.meili_filters.append(f"word_count = {n}")


def _handle_date_filter(value: str, plan: ExecutionPlan) -> None:
    """Convert `date:` comparisons to Meilisearch timestamp filters.

    Every accepted form names a *span*, not an instant: `2026` is a year,
    `2026-08` is a month, `2026-08-15` is a day. Comparisons are resolved
    against the right end of that span, so `date:2026-08` covers all of August
    (it used to match only the 1st) and `date:a..b` includes every entry
    published on `b` (the last day used to be cut off).
    """
    from calendar import monthrange
    from datetime import datetime

    def span(date_str: str) -> tuple[float, float] | None:
        """(inclusive start, exclusive end) timestamps for a date literal."""
        raw = date_str.strip()
        try:
            if len(raw) == 4:
                start = datetime(int(raw), 1, 1, tzinfo=UTC)
                end = datetime(int(raw) + 1, 1, 1, tzinfo=UTC)
            elif len(raw) == 7:
                dt = datetime.strptime(raw, "%Y-%m").replace(tzinfo=UTC)
                end_day = monthrange(dt.year, dt.month)[1]
                start = dt
                end = dt.replace(day=end_day) + timedelta(days=1)
            else:
                start = datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=UTC)
                end = start + timedelta(days=1)
        except ValueError:
            return None
        return start.timestamp(), end.timestamp()

    if ".." in value:
        low, _, high = value.partition("..")
        if (lo := span(low)) is not None:
            plan.meili_filters.append(f"published_at >= {lo[0]}")
        if (hi := span(high)) is not None:
            # Inclusive of the whole final day/month/year the user named.
            plan.meili_filters.append(f"published_at < {hi[1]}")
        return

    for prefix in (">=", "<=", ">", "<"):
        if value.startswith(prefix):
            bounds = span(value[len(prefix) :])
            if bounds is None:
                return
            lo, hi = bounds
            if prefix == ">=":
                plan.meili_filters.append(f"published_at >= {lo}")
            elif prefix == ">":
                # Strictly after the named span, not merely after its start.
                plan.meili_filters.append(f"published_at >= {hi}")
            elif prefix == "<=":
                plan.meili_filters.append(f"published_at < {hi}")
            else:
                plan.meili_filters.append(f"published_at < {lo}")
            return

    if (bounds := span(value)) is not None:
        plan.meili_filters.append(f"published_at >= {bounds[0]}")
        plan.meili_filters.append(f"published_at < {bounds[1]}")


def _handle_entity_field(
    node: FieldNode,
    plan: ExecutionPlan,
    *,
    negated: bool,
    or_group: int | None = None,
) -> None:
    """Route entity field to the appropriate entity filter group."""
    root = node.field_name.split(".")[0]
    entity_type = root

    # Parse operator from value
    op, clean_value = _parse_value_operator(node.value)
    if node.exact:
        op = "eq"

    condition = EntityCondition(
        field=node.field_name,
        value=clean_value,
        exact=node.exact,
        negated=negated,
        op=op,
        or_group=or_group,
    )

    # Find or create entity group
    group = None
    for g in plan.entity_nodes:
        if g.entity_type == entity_type:
            group = g
            break
    if group is None:
        group = EntityFilterGroup(entity_type=entity_type)
        plan.entity_nodes.append(group)

    group.conditions.append(condition)


def _parse_value_operator(value: str) -> tuple[str, str]:
    """Extract comparison operator from value string."""
    if ".." in value:
        return "range", value
    if value.startswith(">="):
        return "gte", value[2:]
    if value.startswith(">"):
        return "gt", value[1:]
    if value.startswith("<="):
        return "lte", value[2:]
    if value.startswith("<"):
        return "lt", value[1:]
    if "*" in value:
        return "contains", value
    return "eq", value


def to_sql_pattern(value: str) -> str:
    """Turn a user value into an ILIKE pattern.

    `*` is the wildcard everywhere in the language, so it has to survive the trip
    into SQL; without this the `*` was matched literally and these fields
    returned nothing at all. Values with no wildcard keep their substring
    behaviour. `%` and `_` are escaped so a CVE id or a URL cannot smuggle in a
    pattern of its own.
    """
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped.replace("*", "%") if "*" in value else f"%{escaped}%"


# ── Feed filter resolution ──────────────────────────────


async def resolve_deferred_filters(db, plan: ExecutionPlan) -> None:
    """Run every Postgres-backed filter resolution this plan is waiting on.

    Both resolvers or neither: a plan that has had only one of them run still
    holds unresolved placeholders, and the clauses they stand for are simply
    lost. Call this rather than the two functions individually.
    """
    if plan.pending_feed_filters:
        await resolve_feed_filters(db, plan)
    if plan.pending_entry_filters:
        await resolve_entry_filters(db, plan)


async def resolve_feed_filters(db, plan: ExecutionPlan) -> None:
    """Resolve pending feed name filters to Meilisearch feed_id filter clauses.

    Requires an async DB session to look up feed IDs by title.
    Mutates the plan in place: appends to meili_filters and sets has_entry_queries.
    """
    from sqlalchemy import select

    from app.models.feed import Feed

    for pf in plan.pending_feed_filters:
        stmt = select(Feed.id).where(Feed.title.ilike(to_sql_pattern(pf.value), escape="\\"))
        result = await db.execute(stmt)
        feed_ids = [str(row[0]) for row in result.all()]

        if feed_ids:
            id_parts = " OR ".join(f'feed_id = "{fid}"' for fid in feed_ids)
            clause = f"({id_parts})" if len(feed_ids) > 1 else f'feed_id = "{feed_ids[0]}"'
            if pf.negated:
                clause = f"NOT ({clause})"
        elif pf.negated:
            # Nothing to exclude — the filter is satisfied by every entry.
            clause = 'NOT feed_id = "no-match"'
        else:
            clause = 'feed_id = "no-match"'
        resolve_pending_filter(plan, pf.token, clause)

    plan.has_entry_queries = True


# Feed-scoped kinds narrow to feed IDs; there are only a few hundred feeds, so
# they become ordinary Meilisearch filter clauses.
_FEED_SCOPED = {"category", "is.muted", "feed.reliability", "feed.timeliness", "feed.relevance"}


async def resolve_entry_filters(db, plan: ExecutionPlan) -> None:
    """Answer the Postgres-backed entry filters and fold them into the plan.

    Feed-scoped kinds append `feed_id` clauses. Entry-scoped kinds accumulate an
    entry-ID set in `plan.db_entry_ids`, which the search endpoint intersects
    with any entity join before running the query — the same mechanism entity
    filters already use, so a filter matching 17,000 entries costs one IN list
    rather than 17,000 OR clauses in a Meilisearch filter string.
    """
    if not plan.pending_entry_filters:
        return

    from sqlalchemy import and_, func, select

    from app.models.category import Category
    from app.models.entry import Entry
    from app.models.entry_signal import EntrySignal
    from app.models.feed import Feed

    resolved: list[tuple[PendingEntryFilter, set[str]]] = []

    for pf in plan.pending_entry_filters:
        kind, value = pf.kind, pf.value

        if kind in _FEED_SCOPED:
            if kind == "category":
                stmt = (
                    select(Feed.id)
                    .join(Category, Feed.category_id == Category.id)
                    .where(Category.name.ilike(to_sql_pattern(value), escape="\\"))
                )
            elif kind == "is.muted":
                stmt = select(Feed.id).where(Feed.is_muted.is_(True))
            else:
                # Source ratings are Admiralty-code letter grades (A/B/C…), not
                # numbers, so this is an equality match on the grade.
                column = getattr(Feed, f"{kind.split('.')[1]}_rating")
                stmt = select(Feed.id).where(func.upper(column) == value.upper())

            rows = await db.execute(stmt)
            feed_ids = [str(r[0]) for r in rows.all()]
            if feed_ids:
                parts = " OR ".join(f'feed_id = "{fid}"' for fid in feed_ids)
                clause = f"({parts})" if len(feed_ids) > 1 else parts
                clause = f"NOT ({clause})" if pf.negated else clause
            elif pf.negated:
                clause = 'NOT feed_id = "no-match"'
            else:
                clause = 'feed_id = "no-match"'

            if pf.token:
                resolve_pending_filter(plan, pf.token, clause)
            else:
                # `is:muted` has no placeholder — it comes from `_handle_is_filter`
                # in the walk, not from the branch expansion.
                add_global_filter(plan, clause)
            continue

        # ── Entry-scoped ──
        if kind == "signal":
            if "*" in value:
                stmt = select(EntrySignal.entry_id).where(
                    EntrySignal.signal_type.ilike(to_sql_pattern(value), escape="\\")
                )
            else:
                stmt = select(EntrySignal.entry_id).where(func.lower(EntrySignal.signal_type) == value.lower())
        elif kind == "url":
            stmt = select(Entry.id).where(Entry.url.ilike(to_sql_pattern(value), escape="\\"))
        elif kind == "is.translated":
            stmt = select(Entry.id).where(Entry.translated_at.isnot(None))
        elif kind == "is.image":
            stmt = select(Entry.id).where(and_(Entry.image_url.isnot(None), Entry.image_url != ""))
        else:
            continue

        rows = await db.execute(stmt)
        matched = {str(r[0]) for r in rows.all()}
        resolved.append((pf, matched))

    _apply_entry_id_filters(plan, resolved)
    plan.has_entry_queries = True


def _apply_entry_id_filters(plan: ExecutionPlan, resolved: list[tuple[PendingEntryFilter, set[str]]]) -> None:
    """Fold resolved entry-ID sets into the plan, honouring OR groups.

    Filters sharing an `or_group` are a disjunction and must be unioned;
    everything else intersects. Unioning is why `signal:kev_added OR
    signal:scoop` stopped returning the entries carrying *both* signals.
    """
    grouped: dict[int, list[tuple[PendingEntryFilter, set[str]]]] = {}
    for pf, matched in resolved:
        if pf.or_group is None:
            _apply_one(plan, pf.negated, matched)
        else:
            grouped.setdefault(pf.or_group, []).append((pf, matched))

    for members in grouped.values():
        positive = [m for pf, m in members if not pf.negated]
        negative = [m for pf, m in members if pf.negated]

        if not negative:
            union: set[str] = set()
            for m in positive:
                union |= m
            _apply_one(plan, False, union)
            continue

        # With a negated member the group is unbounded — `NOT a OR b` matches
        # nearly everything — but its *complement* is not, and that is exactly
        # what the exclusion set holds:
        #   ¬(P₁ ∪ … ∪ ¬N₁ ∪ … ∪ ¬Nₙ) = (N₁ ∩ … ∩ Nₙ) \ (P₁ ∪ … ∪ Pₘ)
        excluded = set(negative[0])
        for m in negative[1:]:
            excluded &= m
        for m in positive:
            excluded -= m
        _apply_one(plan, True, excluded)


def _apply_one(plan: ExecutionPlan, negated: bool, matched: set[str]) -> None:
    if negated:
        # Negation needs the complement, which is every other entry — far too
        # large to enumerate. Excluding via a Meilisearch NOT on id is equally
        # unbounded, so a negated DB filter is honoured by removing the matches
        # from any positive set and otherwise left to the endpoint, which drops
        # entries in `db_excluded_ids`.
        plan.db_excluded_ids |= matched
        return
    plan.db_entry_ids = matched if plan.db_entry_ids is None else (plan.db_entry_ids & matched)
