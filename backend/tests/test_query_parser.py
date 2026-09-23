"""Tests for the unified search query parser."""

import pytest

from app.search.query_parser import (
    BoolNode,
    FieldNode,
    NotNode,
    ParseError,
    TextNode,
    extract_filters,
    parse_query,
    tokenize,
)

# ── Tokenizer tests ───────────────────────────────────────


class TestTokenizer:
    def test_empty(self):
        tokens = tokenize("")
        assert len(tokens) == 1
        assert tokens[0].type.name == "EOF"

    def test_bare_words(self):
        tokens = tokenize("ransomware attack")
        assert tokens[0].value == "ransomware"
        assert tokens[1].value == "attack"

    def test_quoted_phrase(self):
        tokens = tokenize('"cobalt strike"')
        assert tokens[0].type.name == "PHRASE"
        assert tokens[0].value == "cobalt strike"

    def test_field_value(self):
        tokens = tokenize("ioc:192.168.1.*")
        assert tokens[0].type.name == "WORD"
        assert tokens[0].value == "ioc:192.168.1.*"

    def test_boolean_keywords(self):
        tokens = tokenize("a AND b OR NOT c")
        types = [t.type.name for t in tokens[:-1]]
        assert types == ["WORD", "AND", "WORD", "OR", "NOT", "WORD"]

    def test_parentheses(self):
        tokens = tokenize("(a OR b) AND c")
        types = [t.type.name for t in tokens[:-1]]
        assert types == ["LPAREN", "WORD", "OR", "WORD", "RPAREN", "AND", "WORD"]

    def test_unclosed_quote(self):
        tokens = tokenize('"unclosed phrase')
        assert tokens[0].type.name == "PHRASE"
        assert tokens[0].value == "unclosed phrase"

    def test_field_with_quoted_value(self):
        tokens = tokenize('title:"zero day"')
        assert tokens[0].value == "title:"
        assert tokens[1].type.name == "PHRASE"
        assert tokens[1].value == "zero day"


# ── Parser tests ──────────────────────────────────────────


class TestParser:
    def test_empty_query(self):
        node = parse_query("")
        assert isinstance(node, TextNode)
        assert node.value == ""

    def test_whitespace_only(self):
        node = parse_query("   ")
        assert isinstance(node, TextNode)
        assert node.value == ""

    def test_single_word(self):
        node = parse_query("ransomware")
        assert isinstance(node, TextNode)
        assert node.value == "ransomware"

    def test_quoted_phrase(self):
        node = parse_query('"cobalt strike beacon"')
        assert isinstance(node, TextNode)
        assert node.value == "cobalt strike beacon"
        assert node.phrase is True

    def test_bare_term_not_phrase(self):
        node = parse_query("ransomware")
        assert isinstance(node, TextNode)
        assert node.phrase is False

    def test_implicit_and(self):
        node = parse_query("ransomware attack")
        assert isinstance(node, BoolNode)
        assert node.op == "AND"
        assert len(node.children) == 2
        assert isinstance(node.children[0], TextNode)
        assert node.children[0].value == "ransomware"
        assert isinstance(node.children[1], TextNode)
        assert node.children[1].value == "attack"

    def test_explicit_and(self):
        node = parse_query("ransomware AND attack")
        assert isinstance(node, BoolNode)
        assert node.op == "AND"
        assert len(node.children) == 2

    def test_or(self):
        node = parse_query("APT28 OR APT29")
        assert isinstance(node, BoolNode)
        assert node.op == "OR"
        assert len(node.children) == 2

    def test_not(self):
        node = parse_query("NOT spam")
        assert isinstance(node, NotNode)
        assert isinstance(node.child, TextNode)
        assert node.child.value == "spam"

    def test_field_value(self):
        node = parse_query("ioc:192.168.1.100")
        assert isinstance(node, FieldNode)
        assert node.field_name == "ioc"
        assert node.value == "192.168.1.100"
        assert node.exact is False

    def test_field_wildcard(self):
        node = parse_query("ioc:192.168.*")
        assert isinstance(node, FieldNode)
        assert node.value == "192.168.*"

    def test_field_quoted_value(self):
        node = parse_query('title:"zero day"')
        assert isinstance(node, FieldNode)
        assert node.field_name == "title"
        assert node.value == "zero day"
        assert node.exact is True

    def test_field_with_dot(self):
        node = parse_query("cve.severity:critical")
        assert isinstance(node, FieldNode)
        assert node.field_name == "cve.severity"
        assert node.value == "critical"

    def test_field_range(self):
        node = parse_query("cve.cvss:>9.0")
        assert isinstance(node, FieldNode)
        assert node.field_name == "cve.cvss"
        assert node.value == ">9.0"

    def test_field_date_range(self):
        node = parse_query("date:2025-01-01..2025-06-01")
        assert isinstance(node, FieldNode)
        assert node.value == "2025-01-01..2025-06-01"

    def test_is_filter(self):
        node = parse_query("is:starred")
        assert isinstance(node, FieldNode)
        assert node.field_name == "is"
        assert node.value == "starred"

    def test_sort_meta(self):
        node = parse_query("sort:newest")
        assert isinstance(node, FieldNode)
        assert node.field_name == "sort"
        assert node.value == "newest"

    def test_grouped_or(self):
        node = parse_query("(actor:APT28 OR actor:APT29) AND ttp.tactic:initial-access")
        assert isinstance(node, BoolNode)
        assert node.op == "AND"
        assert len(node.children) == 2
        group = node.children[0]
        assert isinstance(group, BoolNode)
        assert group.op == "OR"
        assert len(group.children) == 2
        assert isinstance(group.children[0], FieldNode)
        assert group.children[0].field_name == "actor"
        assert group.children[0].value == "APT28"

    def test_complex_mixed_query(self):
        node = parse_query("ransomware AND actor:LockBit AND is:unread")
        assert isinstance(node, BoolNode)
        assert node.op == "AND"
        assert len(node.children) == 3
        assert isinstance(node.children[0], TextNode)
        assert node.children[0].value == "ransomware"
        assert isinstance(node.children[1], FieldNode)
        assert node.children[1].field_name == "actor"
        assert isinstance(node.children[2], FieldNode)
        assert node.children[2].field_name == "is"

    def test_not_with_field(self):
        node = parse_query("NOT is:read")
        assert isinstance(node, NotNode)
        child = node.child
        assert isinstance(child, FieldNode)
        assert child.field_name == "is"
        assert child.value == "read"

    def test_complex_not(self):
        node = parse_query("content:exploit NOT type:youtube")
        assert isinstance(node, BoolNode)
        assert node.op == "AND"
        assert isinstance(node.children[1], NotNode)

    def test_multiple_or_terms(self):
        node = parse_query("a OR b OR c")
        assert isinstance(node, BoolNode)
        assert node.op == "OR"
        assert len(node.children) == 3

    def test_operator_precedence(self):
        # AND binds tighter than OR: a OR b AND c => a OR (b AND c)
        node = parse_query("a OR b AND c")
        assert isinstance(node, BoolNode)
        assert node.op == "OR"
        assert isinstance(node.children[0], TextNode)
        assert isinstance(node.children[1], BoolNode)
        assert node.children[1].op == "AND"

    def test_unmatched_rparen(self):
        with pytest.raises(ParseError):
            parse_query("a)")

    def test_unmatched_lparen(self):
        with pytest.raises(ParseError):
            parse_query("(a AND b")

    def test_cve_wildcard(self):
        node = parse_query("cve:CVE-2024-*")
        assert isinstance(node, FieldNode)
        assert node.field_name == "cve"
        assert node.value == "CVE-2024-*"

    def test_ttp_wildcard(self):
        node = parse_query("ttp:T1566*")
        assert isinstance(node, FieldNode)
        assert node.value == "T1566*"

    def test_date_greater_than(self):
        node = parse_query("date:>2025-01-01")
        assert isinstance(node, FieldNode)
        assert node.value == ">2025-01-01"

    def test_full_example_query(self):
        q = "(actor:APT28 OR actor:APT29) AND ttp.tactic:initial-access AND date:>2025-01-01"
        node = parse_query(q)
        assert isinstance(node, BoolNode)
        assert node.op == "AND"
        assert len(node.children) == 3


# ── extract_filters tests ────────────────────────────────


class TestExtractFilters:
    def test_no_filters(self):
        node = parse_query("ransomware")
        assert extract_filters(node) == []

    def test_single_filter(self):
        node = parse_query("ioc:192.168.*")
        filters = extract_filters(node)
        assert len(filters) == 1
        assert filters[0]["field"] == "ioc"
        assert filters[0]["value"] == "192.168.*"
        assert filters[0]["negated"] is False

    def test_negated_filter(self):
        node = parse_query("NOT is:read")
        filters = extract_filters(node)
        assert len(filters) == 1
        assert filters[0]["field"] == "is"
        assert filters[0]["value"] == "read"
        assert filters[0]["negated"] is True

    def test_mixed_query_filters(self):
        node = parse_query("ransomware AND actor:APT29 AND is:starred")
        filters = extract_filters(node)
        assert len(filters) == 2
        fields = {f["field"] for f in filters}
        assert fields == {"actor", "is"}

    def test_nested_or_filters(self):
        node = parse_query("(actor:APT28 OR actor:APT29) AND cve.severity:critical")
        filters = extract_filters(node)
        assert len(filters) == 3
        actors = [f for f in filters if f["field"] == "actor"]
        assert len(actors) == 2

    def test_double_negation(self):
        node = parse_query("NOT NOT is:starred")
        filters = extract_filters(node)
        assert len(filters) == 1
        assert filters[0]["negated"] is False  # double NOT cancels out

    def test_exact_filter(self):
        node = parse_query('title:"zero day"')
        filters = extract_filters(node)
        assert filters[0]["exact"] is True
        assert filters[0]["value"] == "zero day"


class TestCaseInsensitiveKeywords:
    """Lowercase `not` used to tokenize as the search word "not" while leaving
    the filter it was meant to negate in place *positively* — the query did the
    opposite of what it said."""

    def test_lowercase_not_negates(self):
        ast = parse_query("not tag:noise")
        assert isinstance(ast, NotNode)
        assert isinstance(ast.child, FieldNode)
        assert ast.child.field_name == "tag"

    def test_mixed_case_not_negates(self):
        assert isinstance(parse_query("Not tag:noise"), NotNode)

    def test_lowercase_and_is_an_operator(self):
        ast = parse_query("ransomware and phishing")
        assert isinstance(ast, BoolNode)
        assert ast.op == "AND"
        assert [c.value for c in ast.children] == ["ransomware", "phishing"]

    def test_lowercase_or_is_an_operator(self):
        ast = parse_query("APT28 or APT29")
        assert isinstance(ast, BoolNode)
        assert ast.op == "OR"

    def test_quoting_searches_the_keyword_literally(self):
        ast = parse_query('"not"')
        assert isinstance(ast, TextNode)
        assert ast.value == "not"
        assert ast.phrase is True
