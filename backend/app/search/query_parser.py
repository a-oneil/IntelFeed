"""
Recursive descent parser for IntelFeed's unified search query language.

Grammar (PEG-style):
    query       = or_expr
    or_expr     = and_expr ( "OR" and_expr )*
    and_expr    = unary ( ("AND" | <implicit>) unary )*
    unary       = "NOT" unary | atom
    atom        = "(" or_expr ")" | field_expr | phrase | term
    field_expr  = FIELD ":" value
    value       = phrase | wildcard_term
    phrase      = '"' [^"]* '"'
    term        = [^ "()]+

Supports:
    - field:value syntax (e.g. threat_actor:APT29, cve.severity:critical)
    - Wildcards (*) in values
    - Boolean operators: AND, OR, NOT (case-insensitive)
    - Quoted phrases: "exact match"
    - Parenthetical grouping: (a OR b) AND c
    - Range operators in values: >9.0, >=2025-01-01, 2025-01..2025-06
    - Implicit AND between adjacent terms
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

# ── AST Nodes ──────────────────────────────────────────────


@dataclass
class TextNode:
    """Bare text for full-text search."""

    value: str
    phrase: bool = False  # True if value was a quoted phrase


@dataclass
class FieldNode:
    """field:value expression."""

    field_name: str
    value: str
    exact: bool = False  # True if value was quoted


@dataclass
class BoolNode:
    """Boolean AND/OR."""

    op: str  # "AND" or "OR"
    children: list[ASTNode] = field(default_factory=list)


@dataclass
class NotNode:
    """Negation."""

    child: ASTNode


ASTNode = TextNode | FieldNode | BoolNode | NotNode


# ── Tokenizer ──────────────────────────────────────────────


class TokenType(Enum):
    WORD = auto()  # any non-special text (may contain : for field:value)
    PHRASE = auto()  # "quoted text"
    LPAREN = auto()  # (
    RPAREN = auto()  # )
    AND = auto()  # AND
    OR = auto()  # OR
    NOT = auto()  # NOT
    EOF = auto()


@dataclass
class Token:
    type: TokenType
    value: str
    pos: int  # character position in original query


def tokenize(query: str) -> list[Token]:
    """Tokenize query string into a list of tokens."""
    tokens: list[Token] = []
    i = 0
    n = len(query)

    while i < n:
        # Skip whitespace
        if query[i].isspace():
            i += 1
            continue

        # Parentheses
        if query[i] == "(":
            tokens.append(Token(TokenType.LPAREN, "(", i))
            i += 1
            continue
        if query[i] == ")":
            tokens.append(Token(TokenType.RPAREN, ")", i))
            i += 1
            continue

        # Quoted phrase
        if query[i] == '"':
            start = i
            i += 1
            while i < n and query[i] != '"':
                i += 1
            phrase_text = query[start + 1 : i]
            if i < n:
                i += 1  # skip closing quote
            tokens.append(Token(TokenType.PHRASE, phrase_text, start))
            continue

        # Word (may include field:value, wildcards, ranges)
        start = i
        while i < n and not query[i].isspace() and query[i] not in '()"':
            i += 1
        word = query[start:i]

        # Classify keywords. Matching is case-insensitive: a lowercase `not`
        # used to tokenize as the search word "not" *and* leave the filter it
        # was meant to negate in place positively, so `not tag:noise` quietly
        # returned the opposite of what it says. Quote the word to search for
        # it literally ("and", "not").
        upper = word.upper()
        if upper == "AND":
            tokens.append(Token(TokenType.AND, word, start))
        elif upper == "OR":
            tokens.append(Token(TokenType.OR, word, start))
        elif upper == "NOT":
            tokens.append(Token(TokenType.NOT, word, start))
        else:
            tokens.append(Token(TokenType.WORD, word, start))

    tokens.append(Token(TokenType.EOF, "", n))
    return tokens


# ── Parser ─────────────────────────────────────────────────


class ParseError(Exception):
    def __init__(self, message: str, pos: int = 0):
        super().__init__(message)
        self.pos = pos


class Parser:
    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Token:
        return self.tokens[self.pos]

    def advance(self) -> Token:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def expect(self, tt: TokenType) -> Token:
        tok = self.peek()
        if tok.type != tt:
            raise ParseError(f"Expected {tt.name}, got {tok.type.name} ({tok.value!r})", tok.pos)
        return self.advance()

    def parse(self) -> ASTNode:
        node = self.parse_or()
        if self.peek().type != TokenType.EOF:
            tok = self.peek()
            raise ParseError(f"Unexpected token: {tok.value!r}", tok.pos)
        return node

    def parse_or(self) -> ASTNode:
        left = self.parse_and()
        children = [left]
        while self.peek().type == TokenType.OR:
            self.advance()  # consume OR
            children.append(self.parse_and())
        if len(children) == 1:
            return children[0]
        return BoolNode(op="OR", children=children)

    def parse_and(self) -> ASTNode:
        left = self.parse_unary()
        children = [left]
        while True:
            tok = self.peek()
            if tok.type == TokenType.AND:
                self.advance()  # consume AND
                children.append(self.parse_unary())
            elif tok.type in (TokenType.WORD, TokenType.PHRASE, TokenType.LPAREN, TokenType.NOT):
                # Implicit AND
                children.append(self.parse_unary())
            else:
                break
        if len(children) == 1:
            return children[0]
        return BoolNode(op="AND", children=children)

    def parse_unary(self) -> ASTNode:
        if self.peek().type == TokenType.NOT:
            self.advance()  # consume NOT
            child = self.parse_unary()
            return NotNode(child=child)
        return self.parse_atom()

    def parse_atom(self) -> ASTNode:
        tok = self.peek()

        # Grouped expression
        if tok.type == TokenType.LPAREN:
            self.advance()  # consume (
            node = self.parse_or()
            self.expect(TokenType.RPAREN)
            return node

        # Quoted phrase (standalone, not field:value)
        if tok.type == TokenType.PHRASE:
            self.advance()
            return TextNode(value=tok.value, phrase=True)

        # Word — could be field:value or bare term
        if tok.type == TokenType.WORD:
            self.advance()
            colon_idx = _find_field_colon(tok.value)
            if colon_idx is not None:
                field_name = tok.value[:colon_idx]
                raw_value = tok.value[colon_idx + 1 :]

                # field:"quoted value" — check if next token is a phrase
                if not raw_value and self.peek().type == TokenType.PHRASE:
                    phrase_tok = self.advance()
                    return FieldNode(field_name=field_name, value=phrase_tok.value, exact=True)

                return FieldNode(field_name=field_name, value=raw_value, exact=False)

            return TextNode(value=tok.value)

        # Unexpected token
        if tok.type == TokenType.EOF:
            raise ParseError("Unexpected end of query", tok.pos)
        raise ParseError(f"Unexpected token: {tok.value!r}", tok.pos)


def _find_field_colon(word: str) -> int | None:
    """Find the colon that separates field from value, ignoring colons inside values.

    Valid field names: lowercase letters, digits, underscores, dots.
    The colon must not be the last character (field: with no value is handled separately).
    """
    for i, ch in enumerate(word):
        if ch == ":":
            field_part = word[:i]
            if field_part and all(c.isalnum() or c in "_." for c in field_part) and field_part[0].isalpha():
                return i
            return None  # not a valid field name before ':'
    return None


# ── Public API ─────────────────────────────────────────────


def parse_query(query: str) -> ASTNode:
    """Parse a query string into an AST.

    Returns a TextNode with empty value for empty/whitespace-only queries.
    """
    query = query.strip()
    if not query:
        return TextNode(value="")
    tokens = tokenize(query)
    parser = Parser(tokens)
    return parser.parse()


def extract_filters(node: ASTNode) -> list[dict]:
    """Walk AST and extract all field:value filters as dicts for chip rendering.

    Returns list of dicts: {"field": str, "value": str, "exact": bool, "negated": bool}
    """
    results: list[dict] = []
    _walk_filters(node, results, negated=False)
    return results


def _walk_filters(node: ASTNode, results: list[dict], *, negated: bool) -> None:
    if isinstance(node, FieldNode):
        results.append(
            {
                "field": node.field_name,
                "value": node.value,
                "exact": node.exact,
                "negated": negated,
            }
        )
    elif isinstance(node, BoolNode):
        for child in node.children:
            _walk_filters(child, results, negated=negated)
    elif isinstance(node, NotNode):
        _walk_filters(node.child, results, negated=not negated)
    # TextNode: no filter to extract
