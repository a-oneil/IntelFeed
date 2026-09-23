/**
 * Client-side query parser for IntelFeed's unified search query language.
 *
 * TypeScript port of backend/app/search/query_parser.py
 * Used for real-time filter chip extraction and cursor-aware autocomplete.
 */

// ── AST Node types ──────────────────────────────────────

export interface TextNode {
  type: "text";
  value: string;
  phrase?: boolean;
}

export interface FieldNode {
  type: "field";
  fieldName: string;
  value: string;
  exact: boolean;
}

export interface BoolNode {
  type: "bool";
  op: "AND" | "OR";
  children: ASTNode[];
}

export interface NotNode {
  type: "not";
  child: ASTNode;
}

export type ASTNode = TextNode | FieldNode | BoolNode | NotNode;

// ── Token types ─────────────────────────────────────────

type TokenType =
  | "WORD"
  | "PHRASE"
  | "LPAREN"
  | "RPAREN"
  | "AND"
  | "OR"
  | "NOT"
  | "EOF";

interface Token {
  type: TokenType;
  value: string;
  pos: number;
}

// ── Tokenizer ───────────────────────────────────────────

function tokenize(query: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const n = query.length;

  while (i < n) {
    if (query[i] === " " || query[i] === "\t") {
      i++;
      continue;
    }

    if (query[i] === "(") {
      tokens.push({ type: "LPAREN", value: "(", pos: i });
      i++;
      continue;
    }
    if (query[i] === ")") {
      tokens.push({ type: "RPAREN", value: ")", pos: i });
      i++;
      continue;
    }

    if (query[i] === '"') {
      const start = i;
      i++;
      while (i < n && query[i] !== '"') i++;
      const text = query.slice(start + 1, i);
      if (i < n) i++; // skip closing quote
      tokens.push({ type: "PHRASE", value: text, pos: start });
      continue;
    }

    // Word
    const start = i;
    while (i < n && query[i] !== " " && query[i] !== "\t" && !['(', ')', '"'].includes(query[i])) {
      i++;
    }
    const word = query.slice(start, i);

    if (word === "AND") tokens.push({ type: "AND", value: word, pos: start });
    else if (word === "OR") tokens.push({ type: "OR", value: word, pos: start });
    else if (word === "NOT") tokens.push({ type: "NOT", value: word, pos: start });
    else tokens.push({ type: "WORD", value: word, pos: start });
  }

  tokens.push({ type: "EOF", value: "", pos: n });
  return tokens;
}

// ── Parser ──────────────────────────────────────────────

export class ParseError extends Error {
  pos: number;
  constructor(message: string, pos: number = 0) {
    super(message);
    this.pos = pos;
  }
}

class Parser {
  private tokens: Token[];
  private pos: number = 0;

  constructor(tokens: Token[]) {
    this.tokens = tokens;
  }

  private peek(): Token {
    return this.tokens[this.pos];
  }

  private advance(): Token {
    return this.tokens[this.pos++];
  }

  private expect(type: TokenType): Token {
    const tok = this.peek();
    if (tok.type !== type) {
      throw new ParseError(`Expected ${type}, got ${tok.type} (${tok.value})`, tok.pos);
    }
    return this.advance();
  }

  parse(): ASTNode {
    const node = this.parseOr();
    if (this.peek().type !== "EOF") {
      const tok = this.peek();
      throw new ParseError(`Unexpected token: ${tok.value}`, tok.pos);
    }
    return node;
  }

  private parseOr(): ASTNode {
    const children: ASTNode[] = [this.parseAnd()];
    while (this.peek().type === "OR") {
      this.advance();
      children.push(this.parseAnd());
    }
    return children.length === 1 ? children[0] : { type: "bool", op: "OR", children };
  }

  private parseAnd(): ASTNode {
    const children: ASTNode[] = [this.parseUnary()];
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const tok = this.peek();
      if (tok.type === "AND") {
        this.advance();
        children.push(this.parseUnary());
      } else if (["WORD", "PHRASE", "LPAREN", "NOT"].includes(tok.type)) {
        // Implicit AND
        children.push(this.parseUnary());
      } else {
        break;
      }
    }
    return children.length === 1 ? children[0] : { type: "bool", op: "AND", children };
  }

  private parseUnary(): ASTNode {
    if (this.peek().type === "NOT") {
      this.advance();
      return { type: "not", child: this.parseUnary() };
    }
    return this.parseAtom();
  }

  private parseAtom(): ASTNode {
    const tok = this.peek();

    if (tok.type === "LPAREN") {
      this.advance();
      const node = this.parseOr();
      this.expect("RPAREN");
      return node;
    }

    if (tok.type === "PHRASE") {
      this.advance();
      return { type: "text", value: tok.value, phrase: true };
    }

    if (tok.type === "WORD") {
      this.advance();
      const colonIdx = findFieldColon(tok.value);
      if (colonIdx !== null) {
        const fieldName = tok.value.slice(0, colonIdx);
        const rawValue = tok.value.slice(colonIdx + 1);

        // field:"quoted value"
        if (!rawValue && this.peek().type === "PHRASE") {
          const phraseTok = this.advance();
          return { type: "field", fieldName, value: phraseTok.value, exact: true };
        }

        return { type: "field", fieldName, value: rawValue, exact: false };
      }
      return { type: "text", value: tok.value };
    }

    if (tok.type === "EOF") {
      throw new ParseError("Unexpected end of query", tok.pos);
    }
    throw new ParseError(`Unexpected token: ${tok.value}`, tok.pos);
  }
}

function findFieldColon(word: string): number | null {
  for (let i = 0; i < word.length; i++) {
    if (word[i] === ":") {
      const fieldPart = word.slice(0, i);
      if (fieldPart && /^[a-zA-Z][a-zA-Z0-9_.]*$/.test(fieldPart)) {
        return i;
      }
      return null;
    }
  }
  return null;
}

// ── Public API ──────────────────────────────────────────

/**
 * Parse a query string into an AST.
 * Returns a TextNode with empty value for empty queries.
 */
export function parseQuery(query: string): ASTNode {
  query = query.trim();
  if (!query) return { type: "text", value: "" };

  try {
    const tokens = tokenize(query);
    const parser = new Parser(tokens);
    return parser.parse();
  } catch {
    // On parse error, return as plain text
    return { type: "text", value: query };
  }
}

// ── Filter extraction ───────────────────────────────────

export interface ParsedFilter {
  field: string;
  value: string;
  exact: boolean;
  negated: boolean;
  raw: string;
}

/**
 * Extract all field:value filters from an AST for chip rendering.
 */
export function extractFilters(node: ASTNode): ParsedFilter[] {
  const results: ParsedFilter[] = [];
  walkFilters(node, results, false);
  return results;
}

function walkFilters(node: ASTNode, results: ParsedFilter[], negated: boolean): void {
  if (node.type === "field") {
    const raw = node.exact
      ? `${node.fieldName}:"${node.value}"`
      : `${node.fieldName}:${node.value}`;
    results.push({
      field: node.fieldName,
      value: node.value,
      exact: node.exact,
      negated,
      raw: negated ? `NOT ${raw}` : raw,
    });
  } else if (node.type === "bool") {
    for (const child of node.children) {
      walkFilters(child, results, negated);
    }
  } else if (node.type === "not") {
    walkFilters(node.child, results, !negated);
  }
}

// ── Cursor-aware token detection ────────────────────────

export interface CursorToken {
  type: "field_name" | "field_value" | "text";
  field?: string;
  partialValue: string;
  startPos: number;
  endPos: number;
}

/**
 * Determine what token the cursor is in for autocomplete purposes.
 */
export function getTokenAtCursor(query: string, cursorPos: number): CursorToken {
  // Find the token boundaries around the cursor
  let start = cursorPos;
  let end = cursorPos;

  // Walk backward to find token start
  while (start > 0 && query[start - 1] !== " " && query[start - 1] !== "\t" && !['(', ')'].includes(query[start - 1])) {
    start--;
  }

  // Walk forward to find token end
  while (end < query.length && query[end] !== " " && query[end] !== "\t" && !['(', ')'].includes(query[end])) {
    end++;
  }

  const token = query.slice(start, end);

  // Check if this looks like a field:value
  const colonIdx = token.indexOf(":");
  if (colonIdx >= 0) {
    const fieldPart = token.slice(0, colonIdx);
    const valuePart = token.slice(colonIdx + 1);

    if (fieldPart && /^[a-zA-Z][a-zA-Z0-9_.]*$/.test(fieldPart)) {
      return {
        type: "field_value",
        field: fieldPart,
        partialValue: valuePart,
        startPos: start,
        endPos: end,
      };
    }
  }

  // Check if this might be a partial field name
  if (/^[a-zA-Z][a-zA-Z0-9_.]*$/.test(token)) {
    return {
      type: "field_name",
      partialValue: token,
      startPos: start,
      endPos: end,
    };
  }

  return {
    type: "text",
    partialValue: token,
    startPos: start,
    endPos: end,
  };
}

/**
 * Remove a filter from a query string by its raw text.
 * Returns the updated query string.
 */
export function removeFilterFromQuery(query: string, filterRaw: string): string {
  // Remove the filter text and clean up whitespace
  const idx = query.indexOf(filterRaw);
  if (idx === -1) return query;

  let result = query.slice(0, idx) + query.slice(idx + filterRaw.length);

  // Clean up: remove double spaces, leading/trailing AND/OR
  result = result.replace(/\s+/g, " ").trim();
  result = result.replace(/^(AND|OR)\s+/i, "");
  result = result.replace(/\s+(AND|OR)$/i, "");
  result = result.replace(/\s+(AND|OR)\s+(AND|OR)\s+/g, " AND ");

  return result;
}
