import { describe, it, expect } from "vitest";
import {
  parseQuery,
  extractFilters,
  getTokenAtCursor,
  removeFilterFromQuery,
} from "../queryParser";

describe("parseQuery", () => {
  it("parses empty query", () => {
    const node = parseQuery("");
    expect(node.type).toBe("text");
    expect((node as { value: string }).value).toBe("");
  });

  it("parses single word", () => {
    const node = parseQuery("ransomware");
    expect(node.type).toBe("text");
    expect((node as { value: string }).value).toBe("ransomware");
  });

  it("parses quoted phrase", () => {
    const node = parseQuery('"cobalt strike beacon"');
    expect(node.type).toBe("text");
    expect((node as { value: string }).value).toBe("cobalt strike beacon");
  });

  it("parses implicit AND", () => {
    const node = parseQuery("ransomware attack");
    expect(node.type).toBe("bool");
    if (node.type === "bool") {
      expect(node.op).toBe("AND");
      expect(node.children.length).toBe(2);
    }
  });

  it("parses explicit OR", () => {
    const node = parseQuery("APT28 OR APT29");
    expect(node.type).toBe("bool");
    if (node.type === "bool") {
      expect(node.op).toBe("OR");
      expect(node.children.length).toBe(2);
    }
  });

  it("parses NOT", () => {
    const node = parseQuery("NOT spam");
    expect(node.type).toBe("not");
    if (node.type === "not") {
      expect(node.child.type).toBe("text");
    }
  });

  it("parses field:value", () => {
    const node = parseQuery("ioc:192.168.1.100");
    expect(node.type).toBe("field");
    if (node.type === "field") {
      expect(node.fieldName).toBe("ioc");
      expect(node.value).toBe("192.168.1.100");
      expect(node.exact).toBe(false);
    }
  });

  it("parses field:wildcard", () => {
    const node = parseQuery("ioc:192.168.*");
    expect(node.type).toBe("field");
    if (node.type === "field") {
      expect(node.value).toBe("192.168.*");
    }
  });

  it('parses field:"quoted value"', () => {
    const node = parseQuery('title:"zero day"');
    expect(node.type).toBe("field");
    if (node.type === "field") {
      expect(node.fieldName).toBe("title");
      expect(node.value).toBe("zero day");
      expect(node.exact).toBe(true);
    }
  });

  it("parses dotted field", () => {
    const node = parseQuery("cve.severity:critical");
    expect(node.type).toBe("field");
    if (node.type === "field") {
      expect(node.fieldName).toBe("cve.severity");
      expect(node.value).toBe("critical");
    }
  });

  it("parses range value", () => {
    const node = parseQuery("cve.cvss:>9.0");
    expect(node.type).toBe("field");
    if (node.type === "field") {
      expect(node.value).toBe(">9.0");
    }
  });

  it("parses grouped OR", () => {
    const node = parseQuery("(threat_actor:APT28 OR threat_actor:APT29) AND ttp.tactic:initial-access");
    expect(node.type).toBe("bool");
    if (node.type === "bool") {
      expect(node.op).toBe("AND");
      expect(node.children.length).toBe(2);
      expect(node.children[0].type).toBe("bool");
    }
  });

  it("parses complex mixed query", () => {
    const node = parseQuery("ransomware AND threat_actor:LockBit AND is:unread");
    expect(node.type).toBe("bool");
    if (node.type === "bool") {
      expect(node.op).toBe("AND");
      expect(node.children.length).toBe(3);
    }
  });

  it("handles operator precedence (AND binds tighter than OR)", () => {
    const node = parseQuery("a OR b AND c");
    expect(node.type).toBe("bool");
    if (node.type === "bool") {
      expect(node.op).toBe("OR");
      expect(node.children[1].type).toBe("bool");
      if (node.children[1].type === "bool") {
        expect(node.children[1].op).toBe("AND");
      }
    }
  });

  it("returns text node on parse error (graceful fallback)", () => {
    const node = parseQuery("(unclosed");
    expect(node.type).toBe("text");
    expect((node as { value: string }).value).toBe("(unclosed");
  });
});

describe("extractFilters", () => {
  it("returns empty for bare text", () => {
    const node = parseQuery("ransomware");
    expect(extractFilters(node)).toEqual([]);
  });

  it("extracts single filter", () => {
    const node = parseQuery("ioc:192.168.*");
    const filters = extractFilters(node);
    expect(filters.length).toBe(1);
    expect(filters[0].field).toBe("ioc");
    expect(filters[0].value).toBe("192.168.*");
    expect(filters[0].negated).toBe(false);
  });

  it("extracts negated filter", () => {
    const node = parseQuery("NOT is:read");
    const filters = extractFilters(node);
    expect(filters.length).toBe(1);
    expect(filters[0].negated).toBe(true);
  });

  it("extracts multiple filters from mixed query", () => {
    const node = parseQuery("ransomware AND threat_actor:APT29 AND is:starred");
    const filters = extractFilters(node);
    expect(filters.length).toBe(2);
    const fields = new Set(filters.map((f) => f.field));
    expect(fields).toEqual(new Set(["threat_actor", "is"]));
  });

  it("extracts filters from nested OR", () => {
    const node = parseQuery("(threat_actor:APT28 OR threat_actor:APT29) AND cve.severity:critical");
    const filters = extractFilters(node);
    expect(filters.length).toBe(3);
  });
});

describe("getTokenAtCursor", () => {
  it("identifies field_value when cursor is after colon", () => {
    const result = getTokenAtCursor("ioc:192", 7);
    expect(result.type).toBe("field_value");
    expect(result.field).toBe("ioc");
    expect(result.partialValue).toBe("192");
  });

  it("identifies field_name for partial field", () => {
    const result = getTokenAtCursor("act", 3);
    expect(result.type).toBe("field_name");
    expect(result.partialValue).toBe("act");
  });

  it("identifies potential field_name for alphanumeric words", () => {
    // Pure alpha words could be field names or text — getTokenAtCursor reports field_name
    // since it can't distinguish without context. Autocomplete uses this to suggest fields.
    const result = getTokenAtCursor("ransomware", 5);
    expect(result.type).toBe("field_name");
    expect(result.partialValue).toBe("ransomware");
  });

  it("works with cursor in middle of query", () => {
    const result = getTokenAtCursor("threat_actor:APT29 AND cve:", 27);
    expect(result.type).toBe("field_value");
    expect(result.field).toBe("cve");
    expect(result.partialValue).toBe("");
  });
});

describe("removeFilterFromQuery", () => {
  it("removes a filter and cleans whitespace", () => {
    expect(removeFilterFromQuery("threat_actor:APT29 AND is:starred", "is:starred")).toBe(
      "threat_actor:APT29"
    );
  });

  it("removes filter from middle", () => {
    expect(
      removeFilterFromQuery("ransomware AND threat_actor:APT29 AND is:starred", "threat_actor:APT29")
    ).toBe("ransomware AND is:starred");
  });

  it("handles NOT filter removal", () => {
    expect(removeFilterFromQuery("NOT is:read AND tag:critical", "NOT is:read")).toBe(
      "tag:critical"
    );
  });

  it("returns original if filter not found", () => {
    expect(removeFilterFromQuery("ransomware", "ioc:test")).toBe("ransomware");
  });
});
