import { createElement } from "react";
import { describe, expect, it } from "vitest";
import { headingIdsByLine, nodeText, slugify } from "../headingAnchors";

describe("slugify", () => {
  it("lowercases and hyphenates words", () => {
    expect(slugify("Autolinker Deep Dive")).toBe("autolinker-deep-dive");
  });

  it("turns each space into one hyphen, so punctuation between words leaves a double hyphen", () => {
    // GitHub's rule, and the one the tables of contents are written against.
    expect(slugify("Logging & Audit")).toBe("logging--audit");
    expect(slugify("Entry-to-Intelligence Pipeline")).toBe("entry-to-intelligence-pipeline");
  });

  it("keeps underscores and hyphens, drops other punctuation", () => {
    expect(slugify("Phase 1: Entry Arrival & Text Normalization")).toBe("phase-1-entry-arrival--text-normalization");
    expect(slugify("The contract: regex never creates a row")).toBe("the-contract-regex-never-creates-a-row");
    expect(slugify("seed_all.py")).toBe("seed_allpy");
  });

  it("keeps non-ASCII letters", () => {
    expect(slugify("Über Straße")).toBe("über-straße");
  });
});

describe("nodeText", () => {
  it("reads through inline code and nested elements", () => {
    const children = [
      "Link Validation (",
      createElement("code", null, "workers/link_validation_tasks.py"),
      ")",
    ];
    expect(nodeText(children)).toBe("Link Validation (workers/link_validation_tasks.py)");
    expect(nodeText(createElement("strong", null, "bold ", createElement("em", null, "and italic")))).toBe(
      "bold and italic",
    );
  });

  it("ignores empty values", () => {
    expect(nodeText(null)).toBe("");
    expect(nodeText([undefined, false, "ok"])).toBe("ok");
  });
});

describe("headingIdsByLine", () => {
  const doc = [
    "# Title", // 1
    "", // 2
    "## Setup", // 3
    "", // 4
    "```bash", // 5
    "# not a heading", // 6
    "```", // 7
    "", // 8
    "## Logging & Audit", // 9
    "", // 10
    "### Setup", // 11
    "", // 12
    "### Setup", // 13
    "", // 14
    "## Deduplication (`correlation_events.py:88-114`)", // 15
    "## A [linked](https://example.com) **bold** heading ##", // 16
  ].join("\n");

  const ids = headingIdsByLine(doc);

  it("keys ids by the line each heading starts on", () => {
    expect(ids.get(1)).toBe("title");
    expect(ids.get(3)).toBe("setup");
    expect(ids.get(9)).toBe("logging--audit");
  });

  it("numbers repeated headings the way GitHub does", () => {
    expect(ids.get(11)).toBe("setup-1");
    expect(ids.get(13)).toBe("setup-2");
  });

  it("skips fenced code", () => {
    expect(ids.has(6)).toBe(false);
  });

  it("slugs the visible text of a heading with inline code, links and emphasis", () => {
    expect(ids.get(15)).toBe("deduplication-correlation_eventspy88-114");
    expect(ids.get(16)).toBe("a-linked-bold-heading");
  });
});
