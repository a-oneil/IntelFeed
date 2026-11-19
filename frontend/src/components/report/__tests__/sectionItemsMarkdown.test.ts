import { describe, it, expect } from "vitest";
import { itemsToMarkdown, dataSectionText } from "../sectionItemsMarkdown";

describe("itemsToMarkdown", () => {
  it("writes actor rows as the exporter does, aliases only when there are any", () => {
    const md = itemsToMarkdown([
      { name: "ShinyHunters", aliases: ["Bling Libra", "UNC6240"], country: "US" },
      { name: "GALLIUM", aliases: [] },
    ]);
    expect(md).toBe("- **ShinyHunters** (aliases: Bling Libra, UNC6240)\n- **GALLIUM**");
  });

  it("writes timeline rows with the day only", () => {
    expect(itemsToMarkdown([{ date: "2026-01-29T10:00:00+00:00", title: "First" }])).toBe(
      "- **2026-01-29**: First",
    );
  });

  it("writes observables as a table", () => {
    const md = itemsToMarkdown([{ kind: "ipv4", value: "10.0.0.1", confidence: 0.8, claimed_by: ["x"] }]);
    expect(md.split("\n")[0]).toBe("| Kind | Value | Confidence | Attribution | Last seen |");
    expect(md).toContain("| ipv4 | 10.0.0.1 | 80% | x |  |");
  });

  it("is empty for no rows", () => {
    expect(itemsToMarkdown([])).toBe("");
  });
});

describe("dataSectionText", () => {
  it("puts the written body before the rows", () => {
    expect(dataSectionText("Intro.\n", [{ name: "A", aliases: ["B"] }])).toBe("Intro.\n\n- **A** (aliases: B)");
  });
  it("is just the body when there are no rows", () => {
    expect(dataSectionText("Only text", [])).toBe("Only text");
  });
});
