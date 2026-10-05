import { describe, expect, it } from "vitest";
import { normalizeTagSpec, specsFromNames, tagSpecName, toTagSpecs } from "../tagSpecs";

describe("tagSpecs", () => {
  it("reads legacy comma strings and mixed arrays", () => {
    expect(toTagSpecs("a, b,,c")).toEqual(["a", "b", "c"]);
    expect(toTagSpecs(["a", { name: "b", chip: true }, { name: "" }, 3, null])).toEqual([
      "a",
      { name: "b", chip: true },
    ]);
    expect(toTagSpecs(undefined)).toEqual([]);
  });

  it("collapses a spec with no presentation back to a bare name", () => {
    expect(normalizeTagSpec({ name: "x" })).toBe("x");
    expect(normalizeTagSpec({ name: "x", color: "#6b7280", description: "  ", chip: false })).toBe("x");
    expect(normalizeTagSpec({ name: "x", chip: true, color: "#DC2626" })).toEqual({
      name: "x",
      chip: true,
      color: "#DC2626",
    });
  });

  it("keeps the global scope only when set", () => {
    expect(normalizeTagSpec({ name: "x", global: false })).toBe("x");
    expect(normalizeTagSpec({ name: "x", global: true })).toEqual({ name: "x", global: true });
  });

  it("keeps spaces in a description while it is being typed", () => {
    expect(normalizeTagSpec({ name: "x", description: "Customer " })).toEqual({ name: "x", description: "Customer " });
  });

  it("keeps each surviving name's presentation when the list is edited as text", () => {
    const previous = ["a", { name: "b", chip: true }];
    expect(specsFromNames(["b", "c"], previous)).toEqual([{ name: "b", chip: true }, "c"]);
    expect(specsFromNames(["b"], previous).map(tagSpecName)).toEqual(["b"]);
  });
});
