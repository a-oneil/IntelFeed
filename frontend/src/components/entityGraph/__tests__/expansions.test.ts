import { describe, expect, it } from "vitest";
import { pruneExpansions } from "../expansions";

const ex = (...ids: string[]) => ({ nodes: ids.map((id) => ({ id })) });

describe("pruneExpansions", () => {
  const base = new Set(["seed", "x"]);

  it("drops expansions that only keep each other alive", () => {
    // y and z came from x's expansion and each lists the other; x is collapsed.
    const left = new Map([["y", ex("z", "a")], ["z", ex("y", "b")]]);
    expect([...pruneExpansions(left, base).keys()]).toEqual([]);
  });

  it("keeps chains still rooted in the base graph", () => {
    const all = new Map([["x", ex("y")], ["y", ex("z")], ["z", ex("q")], ["orphan", ex("w")]]);
    expect([...pruneExpansions(all, base).keys()]).toEqual(["x", "y", "z"]);
  });
});
