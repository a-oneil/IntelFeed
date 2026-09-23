import { describe, it, expect } from "vitest";
import { adjacentEntryId } from "@/utils/entryNavigation";

describe("adjacentEntryId", () => {
  const trail = ["a", "b", "c"];

  it("steps through the list when the current entry is still in it", () => {
    const list = ["a", "b", "c", "d"];
    expect(adjacentEntryId("next", "b", list, trail, 1)).toBe("c");
    expect(adjacentEntryId("prev", "b", list, trail, 1)).toBe("a");
  });

  it("walks back to an entry auto-read out of the list", () => {
    // Auto-read dropped a and b once the reader moved on to c.
    expect(adjacentEntryId("prev", "c", ["c", "d"], trail, 2)).toBe("b");
  });

  it("walks forward again from an entry no longer in the list", () => {
    expect(adjacentEntryId("next", "b", ["c", "d"], trail, 1)).toBe("c");
  });

  it("returns null at either end of both the list and the trail", () => {
    expect(adjacentEntryId("prev", "a", ["a", "b"], ["a"], 0)).toBeNull();
    expect(adjacentEntryId("next", "c", ["c"], trail, 2)).toBeNull();
    expect(adjacentEntryId("prev", null, ["a"], trail, 2)).toBeNull();
  });

  it("returns null for an entry the trail has never seen", () => {
    expect(adjacentEntryId("prev", "zz", [], trail, 2)).toBeNull();
  });
});
