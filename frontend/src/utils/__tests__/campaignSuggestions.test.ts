import { describe, it, expect } from "vitest";
import { groupSuggestions } from "@/utils/campaignSuggestions";
import type { CampaignSuggestion } from "@/api/types";

function suggestion(over: Partial<CampaignSuggestion> & { entry_id: string }): CampaignSuggestion {
  return {
    title: over.entry_id,
    url: null,
    published_at: null,
    overlap_count: 0,
    overlapping_entities: [],
    reason: "shared_entities",
    thread_id: null,
    thread_slug: null,
    thread_title: null,
    thread_role: null,
    thread_article_count: null,
    thread_in_campaign: null,
    ...over,
  };
}

const story = (entry_id: string) =>
  suggestion({
    entry_id,
    reason: "same_story",
    thread_id: "t1",
    thread_slug: "chrome-v8-zero-day",
    thread_title: "Chrome V8 zero-day",
    thread_article_count: 27,
    thread_in_campaign: 3,
  });

describe("groupSuggestions", () => {
  it("offers the rest of a story as one row", () => {
    const groups = groupSuggestions([story("a"), story("b"), story("c")]);

    expect(groups).toHaveLength(1);
    if (groups[0].kind !== "story") throw new Error("expected a story row");
    expect(groups[0].title).toBe("Chrome V8 zero-day");
    expect(groups[0].held).toBe(3);
    expect(groups[0].total).toBe(27);
    expect(groups[0].items.map((i) => i.entry_id)).toEqual(["a", "b", "c"]);
  });

  it("leaves entity matches that never clustered as their own rows", () => {
    const groups = groupSuggestions([
      suggestion({ entry_id: "loose-1", overlap_count: 5 }),
      suggestion({ entry_id: "loose-2", overlap_count: 4 }),
    ]);

    expect(groups.map((g) => g.kind)).toEqual(["entry", "entry"]);
  });

  it("does not make a story row out of a single article", () => {
    const groups = groupSuggestions([story("only-one")]);

    expect(groups).toHaveLength(1);
    expect(groups[0].kind).toBe("entry");
  });

  it("keeps the backend's order, stories and loose articles interleaved", () => {
    const groups = groupSuggestions([
      story("a"),
      story("b"),
      suggestion({ entry_id: "loose", overlap_count: 9 }),
    ]);

    expect(groups.map((g) => (g.kind === "story" ? g.slug : g.item.entry_id))).toEqual([
      "chrome-v8-zero-day",
      "loose",
    ]);
  });
});
