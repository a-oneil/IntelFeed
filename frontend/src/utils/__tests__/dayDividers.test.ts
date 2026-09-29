import { describe, expect, it } from "vitest";
import type { Entry, StoryThread } from "@/api/types";
import { filterCollapsedDays, injectDayDividers, type DayDividerItem } from "../dayDividers";
import type { MagazineItem } from "../threads";

function single(id: string, publishedAt: string): MagazineItem {
  return {
    type: "single",
    entry: { id, title: `Entry ${id}`, published_at: publishedAt } as unknown as Entry,
    flatIndex: 0,
  };
}

function threadItem(lastSeen: string | null): MagazineItem {
  return {
    type: "thread",
    thread: {
      id: "t1",
      slug: "story",
      title: "One story",
      last_seen: lastSeen,
    } as unknown as StoryThread,
    score: 7,
    memberIds: [],
    key: "thread-t1",
  };
}

function keysOf(items: (MagazineItem | DayDividerItem)[]): string[] {
  return items.map((i) => (i.type === "divider" ? `divider:${i.dayKey}` : i.type));
}

/**
 * Threads have to sit under a day like anything else, or the magazine grid's
 * dividers start lying about what is under them.
 */
describe("injectDayDividers with a thread row", () => {
  it("files a thread under its last beat, not its first", () => {
    const out = injectDayDividers(
      [single("a", "2026-03-02T10:00:00"), threadItem("2026-03-01T09:00:00")],
      true,
    );

    expect(keysOf(out)).toEqual(["divider:2026-03-02", "single", "divider:2026-03-01", "thread"]);
  });

  it("joins the day an entry already opened instead of repeating the divider", () => {
    const out = injectDayDividers(
      [single("a", "2026-03-02T10:00:00"), threadItem("2026-03-02T23:00:00")],
      true,
    );

    expect(keysOf(out)).toEqual(["divider:2026-03-02", "single", "thread"]);
    expect((out[0] as DayDividerItem).dayCount).toBe(2);
  });

  it("counts a thread as one card, not as the articles it folded", () => {
    const [divider] = injectDayDividers([threadItem("2026-03-02T10:00:00")], true);

    expect((divider as DayDividerItem).dayCount).toBe(1);
  });

  it("leaves an undated thread out of the day buckets", () => {
    const out = injectDayDividers([threadItem(null), single("a", "2026-03-02T10:00:00")], true);

    expect(keysOf(out)).toEqual(["thread", "divider:2026-03-02", "single"]);
  });
});

describe("filterCollapsedDays with a thread row", () => {
  it("hides a thread under a collapsed day and keeps the divider", () => {
    const items = injectDayDividers(
      [single("a", "2026-03-02T10:00:00"), threadItem("2026-03-01T09:00:00")],
      true,
    );

    const out = filterCollapsedDays(items, new Set(["2026-03-01"]));

    expect(keysOf(out)).toEqual(["divider:2026-03-02", "single", "divider:2026-03-01"]);
  });

  it("leaves a thread alone when its day is open", () => {
    const items = injectDayDividers([threadItem("2026-03-01T09:00:00")], true);

    expect(keysOf(filterCollapsedDays(items, new Set(["2026-03-02"])))).toEqual([
      "divider:2026-03-01",
      "thread",
    ]);
  });
});
