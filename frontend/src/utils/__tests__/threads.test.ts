import { describe, expect, it } from "vitest";
import type { Entry, PriorityQueueRow, StoryThread } from "@/api/types";
import { magazineQueueItems, queueItems, threadSummaryLine } from "../threads";

function entry(id: string, title = `Entry ${id}`): Entry {
  return { id, title, feed_id: "f1" } as unknown as Entry;
}

function thread(overrides: Partial<StoryThread> = {}): StoryThread {
  return {
    id: "t1",
    slug: "story",
    title: "One story",
    summary: null,
    status: "open",
    entry_count: 3,
    source_count: 3,
    echo_count: 1,
    first_seen: null,
    last_seen: null,
    peak_at: null,
    key_entities: [],
    unread_count: 3,
    new_since_opened: 2,
    top_score: 5,
    top_entry_id: "a",
    entry_ids: ["a", "b"],
    narrated_at: null,
    ...overrides,
  };
}

function entryRow(id: string, score: number, title?: string): PriorityQueueRow {
  return { kind: "entry", score, entry: entry(id, title), thread: null, absorbed_entry_ids: [] };
}

function threadRow(score: number, overrides: Partial<StoryThread> = {}): PriorityQueueRow {
  return {
    kind: "thread",
    score,
    entry: null,
    thread: thread(overrides),
    absorbed_entry_ids: ["a", "b"],
  };
}

/**
 * Ranking and folding belong to GET /api/entries/priority-queue (covered by
 * backend/tests/test_priority_queue.py). What is left here is the rendering
 * adapter: the server's order must survive untouched, and flatIndex must keep
 * counting entries only.
 */
describe("queueItems", () => {
  it("keeps the server's order", () => {
    const out = queueItems([entryRow("x", 9), threadRow(7), entryRow("y", 6)]);

    expect(out.map((i) => i.type)).toEqual(["single", "thread", "single"]);
  });

  it("badges a thread with the score it ranks by", () => {
    // The badge and the queue order use one number, so a story sorts among
    // articles exactly where its badge says it should.
    const [row] = queueItems([threadRow(7.5)]);

    expect(row).toMatchObject({
      type: "thread",
      score: 7.5,
      memberIds: ["a", "b"],
      key: "thread-t1",
    });
  });

  it("badges a standalone entry with the row's lifted score", () => {
    const [row] = queueItems([entryRow("x", 8.4)]);
    expect(row).toMatchObject({
      type: "single",
      entry: { id: "x", priority_score: 8.4 },
    });
  });

  it("counts flatIndex over entries only, skipping thread rows", () => {
    const out = queueItems([entryRow("x", 9), threadRow(7), entryRow("y", 6), entryRow("z", 5)]);

    const indexes = out.flatMap((i) => (i.type === "single" ? [[i.entry.id, i.flatIndex]] : []));
    expect(indexes).toEqual([
      ["x", 0],
      ["y", 1],
      ["z", 2],
    ]);
  });

  it("groups a consecutive CVE run from one feed", () => {
    const out = queueItems([
      entryRow("a", 9, "CVE-2026-1111 Acme Router flaw"),
      entryRow("b", 8, "CVE-2026-2222 Acme Router flaw"),
    ]);

    expect(out).toHaveLength(1);
    expect(out[0].type).toBe("group");
  });

  it("does not group across a thread row that separates the run", () => {
    const out = queueItems([
      entryRow("a", 9, "CVE-2026-1111 Acme Router flaw"),
      threadRow(8),
      entryRow("b", 7, "CVE-2026-2222 Acme Router flaw"),
    ]);

    expect(out.map((i) => i.type)).toEqual(["single", "thread", "single"]);
  });

  it("is empty for an empty queue", () => {
    expect(queueItems([])).toEqual([]);
  });
});

/**
 * The magazine grid's own walk: same rows, same order, one card each. The bug
 * it exists to close is silent — the queue withholds a thread's articles, so a
 * grid built from the entry stream loses the whole story without a gap.
 */
describe("magazineQueueItems", () => {
  it("gives a thread a card of its own, in the server's order", () => {
    const out = magazineQueueItems([entryRow("x", 9), threadRow(7), entryRow("y", 6)]);

    expect(out.map((i) => i.type)).toEqual(["single", "thread", "single"]);
    expect(out[1]).toMatchObject({ type: "thread", score: 7, key: "thread-t1" });
  });

  it("never groups CVE runs — magazine cards stay one per entry", () => {
    const out = magazineQueueItems([
      entryRow("a", 9, "CVE-2026-1111 Acme Router flaw"),
      entryRow("b", 8, "CVE-2026-2222 Acme Router flaw"),
    ]);

    expect(out.map((i) => i.type)).toEqual(["single", "single"]);
  });

  it("counts flatIndex over entries only, so range selection still lines up", () => {
    const out = magazineQueueItems([entryRow("x", 9), threadRow(7), entryRow("y", 6)]);

    const indexes = out.flatMap((i) => (i.type === "single" ? [[i.entry.id, i.flatIndex]] : []));
    expect(indexes).toEqual([
      ["x", 0],
      ["y", 1],
    ]);
  });

  it("skips rows the server sent without their payload", () => {
    expect(
      magazineQueueItems([
        { kind: "thread", score: 5, entry: null, thread: null, absorbed_entry_ids: [] },
        { kind: "entry", score: 4, entry: null, thread: null, absorbed_entry_ids: [] },
      ]),
    ).toEqual([]);
  });

  it("is empty for an empty queue", () => {
    expect(magazineQueueItems([])).toEqual([]);
  });
});

describe("threadSummaryLine", () => {
  it("counts outlets, articles, what is new, and what was folded", () => {
    expect(threadSummaryLine(thread())).toBe("3 outlets · 3 articles · 2 new · 1 folded");
  });

  it("drops the empty halves", () => {
    expect(threadSummaryLine(thread({ new_since_opened: 0, echo_count: 0, source_count: 1, entry_count: 1 }))).toBe(
      "1 outlet · 1 article",
    );
  });
});
