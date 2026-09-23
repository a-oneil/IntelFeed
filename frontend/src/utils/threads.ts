import type { Entry, PriorityQueueRow, StoryThread } from "@/api/types";
import type { DisplayItemWithDividers } from "./dayDividers";
import { groupConsecutiveEntries } from "./groupEntries";

/** A story-thread row slotted into a list of entries. */
export interface ThreadItem {
  type: "thread";
  thread: StoryThread;
  score: number;
  /** Members the row absorbed (kept out of the list as standalone entries). */
  memberIds: string[];
  key: string;
}

export type QueueItem = DisplayItemWithDividers | ThreadItem;

/** "11 outlets · 23 articles · 6 new" — the row's one-line account of itself. */
export function threadSummaryLine(thread: StoryThread): string {
  const parts = [
    `${thread.source_count} outlet${thread.source_count === 1 ? "" : "s"}`,
    `${thread.entry_count} article${thread.entry_count === 1 ? "" : "s"}`,
  ];
  if (thread.new_since_opened > 0) parts.push(`${thread.new_since_opened} new`);
  if (thread.echo_count > 0) parts.push(`${thread.echo_count} folded`);
  return parts.join(" · ");
}

/**
 * Render the server's Priority Queue rows as list items, in the order they came.
 *
 * The ranking — where a thread sits, which entries it swallowed — is decided by
 * GET /api/entries/priority-queue, so nothing here reorders anything. The only
 * work left is presentational: consecutive CVE entries from one feed still
 * collapse into a group, and a thread row between them ends a run rather than
 * being grouped across. `flatIndex` stays an index into the entry-only stream,
 * which is what keyboard navigation and range selection count in.
 */
export function queueItems(rows: PriorityQueueRow[]): QueueItem[] {
  const out: QueueItem[] = [];
  let run: Entry[] = [];
  let runStart = 0;
  let entriesSeen = 0;

  const flushRun = () => {
    if (run.length === 0) return;
    for (const item of groupConsecutiveEntries(run)) {
      out.push({ ...item, flatIndex: item.flatIndex + runStart });
    }
    run = [];
  };

  for (const row of rows) {
    if (row.kind === "thread") {
      if (!row.thread) continue;
      flushRun();
      out.push({
        type: "thread",
        thread: row.thread,
        score: row.score,
        memberIds: row.absorbed_entry_ids,
        key: `thread-${row.thread.id}`,
      });
      continue;
    }
    if (!row.entry) continue;
    if (run.length === 0) runStart = entriesSeen;
    run.push(row.entry);
    entriesSeen++;
  }
  flushRun();
  return out;
}
