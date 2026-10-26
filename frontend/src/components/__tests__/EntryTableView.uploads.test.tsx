import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Entry } from "@/api/types";
import { useAuthStore } from "@/stores/authStore";
import { useUIStore } from "@/stores/uiStore";

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count, getItemKey }: { count: number; getItemKey: (i: number) => string }) => ({
    getVirtualItems: () =>
      Array.from({ length: count }, (_, index) => ({ index, key: getItemKey(index), start: index * 34, size: 34 })),
    getTotalSize: () => count * 34,
    scrollToIndex: vi.fn(),
    measureElement: vi.fn(),
    measure: vi.fn(),
  }),
}));

import { EntryTableView } from "../EntryTableView";

function entry(overrides: Partial<Entry> = {}): Entry {
  return {
    id: "e1",
    feed_id: "manual",
    feed_title: "Manual Uploads",
    feed_type: "manual",
    title: "M-Trends 2026",
    url: null,
    author: null,
    summary: null,
    published_at: "2026-10-24T09:12:00Z",
    is_read: false,
    tags: [],
    metadata: {
      source: "file_upload",
      batch_id: "b1",
      ingest_file_id: "file-1",
      filename: "Mandiant_M-Trends_2026.pdf",
      file_content_type: "application/pdf",
      size_bytes: 8_600_000,
      original_retained: true,
    },
    ...(overrides as Partial<Entry>),
  } as Entry;
}

const baseProps = {
  hasNextPage: false,
  isFetchingNextPage: false,
  fetchNextPage: vi.fn(),
  isLoading: false,
};

describe("EntryTableView on the Manual Uploads feed", () => {
  beforeEach(() => {
    useAuthStore.setState({ accessToken: "tok" });
    useUIStore.setState({ tables: {} } as never);
  });

  it("shows File, Size and Original with a signed download link", () => {
    render(<EntryTableView {...baseProps} entries={[entry()]} uploadsFeed />);
    expect(screen.getByText("Mandiant_M-Trends_2026.pdf")).toBeInTheDocument();
    expect(screen.getByText("PDF")).toBeInTheDocument();
    expect(screen.getByText("8.2 MB")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: "Download" });
    expect(link.getAttribute("href")).toBe("/api/ingest-files/file-1?token=tok");
  });

  it("reads 'removed' once the retention sweep took the file, and 'not kept' for a pre-batch PDF", () => {
    render(
      <EntryTableView
        {...baseProps}
        uploadsFeed
        entries={[
          entry({ id: "e1", metadata: { source: "file_upload", ingest_file_id: "f", filename: "a.pdf", original_retained: false } }),
          entry({ id: "e2", metadata: { source: "pdf_upload", filename: "legacy.pdf" } }),
        ]}
      />,
    );
    expect(screen.getByText("removed")).toBeInTheDocument();
    expect(screen.getByText("not kept")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Download" })).toBeNull();
  });

  it("keeps the upload columns hidden on an ordinary feed", () => {
    render(<EntryTableView {...baseProps} entries={[entry({ feed_type: "rss", feed_title: "Bleeping" })]} />);
    expect(screen.queryByText("Mandiant_M-Trends_2026.pdf")).toBeNull();
    expect(screen.queryByRole("link", { name: "Download" })).toBeNull();
  });
});
