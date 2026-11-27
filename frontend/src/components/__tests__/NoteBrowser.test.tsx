import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const mockDeleteNote = vi.fn();

vi.mock("@/hooks/useNotes", () => ({
  useNotes: () => ({
    data: {
      items: [
        {
          id: "n1",
          created_by: "u1",
          entry_id: null,
          title: "Analysis Report",
          content_markdown: "## Findings\n\nKey takeaways from the analysis...",
          content_html: "<h2>Findings</h2>",
          tags: ["analysis"],
          is_pinned: true,
          created_at: "2026-03-01T00:00:00Z",
          updated_at: "2026-03-01T00:00:00Z",
          entry_title: null,
          feed_title: null,
        },
        {
          id: "n2",
          created_by: "u1",
          entry_id: "e1",
          title: "Article Notes",
          content_markdown: "Some observations",
          content_html: "<p>Some observations</p>",
          tags: [],
          is_pinned: false,
          created_at: "2026-02-28T00:00:00Z",
          updated_at: "2026-02-28T00:00:00Z",
          entry_title: "CVE Article",
          feed_title: "Security Blog",
        },
      ],
      total: 2,
      limit: 50,
      offset: 0,
      has_more: false,
    },
    isLoading: false,
  }),
  useDeleteNote: () => ({ mutate: mockDeleteNote }),
  useCreateNote: () => ({ mutate: vi.fn() }),
  useCreateEntryNote: () => ({ mutate: vi.fn() }),
  useUpdateNote: () => ({ mutate: vi.fn() }),
}));

vi.mock("@/hooks/useExport", () => ({
  exportNote: vi.fn(),
}));

vi.mock("@/hooks/useTelemetrySources", () => ({
  useAllTelemetryNotes: () => ({
    data: {
      items: [
        {
          id: "t1",
          source_name: "AWS GuardDuty",
          user_id: "u1",
          username: "analyst",
          url: "https://docs.aws.amazon.com/guardduty/x",
          page_title: "Finding types",
          quote: "Needs the agent",
          content: "**EC2** fleet has no agent",
          created_at: "2026-02-27T00:00:00Z",
          updated_at: "2026-02-27T00:00:00Z",
        },
      ],
      total: 1,
      limit: 200,
      offset: 0,
      has_more: false,
    },
    isLoading: false,
  }),
  useDeleteTelemetryNote: () => ({ mutate: vi.fn() }),
  useUpdateTelemetryNote: () => ({ mutate: vi.fn(), mutateAsync: vi.fn() }),
}));

vi.mock("@/hooks/useEntityNotes", () => ({
  useAllEntityNotes: () => ({ data: { items: [], total: 0, limit: 50, offset: 0, has_more: false }, isLoading: false }),
  useDeleteEntityNote: () => ({ mutate: vi.fn() }),
  useUpdateEntityNote: () => ({ mutate: vi.fn(), mutateAsync: vi.fn() }),
}));

vi.mock("@/hooks/useUndoableDelete", () => ({
  useUndoableDelete: vi.fn(() => vi.fn()),
}));

// NoteBody renders markdown via EntityLinkedMarkdown, which scans text for entities via react-query — stub it so tests don't need a QueryClient.
vi.mock("@/hooks/useEntityScan", () => ({
  useEntityScan: () => ({ data: [] }),
}));

vi.mock("react-router-dom", () => ({
  useNavigate: () => vi.fn(),
}));

vi.mock("@/stores/authStore", () => {
  // Signed in as the author of both fixture notes — edit/delete are author-gated
  const state = { user: { id: "u1", role: "user" } };
  const useAuthStore = (selector: (s: typeof state) => unknown) => selector(state);
  useAuthStore.getState = () => state;
  return { useAuthStore };
});

vi.mock("@/stores/uiStore", () => ({
  useUIStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector({
      setSelectedEntry: vi.fn(),
      setActivePanel: vi.fn(),
      setActiveReaderPanel: vi.fn(),
      pendingNoteSearch: null,
      clearPendingNoteSearch: vi.fn(),
    })
  ),
}));

import { NoteBrowser } from "../NoteBrowser";

describe("NoteBrowser", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders notes list", () => {
    render(<NoteBrowser />);
    expect(screen.getByText("Analysis Report")).toBeInTheDocument();
    expect(screen.getByText("Article Notes")).toBeInTheDocument();
  });

  it("shows new note button", () => {
    render(<NoteBrowser />);
    expect(screen.getByText("+ New Note")).toBeInTheDocument();
  });

  it("shows pinned indicator", () => {
    render(<NoteBrowser />);
    // Pinned notes show pushpin icon (&#128204;)
    const pinIcon = document.querySelector("[class*='pinIcon']");
    expect(pinIcon).toBeInTheDocument();
  });

  it("shows linked entry info", () => {
    render(<NoteBrowser />);
    // Shows "Security Blog > CVE Article"
    expect(screen.getByText(/Security Blog/)).toBeInTheDocument();
  });

  it("shows note preview text", () => {
    render(<NoteBrowser />);
    expect(screen.getByText(/Findings/)).toBeInTheDocument();
  });

  it("shows export and delete buttons on own notes", () => {
    render(<NoteBrowser />);
    const exportBtns = screen.getAllByText("Export");
    const deleteBtns = screen.getAllByTitle("Delete note");
    expect(exportBtns.length).toBe(3);
    expect(deleteBtns.length).toBe(3);
  });

  it("lists telemetry source notes as markdown, with their link, quote and source", () => {
    render(<NoteBrowser />);
    expect(screen.getByText("Telemetry source: AWS GuardDuty")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Finding types" })).toHaveAttribute(
      "href",
      "https://docs.aws.amazon.com/guardduty/x",
    );
    expect(screen.getByText("Needs the agent").closest("blockquote")).not.toBeNull();
    expect(screen.getByText("EC2").tagName).toBe("STRONG");
  });

  it("shows filter dropdown", () => {
    render(<NoteBrowser />);
    expect(screen.getByText("All Sources")).toBeInTheDocument();
  });
});
