import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { IngestBatch, IngestItem } from "@/hooks/useIngest";
import { useUIStore } from "@/stores/uiStore";

const createBatch = vi.fn();
const addFile = vi.fn();
const addUrls = vi.fn();
const addText = vi.fn();
const retryItem = vi.fn();
const deleteItem = vi.fn();
let batchData: IngestBatch | undefined;

vi.mock("@/hooks/useIngest", () => ({
  useCreateIngestBatch: () => ({ mutateAsync: createBatch, isPending: false }),
  useAddIngestFile: () => ({ mutateAsync: addFile, isPending: false }),
  useAddIngestUrls: () => ({ mutateAsync: addUrls, isPending: false }),
  useAddIngestText: () => ({ mutateAsync: addText, isPending: false }),
  useRetryIngestItem: () => ({ mutate: retryItem }),
  useDeleteIngestItem: () => ({ mutate: deleteItem }),
  useIngestBatch: (id: string | null) => ({ data: id ? batchData : undefined }),
  useIngestCapabilities: () => ({
    data: { extensions: ["pdf", "txt", "docx", "zip"], max_file_mb: 50, max_batch_items: 200, zip_max_members: 100 },
  }),
}));

vi.mock("@/hooks/useFeeds", () => ({
  useFeeds: () => ({
    data: { items: [{ id: "manual-feed", url: "manual://uploads", feed_type: "manual", title: "Manual Uploads" }] },
    refetch: vi.fn(),
  }),
}));

vi.mock("@/hooks/useFocusTrap", () => ({ useFocusTrap: () => ({ current: null }) }));

import { IngestModal } from "../IngestModal";

function item(overrides: Partial<IngestItem>): IngestItem {
  return {
    id: "i1",
    batch_id: "b1",
    parent_item_id: null,
    position: 0,
    kind: "file",
    status: "queued",
    phase: null,
    filename: "report.pdf",
    content_type: "application/pdf",
    size_bytes: 1024 * 1024 * 8,
    title: null,
    source_url: null,
    is_ioc_list: false,
    entry_id: null,
    entry_title: null,
    error: null,
    attempts: 0,
    retryable: false,
    file: null,
    created_at: "2026-10-24T09:12:00Z",
    started_at: null,
    finished_at: null,
    ...overrides,
  };
}

function batch(items: IngestItem[]): IngestBatch {
  const active = items.filter((i) => i.status === "queued" || i.status === "parsing").length;
  const created = items.filter((i) => i.status === "created").length;
  return {
    id: "b1",
    user_id: "u1",
    label: null,
    source: "ui",
    created_at: "2026-10-24T09:12:00Z",
    items,
    summary: {
      total: items.length,
      active,
      created,
      duplicate: items.filter((i) => i.status === "duplicate").length,
      failed: items.filter((i) => ["failed", "no_text", "unsupported", "too_large"].includes(i.status)).length,
      status: active ? "processing" : "complete",
      by_status: {},
    },
  };
}

describe("IngestModal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    batchData = undefined;
    createBatch.mockResolvedValue({ id: "b1", items: [], summary: { total: 0, active: 0 } });
    addFile.mockResolvedValue(item({}));
    addUrls.mockResolvedValue([]);
    addText.mockResolvedValue(item({ kind: "text" }));
    useUIStore.setState({ selectedEntryId: null, selectedFeedId: null, viewMode: "compact" });
  });

  it("opens on Files with the accepted types and cap in the hint", () => {
    render(<IngestModal onClose={vi.fn()} />);
    expect(screen.getByRole("tab", { name: "Files" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText(/up to 50 MB each/)).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "URLs" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Paste" })).toBeInTheDocument();
  });

  it("uploads every dropped file into one batch, one request each", async () => {
    render(<IngestModal onClose={vi.fn()} />);
    const drop = screen.getByRole("button", { name: /drop files/i });
    const a = new File(["a"], "a.pdf", { type: "application/pdf" });
    const b = new File(["b"], "b.docx", { type: "application/octet-stream" });
    fireEvent.drop(drop, { dataTransfer: { files: [a, b] } });

    await waitFor(() => expect(addFile).toHaveBeenCalledTimes(2));
    expect(createBatch).toHaveBeenCalledTimes(1);
    expect(addFile.mock.calls[0][0]).toMatchObject({ batchId: "b1", file: a, isIocList: false });
    expect(addFile.mock.calls[1][0]).toMatchObject({ batchId: "b1", file: b });
  });

  it("sends the indicator-list flag with files added after it is ticked", async () => {
    const user = userEvent.setup();
    render(<IngestModal onClose={vi.fn()} />);
    await user.click(screen.getByLabelText("Indicator list"));
    const input = document.getElementById("ingest-files") as HTMLInputElement;
    await user.upload(input, new File(["1.2.3.4"], "iocs.txt", { type: "text/plain" }));
    await waitFor(() => expect(addFile).toHaveBeenCalledTimes(1));
    expect(addFile.mock.calls[0][0]).toMatchObject({ isIocList: true });
  });

  it("submits one URL per line from the URLs tab", async () => {
    const user = userEvent.setup();
    render(<IngestModal onClose={vi.fn()} />);
    await user.click(screen.getByRole("tab", { name: "URLs" }));
    const box = screen.getByLabelText("URLs, one per line");
    fireEvent.change(box, {
      target: { value: "https://a.example/x\n\n https://github.com/o/r \n" },
    });
    await user.click(screen.getByRole("button", { name: "Ingest URLs" }));
    await waitFor(() => expect(addUrls).toHaveBeenCalledTimes(1));
    expect(addUrls.mock.calls[0][0]).toEqual({
      batchId: "b1",
      urls: ["https://a.example/x", "https://github.com/o/r"],
      isIocList: false,
    });
    await waitFor(() => expect((box as HTMLTextAreaElement).value).toBe(""));
  });

  it("submits a paste with its title and source", async () => {
    const user = userEvent.setup();
    render(<IngestModal onClose={vi.fn()} />);
    await user.click(screen.getByRole("tab", { name: "Paste" }));
    fireEvent.change(screen.getByLabelText("Text"), { target: { value: "Helpdesk took three calls." } });
    fireEvent.change(screen.getByLabelText("Title (optional)"), { target: { value: "Vishing writeup" } });
    await user.click(screen.getByRole("button", { name: "Ingest text" }));
    await waitFor(() => expect(addText).toHaveBeenCalledTimes(1));
    expect(addText.mock.calls[0][0]).toMatchObject({
      batchId: "b1",
      text: "Helpdesk took three calls.",
      title: "Vishing writeup",
      isIocList: false,
    });
  });

  it("shows one row per item with its outcome, and wires Open / Retry", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    batchData = batch([
      item({ id: "i1", filename: "done.pdf", status: "created", phase: "done", entry_id: "e1", entry_title: "M-Trends" }),
      item({ id: "i2", filename: "twin.pdf", status: "duplicate", entry_id: "e1", entry_title: "M-Trends", error: "Already ingested" }),
      item({ id: "i3", filename: "scan.pdf", status: "no_text", error: "no extractable text", retryable: true }),
      item({ id: "i4", filename: "notes.docx", status: "parsing" }),
      item({ id: "i5", kind: "github_repo", filename: "SigmaHQ/sigma", status: "expanded", source_url: "https://github.com/SigmaHQ/sigma" }),
    ]);
    render(<IngestModal onClose={onClose} />);
    // The batch query is keyed on a batch id, which only exists once something was added.
    fireEvent.drop(screen.getByRole("button", { name: /drop files/i }), {
      dataTransfer: { files: [new File(["x"], "x.txt", { type: "text/plain" })] },
    });
    await waitFor(() => expect(screen.getAllByTestId("ingest-item")).toHaveLength(5));

    const rows = screen.getAllByTestId("ingest-item");
    expect(within(rows[0]).getByText("done")).toBeInTheDocument();
    expect(within(rows[1]).getByText("duplicate")).toBeInTheDocument();
    expect(within(rows[1]).getByText(/same as “M-Trends”/)).toBeInTheDocument();
    expect(within(rows[2]).getByText("no text")).toBeInTheDocument();
    expect(within(rows[3]).getByText("parsing")).toBeInTheDocument();
    expect(within(rows[4]).getByText("expanded")).toBeInTheDocument();
    expect(screen.getByText(/5 items · 1 created · 1 working · 1 duplicate · 1 failed/)).toBeInTheDocument();

    await user.click(within(rows[2]).getByRole("button", { name: "Retry" }));
    expect(retryItem).toHaveBeenCalledWith({ batchId: "b1", itemId: "i3" });

    await user.click(within(rows[0]).getByRole("button", { name: "Open" }));
    expect(useUIStore.getState().selectedEntryId).toBe("e1");
    expect(useUIStore.getState().selectedFeedId).toBe("manual-feed");
    expect(onClose).toHaveBeenCalled();
  });

  it("Open Manual Uploads selects the feed in table view", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    batchData = batch([item({ id: "i1", status: "created", entry_id: "e1" })]);
    render(<IngestModal onClose={onClose} />);
    fireEvent.drop(screen.getByRole("button", { name: /drop files/i }), {
      dataTransfer: { files: [new File(["x"], "x.txt", { type: "text/plain" })] },
    });
    await user.click(await screen.findByRole("button", { name: "Open Manual Uploads" }));
    expect(useUIStore.getState().selectedFeedId).toBe("manual-feed");
    expect(useUIStore.getState().viewMode).toBe("table");
    expect(onClose).toHaveBeenCalled();
  });
});
