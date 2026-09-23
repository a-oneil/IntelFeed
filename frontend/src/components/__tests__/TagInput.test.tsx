import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";

const mockCreateTag = vi.fn();
const mockAddTags = vi.fn();
const mockRemoveTag = vi.fn();

vi.mock("@/hooks/useTags", () => ({
  useTags: () => ({
    data: [
      { id: "t1", name: "critical", color: "#FF4444", entry_count: 5, created_at: "2026-01-01" },
      { id: "t2", name: "exploit", color: "#FF8800", entry_count: 3, created_at: "2026-01-01" },
    ],
  }),
  useEntryTags: (entryId: string) => ({
    data: entryId === "e1-tagged"
      ? [{ id: "t1", name: "critical", color: "#FF4444", entry_count: 5, created_at: "2026-01-01" }]
      : [],
  }),
  useCreateTag: () => ({ mutateAsync: mockCreateTag }),
  useAddTagsToEntry: () => ({ mutate: mockAddTags }),
  useRemoveTagFromEntry: () => ({ mutate: mockRemoveTag }),
}));

import { TagInput } from "../TagInput";

describe("TagInput", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders existing tags", () => {
    render(<TagInput entryId="e1" />);
    expect(screen.getByText("critical")).toBeInTheDocument();
    expect(screen.getByText("exploit")).toBeInTheDocument();
  });

  it("shows entry count for each tag", () => {
    render(<TagInput entryId="e1" />);
    expect(screen.getByText("(5)")).toBeInTheDocument();
    expect(screen.getByText("(3)")).toBeInTheDocument();
  });

  it("highlights active tags", () => {
    render(<TagInput entryId="e1-tagged" />);
    const criticalBtn = screen.getByText("critical").closest("button");
    expect(criticalBtn?.className).toContain("active");
  });

  it("renders search/create tag input", () => {
    render(<TagInput entryId="e1" />);
    expect(screen.getByPlaceholderText("Search or create tag...")).toBeInTheDocument();
  });

  it("shows color picker and create button when typing new tag name", async () => {
    const user = userEvent.setup();
    render(<TagInput entryId="e1" />);
    await user.type(screen.getByPlaceholderText("Search or create tag..."), "newtag");
    const colorInput = document.querySelector('input[type="color"]');
    expect(colorInput).toBeInTheDocument();
    expect(screen.getByText(/Create "newtag"/)).toBeInTheDocument();
  });

  it("does not show create button when input matches existing tag", async () => {
    const user = userEvent.setup();
    render(<TagInput entryId="e1" />);
    await user.type(screen.getByPlaceholderText("Search or create tag..."), "critical");
    expect(screen.queryByText(/Create/)).not.toBeInTheDocument();
  });

  it("shows close button when onClose provided", () => {
    const onClose = vi.fn();
    render(<TagInput entryId="e1" onClose={onClose} />);
    const closeBtn = screen.getAllByRole("button").find((b) => b.textContent === "\u00d7");
    expect(closeBtn).toBeInTheDocument();
  });

  it("toggles tag on click (add)", async () => {
    const user = userEvent.setup();
    render(<TagInput entryId="e1" />);
    await user.click(screen.getByText("critical"));
    expect(mockAddTags).toHaveBeenCalledWith({ entryId: "e1", tagIds: ["t1"] });
  });

  it("removes active tag on click", async () => {
    const user = userEvent.setup();
    render(<TagInput entryId="e1-tagged" />);
    await user.click(screen.getByText("critical"));
    expect(mockRemoveTag).toHaveBeenCalledWith({ entryId: "e1-tagged", tagId: "t1" });
  });
});
