import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Category, Feed } from "@/api/types";

const mockBulk = vi.fn().mockResolvedValue({ updated: 1, feed_defaults: {} });
const mockUpdateCategory = vi.fn().mockResolvedValue({});
const mockConfirm = vi.fn();

vi.mock("@/hooks/useFeeds", () => ({
  useBulkUpdateCategoryFeeds: () => ({ mutateAsync: mockBulk, isPending: false }),
  useUpdateCategory: () => ({ mutateAsync: mockUpdateCategory, isPending: false }),
}));
vi.mock("@/hooks/useFocusTrap", () => ({ useFocusTrap: () => ({ current: null }) }));
vi.mock("@/utils/dialog", () => ({ confirmDialog: (...a: unknown[]) => mockConfirm(...a) }));

import { EditCategoryModal, describeDefaults } from "../EditCategoryModal";

function makeCategory(overrides: Partial<Category> = {}): Category {
  return {
    id: "cat-1",
    name: "Vendor Research",
    parent_id: null,
    position: 0,
    created_at: "2026-01-01T00:00:00Z",
    children: [],
    feed_count: 2,
    feed_defaults: {},
    ...overrides,
  };
}

const feeds = [
  { id: "f1", extract_tools: true, ai_analysis_enabled: true } as Feed,
  { id: "f2", extract_tools: true, ai_analysis_enabled: true } as Feed,
];

beforeEach(() => {
  mockBulk.mockClear();
  mockUpdateCategory.mockClear();
  mockConfirm.mockReset();
  mockConfirm.mockResolvedValue(true);
});

describe("describeDefaults", () => {
  it("reads nothing as no defaults", () => {
    expect(describeDefaults(undefined)).toBeNull();
    expect(describeDefaults({})).toBeNull();
  });

  it("names each saved default", () => {
    const text = describeDefaults({ ai_analysis_enabled: false, extract_tools: false });
    expect(text).toMatch(/ off; .* off$/);
  });
});

describe("EditCategoryModal", () => {
  it("says the change is for the feeds there now unless saved as a default", () => {
    render(<EditCategoryModal category={makeCategory()} feeds={feeds} onClose={vi.fn()} />);
    expect(screen.getByText(/apply to the 2 feeds in this category now/i)).toBeInTheDocument();
    expect(screen.getByText("Feeds added here later start with the global defaults.")).toBeInTheDocument();
  });

  it("applies to the feeds now by default, without touching the defaults", async () => {
    const user = userEvent.setup();
    render(<EditCategoryModal category={makeCategory()} feeds={feeds} onClose={vi.fn()} />);

    await user.selectOptions(screen.getByLabelText(/AI/, { selector: "select" }), "off");
    await user.click(screen.getByRole("button", { name: "Apply to 2" }));

    await waitFor(() => expect(mockBulk).toHaveBeenCalled());
    expect(mockBulk.mock.calls[0][0].data).toEqual({
      apply_to_feeds: true,
      save_as_category_default: false,
      ai_analysis_enabled: false,
    });
  });

  it("can save the pipeline settings as the category default only", async () => {
    const user = userEvent.setup();
    render(<EditCategoryModal category={makeCategory()} feeds={feeds} onClose={vi.fn()} />);

    await user.selectOptions(screen.getByLabelText(/AI/, { selector: "select" }), "off");
    await user.selectOptions(screen.getByLabelText("Check for new articles"), "60");
    await user.click(screen.getByLabelText(/Apply to the 2 feeds here now/));
    await user.click(screen.getByLabelText(/Save the pipeline settings as this category/));
    await user.click(screen.getByRole("button", { name: "Save default" }));

    await waitFor(() => expect(mockBulk).toHaveBeenCalled());
    expect(mockConfirm.mock.calls[0][0].message).toMatch(/already there stay as they are/);
    // The interval is never a default, so it is not sent when only defaults are saved.
    expect(mockBulk.mock.calls[0][0].data).toEqual({
      apply_to_feeds: false,
      save_as_category_default: true,
      ai_analysis_enabled: false,
    });
  });

  it("shows saved defaults and can clear them", async () => {
    const user = userEvent.setup();
    render(
      <EditCategoryModal
        category={makeCategory({ feed_defaults: { extract_tools: false } })}
        feeds={feeds}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByText(/Feeds added here later start with:/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Clear" }));
    await waitFor(() =>
      expect(mockUpdateCategory).toHaveBeenCalledWith({
        categoryId: "cat-1",
        data: { feed_defaults: {} },
      })
    );
  });
});
