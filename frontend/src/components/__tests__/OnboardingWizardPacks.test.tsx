import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";

const mockImportPacks = vi.fn();

const PACKS = [
  {
    id: "core",
    title: "Core",
    description: "Major security news, CERT advisories and vendor research.",
    feed_count: 37,
    recommended: true,
    requires: null,
  },
  {
    id: "github-rules",
    title: "Detection rule repositories",
    description: "Sigma, Elastic, Splunk and YARA repositories.",
    feed_count: 20,
    recommended: false,
    requires: "A GitHub token",
  },
];

vi.mock("@/hooks/useFeeds", () => ({
  useFeeds: () => ({ data: { total: 0, items: [] } }),
  useAddFeed: () => ({ mutateAsync: vi.fn() }),
  useStarterPacks: () => ({ data: PACKS }),
  useImportStarterPacks: () => ({
    mutateAsync: mockImportPacks,
    isPending: false,
    isSuccess: false,
  }),
}));

vi.mock("@/hooks/useAuth", () => ({
  useUpdateProfile: () => ({ mutate: vi.fn() }),
}));
vi.mock("@/hooks/useAI", () => ({ useCreateAIProvider: () => ({ mutateAsync: vi.fn() }) }));
vi.mock("@/hooks/useThemes", () => ({
  useThemes: () => ({ data: [] }),
  useSetThemePreference: () => ({ mutate: vi.fn() }),
}));
vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: unknown) => unknown) =>
    selector({ user: { id: "u1", role: "admin", settings: {} } }),
}));
vi.mock("@tanstack/react-query", () => ({
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
}));
vi.mock("@/api/client", () => ({ default: { post: vi.fn() } }));

const { OnboardingWizard } = await import("../OnboardingWizard");

/** Walk from the welcome step to the starter-packs step. */
async function openPacksStep(user: ReturnType<typeof userEvent.setup>) {
  render(<OnboardingWizard />);
  await user.click(screen.getByRole("button", { name: /next/i }));
  return screen.getByText("Start With Recommended Feeds");
}

describe("OnboardingWizard starter packs", () => {
  beforeEach(() => {
    mockImportPacks.mockReset();
    mockImportPacks.mockResolvedValue({
      feeds_added: 37,
      feeds_skipped: 0,
      categories_created: 5,
      errors: [],
      packs: [{ id: "core", title: "Core", feeds_added: 37 }],
    });
  });

  it("pre-selects only the recommended pack and totals its feeds", async () => {
    const user = userEvent.setup();
    await openPacksStep(user);

    const checkboxes = screen.getAllByRole("checkbox");
    expect(checkboxes[0]).toBeChecked(); // core, recommended
    expect(checkboxes[1]).not.toBeChecked();
    expect(screen.getByRole("button", { name: "Add 37 feeds" })).toBeEnabled();
  });

  it("adds the selected packs' feed counts together", async () => {
    const user = userEvent.setup();
    await openPacksStep(user);

    await user.click(screen.getAllByRole("checkbox")[1]);
    expect(screen.getByRole("button", { name: "Add 57 feeds" })).toBeEnabled();
  });

  it("surfaces a pack's prerequisite once it is selected", async () => {
    const user = userEvent.setup();
    await openPacksStep(user);

    expect(screen.queryByText(/Needs: A GitHub token/)).not.toBeInTheDocument();
    await user.click(screen.getAllByRole("checkbox")[1]);
    expect(screen.getByText(/Needs: A GitHub token/)).toBeInTheDocument();
  });

  it("imports nothing until the button is pressed, then reports what it added", async () => {
    const user = userEvent.setup();
    await openPacksStep(user);
    expect(mockImportPacks).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Add 37 feeds" }));

    expect(mockImportPacks).toHaveBeenCalledWith(["core"]);
    await waitFor(() =>
      expect(screen.getByText(/Added 37 feeds in 5 categories/)).toBeInTheDocument(),
    );
  });

  it("disables the button when every pack is deselected", async () => {
    const user = userEvent.setup();
    await openPacksStep(user);

    await user.click(screen.getAllByRole("checkbox")[0]);
    expect(screen.getByRole("button", { name: /select a pack/i })).toBeDisabled();
  });

  it("explains the failure without losing the selection", async () => {
    mockImportPacks.mockRejectedValue(new Error("boom"));
    const user = userEvent.setup();
    await openPacksStep(user);

    await user.click(screen.getByRole("button", { name: "Add 37 feeds" }));
    await waitFor(() =>
      expect(screen.getByText(/Could not add the recommended feeds/)).toBeInTheDocument(),
    );
    expect(screen.getAllByRole("checkbox")[0]).toBeChecked();
  });
});
