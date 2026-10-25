import { render as rtlRender, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Feed } from "@/api/types";

const mockUpdateAsync = vi.fn().mockResolvedValue({});
const mockTitlePreview = vi.fn();
const mockUpdateMutate = vi.fn();
let aiUsage: Record<string, unknown> | undefined;
const mockConfirm = vi.fn();
let role = "admin";

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: unknown) => unknown) =>
    selector({ user: { id: "u1", username: "aoneil", role } }),
}));

vi.mock("@/hooks/useFeeds", () => ({
  useCategories: () => ({ data: [{ id: "cat-1", name: "News" }] }),
  useUpdateFeed: () => ({ mutateAsync: mockUpdateAsync, mutate: mockUpdateMutate, isPending: false }),
  useFeedAIUsage: (_id: string, enabled: boolean) => ({ data: enabled ? aiUsage : undefined }),
  useDeleteFeed: () => ({ mutate: vi.fn(), isPending: false }),
  useRefreshFeed: () => ({ mutate: vi.fn(), isPending: false }),
  useFullSyncFeed: () => ({ mutate: vi.fn(), isPending: false }),
  useFeedPipeline: () => ({
    data: { engine_enabled: false, stages: {}, decided_by: {} },
    isLoading: false,
  }),
  useFeedValue: () => ({
    data: {
      feed_id: "feed-1",
      scored: true,
      tier: "B",
      articles: 142,
      entity_introductions: 11,
      correlation_events: 3,
      detection_rules: 0,
      pir_matches: 2,
      rank: 4,
      of: 37,
      days: 90,
    },
    isLoading: false,
  }),
  useFeedSubscribers: () => ({
    data: { subscribers: [], non_subscribers: [], muted_count: 0, per_user_active: true },
    isLoading: false,
  }),
  useTitleFilterPreview: (...a: unknown[]) => mockTitlePreview(...a),
  usePushFeedToUsers: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useRemoveFeedSubscriber: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));

vi.mock("@/hooks/useFocusTrap", () => ({ useFocusTrap: () => ({ current: null }) }));
vi.mock("@/hooks/useUndoableDelete", () => ({ useUndoableDelete: () => vi.fn() }));
vi.mock("@/hooks/useSystemSettings", () => ({
  useSystemSettings: () => ({ data: { settings: { ai_one_pass_enabled: { value: true } } } }),
}));
const mockBulkExtract = vi.fn();
vi.mock("@/hooks/useIntelligence", () => ({
  useThreatActors: () => ({ data: { items: [] } }),
  useVendors: () => ({ data: { items: [] } }),
  useProducts: () => ({ data: { items: [] } }),
  useBulkExtract: () => ({ mutate: mockBulkExtract, isPending: false }),
  useBulkTranslate: () => ({ mutate: vi.fn(), isPending: false }),
}));
vi.mock("@/hooks/useCampaigns", () => ({ useCampaigns: () => ({ data: { items: [] } }) }));
vi.mock("@/hooks/useTelegram", () => ({
  useTelegramFeedHealth: () => ({ data: null }),
  useTelegramListenerStatus: () => ({ data: null }),
}));
vi.mock("@/utils/dialog", () => ({ confirmDialog: (...a: unknown[]) => mockConfirm(...a) }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import { EditFeedModal } from "../EditFeedModal";

function makeFeed(overrides: Partial<Feed> = {}): Feed {
  return {
    id: "feed-1",
    title: "BleepingComputer",
    url: "https://www.bleepingcomputer.com/feed/",
    feed_type: "rss",
    site_url: null,
    icon_url: null,
    description: null,
    language: null,
    last_fetched_at: new Date().toISOString(),
    fetch_interval_minutes: 30,
    error_count: 0,
    last_error: null,
    is_active: true,
    adapter_config: {},
    intel_extraction_mode: "selective",
    ai_analysis_enabled: true,
    auto_extract_on_ingest: true,
    extract_detection_rules: false,
    extract_tools: true,
    reliability_rating: "B",
    timeliness_rating: null,
    relevance_rating: null,
    analyst_notes: null,
    last_reviewed_at: null,
    category_id: "cat-1",
    custom_title: null,
    is_muted: false,
    retention_days: 90,
    unread_count: 0,
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

const render = (ui: React.ReactElement) => rtlRender(<MemoryRouter>{ui}</MemoryRouter>);

const rail = () => screen.getByRole("navigation", { name: /sections/i });

beforeEach(() => {
  role = "admin";
  mockUpdateAsync.mockClear();
  mockConfirm.mockReset();
  mockConfirm.mockResolvedValue(true);
  mockTitlePreview.mockReset();
  mockUpdateMutate.mockReset();
  aiUsage = {
    feed_id: "feed-1",
    days: 30,
    runs: 412,
    tokens_input: 780_000,
    tokens_output: 24_000,
    last_run_at: null,
    ai_analysis_enabled: true,
  };
  mockTitlePreview.mockReturnValue({ data: undefined, isError: false });
});

describe("EditFeedModal", () => {
  it("opens on Overview with the feed's own evidence", () => {
    render(<EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />);

    expect(screen.getByText("B")).toBeInTheDocument();
    expect(screen.getByText("142")).toBeInTheDocument();
    expect(screen.getByText(/4 of 37 feeds/i)).toBeInTheDocument();
  });

  it("gives an admin every pane", () => {
    render(<EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />);

    const labels = Array.from(rail().querySelectorAll("button")).map((b) => b.textContent);
    expect(labels).toEqual([
      "Overview",
      "Identity",
      "Source",
      "Pipeline",
      "Assessment",
      "Readers",
    ]);
  });

  it("gives a non-admin only the panes the API will serve them", () => {
    role = "analyst";
    render(<EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />);

    const labels = Array.from(rail().querySelectorAll("button")).map((b) => b.textContent);
    expect(labels).toEqual(["Overview", "Identity", "Assessment"]);
  });

  it("switches panes from the rail", async () => {
    const user = userEvent.setup();
    render(<EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Source" }));
    expect(screen.getByLabelText("Feed URL")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Assessment" }));
    expect(screen.getByLabelText("Timeliness")).toBeInTheDocument();
  });

  it("offers every registered feed type and nothing else", async () => {
    const user = userEvent.setup();
    render(<EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Source" }));

    const options = Array.from(
      screen.getByLabelText("Read as").querySelectorAll("option")
    ).map((o) => (o as HTMLOptionElement).value);

    // `github` has no adapter; these five used to be rejected by the PUT.
    expect(options).not.toContain("github");
    for (const t of ["github_repo", "github_releases", "github_advisories", "nvd", "mastodon"]) {
      expect(options).toContain(t);
    }
  });

  it("keeps Save inert until something actually changes", async () => {
    const user = userEvent.setup();
    render(<EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />);

    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    expect(screen.getByText("No changes")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Identity" }));
    await user.type(screen.getByLabelText("Display name"), "Bleeping");

    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
    expect(screen.getByText("1 unsaved change")).toBeInTheDocument();
  });

  it("marks the pane holding the edit, since you can no longer see them all", async () => {
    const user = userEvent.setup();
    render(<EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Assessment" }));
    await user.selectOptions(screen.getByLabelText("Relevance"), "high");

    const assessment = screen.getByRole("button", { name: /Assessment/ });
    expect(assessment.querySelector('[aria-label="has unsaved changes"]')).toBeTruthy();

    const identity = screen.getByRole("button", { name: /^Identity/ });
    expect(identity.querySelector('[aria-label="has unsaved changes"]')).toBeFalsy();
  });

  it("saves only what changed", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<EditFeedModal subscription={makeFeed()} onClose={onClose} />);

    await user.click(screen.getByRole("button", { name: "Assessment" }));
    await user.selectOptions(screen.getByLabelText("Timeliness"), "good");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(mockUpdateAsync).toHaveBeenCalledTimes(1));
    expect(mockUpdateAsync).toHaveBeenCalledWith({
      feedId: "feed-1",
      data: { timeliness_rating: "good" },
    });
    expect(onClose).toHaveBeenCalled();
  });

  it("sends a null when retention is set back to keep-forever", async () => {
    const user = userEvent.setup();
    render(<EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Source" }));
    await user.selectOptions(screen.getByLabelText("Keep articles for"), "");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(mockUpdateAsync).toHaveBeenCalled());
    expect(mockUpdateAsync.mock.calls[0][0].data).toEqual({ retention_days: null });
  });

  it("previews how many recent titles an exclude list would drop", async () => {
    const user = userEvent.setup();
    mockTitlePreview.mockImplementation((_id: string, text: string) =>
      text.trim()
        ? {
            data: { checked: 100, dropped: 2, examples: ["ISC Stormcast For Monday"] },
            isError: false,
          }
        : { data: undefined, isError: false }
    );
    render(<EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Source" }));
    await user.type(
      screen.getByLabelText("Skip articles whose title contains"),
      "ISC Stormcast For"
    );

    expect(await screen.findByText("2 of the last 100 titles would be dropped.")).toBeInTheDocument();
    expect(screen.getByText("ISC Stormcast For Monday")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mockUpdateAsync).toHaveBeenCalled());
    expect(mockUpdateAsync.mock.calls[0][0].data).toEqual({
      exclude_title_patterns: "ISC Stormcast For",
    });
  });

  it("shows a rejected exclude list inline", async () => {
    const user = userEvent.setup();
    mockTitlePreview.mockReturnValue({
      data: undefined,
      isError: true,
      error: {
        response: {
          status: 422,
          data: { error: { code: "invalid_title_filter", message: '"ab" is too short to filter on' } },
        },
      },
    });
    render(<EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Source" }));
    await user.type(screen.getByLabelText("Skip articles whose title contains"), "ab");

    expect(await screen.findByRole("alert")).toHaveTextContent("too short");
  });

  it("shows what a muted feed still costs, with an admin switch for its AI", async () => {
    const user = userEvent.setup();
    render(<EditFeedModal subscription={makeFeed({ is_muted: true })} onClose={vi.fn()} />);

    expect(
      screen.getByText(/Muted, but still analysed: 412 AI runs and 804k tokens in the last 30 days/)
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Turn off AI for this feed" }));
    expect(mockUpdateMutate).toHaveBeenCalledWith(
      { feedId: "feed-1", data: { ai_analysis_enabled: false } },
      expect.anything()
    );
  });

  it("says in the Pipeline pane where an unrated feed's tags stop", async () => {
    const user = userEvent.setup();
    render(<EditFeedModal subscription={makeFeed({ reliability_rating: null })} onClose={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Pipeline" }));
    expect(
      screen.getByText(/Unrated: catalog-matched tags from this feed top out at medium/)
    ).toBeInTheDocument();
  });

  it("says nothing about AI cost for a feed that is not muted", () => {
    render(<EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />);
    expect(screen.queryByText(/still analysed/)).not.toBeInTheDocument();
  });

  it("does not offer a non-admin the AI switch", () => {
    role = "analyst";
    render(<EditFeedModal subscription={makeFeed({ is_muted: true })} onClose={vi.fn()} />);
    expect(screen.getByText(/still analysed/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Turn off AI for this feed" })).not.toBeInTheDocument();
  });

  it("closes without asking when nothing is dirty", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<EditFeedModal subscription={makeFeed()} onClose={onClose} />);

    await user.click(screen.getByRole("button", { name: "Cancel" }));

    expect(mockConfirm).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it("asks before discarding unsaved edits", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<EditFeedModal subscription={makeFeed()} onClose={onClose} />);

    await user.click(screen.getByRole("button", { name: "Identity" }));
    await user.type(screen.getByLabelText("Display name"), "x");
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    await waitFor(() => expect(mockConfirm).toHaveBeenCalled());
    expect(onClose).toHaveBeenCalled();
  });

  it("stays open when the discard prompt is declined", async () => {
    mockConfirm.mockResolvedValue(false);
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<EditFeedModal subscription={makeFeed()} onClose={onClose} />);

    await user.click(screen.getByRole("button", { name: "Identity" }));
    await user.type(screen.getByLabelText("Display name"), "x");
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    await waitFor(() => expect(mockConfirm).toHaveBeenCalled());
    expect(onClose).not.toHaveBeenCalled();
  });

  it("describes the pipeline in plain words, warning that the AI writes entities", async () => {
    const user = userEvent.setup();
    render(<EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Pipeline" }));

    expect(screen.getByText(/can add entities you do not have yet/i)).toBeInTheDocument();
    // Three stages can mint entities on this feed: the AI pass, the NVD
    // lookup, and tool creation under the AI.
    expect(screen.getAllByText("writes entities")).toHaveLength(3);
  });

  it("switching the feed off disables the rest of the pipeline", async () => {
    const user = userEvent.setup();
    render(<EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Pipeline" }));

    await user.click(screen.getByRole("checkbox", { name: /^Analyse this feed/i }));

    expect(screen.getByRole("checkbox", { name: /^Tag articles with entities/i })).toBeDisabled();
    expect(screen.getByText(/Articles still arrive, are cleaned up/i)).toBeInTheDocument();
    // No checkbox for the ledger scan — it has no switch of its own — and
    // switching the feed off stops it too, so the sentence must say so.
    expect(screen.queryByRole("checkbox", { name: /ledger/i })).toBeNull();
    expect(screen.getByText(/no indicator matching/i)).toBeInTheDocument();
  });

  it("turns the AI off for one feed without touching its autolinking", async () => {
    const user = userEvent.setup();
    render(<EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Pipeline" }));

    await user.click(screen.getByRole("checkbox", { name: /^Let the AI read each article/i }));
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(mockUpdateAsync).toHaveBeenCalled());
    // Only the AI field — autolinking rides on intel_extraction_mode and must
    // not be dragged along.
    expect(mockUpdateAsync.mock.calls[0][0].data).toEqual({ ai_analysis_enabled: false });
    expect(screen.queryByText(/can add entities you do not have yet/i)).toBeNull();
  });

  it("can backfill the articles already here, next to the switches that changed", async () => {
    const user = userEvent.setup();
    render(<EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Pipeline" }));

    await user.click(screen.getByRole("button", { name: "Re-analyse past articles" }));

    expect(mockBulkExtract).toHaveBeenCalled();
    expect(mockBulkExtract.mock.calls[0][0]).toMatchObject({ feed_id: "feed-1", use_ai: true });
  });

  it("shows a paused feed as paused and offers to resume it", () => {
    render(<EditFeedModal subscription={makeFeed({ is_active: false })} onClose={vi.fn()} />);

    expect(screen.getByText("paused")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Resume feed" })).toBeInTheDocument();
  });

  it("offers full sync only for the feed type whose endpoint accepts it", () => {
    const { unmount } = render(
      <EditFeedModal subscription={makeFeed()} onClose={vi.fn()} />
    );
    expect(screen.queryByRole("button", { name: "Full sync" })).not.toBeInTheDocument();
    unmount();

    render(
      <EditFeedModal subscription={makeFeed({ feed_type: "github_repo" })} onClose={vi.fn()} />
    );
    expect(screen.getByRole("button", { name: "Full sync" })).toBeInTheDocument();
  });

  it("surfaces the last error where you go to fix it", () => {
    render(
      <EditFeedModal
        subscription={makeFeed({ error_count: 3, last_error: "403 Forbidden" })}
        onClose={vi.fn()}
      />
    );

    expect(screen.getByText("403 Forbidden")).toBeInTheDocument();
    expect(screen.getByText(/3 recent errors/i)).toBeInTheDocument();
  });
});
