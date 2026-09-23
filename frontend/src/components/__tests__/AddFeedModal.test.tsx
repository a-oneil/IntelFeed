import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock hooks
const mockMutateAsync = vi.fn();
const mockDiscoverMutate = vi.fn();
const mockImportOpml = vi.fn();

vi.mock("@/hooks/useFeeds", () => ({
  useCategories: () => ({ data: [] }),
  useAddFeed: () => ({
    mutateAsync: mockMutateAsync,
    isPending: false,
    isError: false,
  }),
  useDiscoverFeed: () => ({
    mutate: mockDiscoverMutate,
    mutateAsync: mockDiscoverMutate,
    isPending: false,
    data: null,
    isError: false,
  }),
  useBulkSetupGitHubRepos: () => ({
    mutateAsync: vi.fn(),
    isPending: false,
    isError: false,
    isSuccess: false,
  }),
  useResolveBlueskyFeedUrl: () => ({
    mutate: vi.fn(),
    mutateAsync: vi.fn(),
    isPending: false,
    isError: false,
    data: null,
  }),
  useImportOpml: () => ({
    mutateAsync: mockImportOpml,
    reset: vi.fn(),
    isPending: false,
    isError: false,
    error: null,
    data: undefined,
  }),
}));

vi.mock("@/hooks/useFocusTrap", () => ({
  useFocusTrap: () => ({ current: null }),
}));

vi.mock("@/hooks/useIntelligence", () => ({
  useThreatActors: () => ({ data: { items: [] } }),
  useVendors: () => ({ data: { items: [] } }),
  useProducts: () => ({ data: { items: [] } }),
}));

vi.mock("@/hooks/useCampaigns", () => ({
  useCampaigns: () => ({ data: { items: [] } }),
}));

vi.mock("@/hooks/useTelegram", () => ({
  useDiscoverTelegramChannelsLazy: () => ({
    mutate: vi.fn(),
    data: undefined,
    isPending: false,
    isError: false,
  }),
}));

import { AddFeedModal } from "../AddFeedModal";

describe("AddFeedModal", () => {
  const onClose = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the add feed modal with URL input", () => {
    render(<AddFeedModal onClose={onClose} />);
    expect(screen.getByText("Add Feed")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Enter feed URL or website URL...")).toBeInTheDocument();
    expect(screen.getByText("Discover")).toBeInTheDocument();
  });

  it("shows mode tabs for URL and GitHub Repo", () => {
    render(<AddFeedModal onClose={onClose} />);
    expect(screen.getByText("Feed URL")).toBeInTheDocument();
    expect(screen.getByText("GitHub Repo")).toBeInTheDocument();
  });

  it("calls discover when Discover button is clicked", async () => {
    const user = userEvent.setup();
    render(<AddFeedModal onClose={onClose} />);

    const input = screen.getByPlaceholderText("Enter feed URL or website URL...");
    await user.type(input, "https://blog.example.com/rss");
    await user.click(screen.getByText("Discover"));

    expect(mockDiscoverMutate).toHaveBeenCalledWith("https://blog.example.com/rss");
  });

  it("disables Discover button when input is empty", () => {
    render(<AddFeedModal onClose={onClose} />);
    expect(screen.getByText("Discover")).toBeDisabled();
  });

  it("calls onClose when close button is clicked", async () => {
    const user = userEvent.setup();
    render(<AddFeedModal onClose={onClose} />);
    await user.click(screen.getByLabelText("Close"));
    expect(onClose).toHaveBeenCalled();
  });

  it("renders Bluesky tab and switches to it", async () => {
    const user = userEvent.setup();
    render(<AddFeedModal onClose={onClose} />);
    await user.click(screen.getByText("Bluesky"));
    expect(screen.getByPlaceholderText("alice.bsky.social")).toBeInTheDocument();
  });

  it("previews an OPML file and imports it", async () => {
    const user = userEvent.setup();
    mockImportOpml.mockResolvedValueOnce({
      feeds_added: 2,
      feeds_skipped: 0,
      categories_created: 1,
    });
    render(<AddFeedModal onClose={onClose} />);
    await user.click(screen.getByText("OPML"));

    const opml = `<?xml version="1.0"?><opml version="1.0"><body>
      <outline text="Security">
        <outline type="rss" text="A" xmlUrl="https://a.example.com/rss" />
        <outline type="rss" text="B" xmlUrl="https://b.example.com/rss" />
      </outline>
    </body></opml>`;
    const file = new File([opml], "subs.opml", { type: "text/xml" });
    // jsdom's File lacks .text() in some versions
    Object.defineProperty(file, "text", { value: () => Promise.resolve(opml) });

    await user.upload(screen.getByTestId("opml-file-input"), file);
    const importBtn = await screen.findByText("Import 2 feeds");
    expect(screen.getByText(/2 feeds in 1 category/)).toBeInTheDocument();

    await user.click(importBtn);
    expect(mockImportOpml).toHaveBeenCalledWith(file);
  });

  it("rejects a file that is not OPML", async () => {
    const user = userEvent.setup();
    render(<AddFeedModal onClose={onClose} />);
    await user.click(screen.getByText("OPML"));

    const file = new File(["not xml at all"], "notes.opml", { type: "text/xml" });
    Object.defineProperty(file, "text", { value: () => Promise.resolve("not xml at all") });
    await user.upload(screen.getByTestId("opml-file-input"), file);

    expect(
      await screen.findByText("This doesn't look like an OPML subscription file.")
    ).toBeInTheDocument();
    expect(mockImportOpml).not.toHaveBeenCalled();
  });

  it("renders Telegram tab and switches to it", async () => {
    const user = userEvent.setup();
    render(<AddFeedModal onClose={onClose} />);
    await user.click(screen.getByText("Telegram"));
    expect(screen.getByPlaceholderText("@channelname or t.me/channel")).toBeInTheDocument();
  });

  it("submits a Telegram channel feed", async () => {
    const user = userEvent.setup();
    mockMutateAsync.mockResolvedValueOnce({});
    render(<AddFeedModal onClose={onClose} />);
    await user.click(screen.getByText("Telegram"));
    await user.type(
      screen.getByPlaceholderText("@channelname or t.me/channel"),
      "@breachintelligence"
    );
    const subscribeButtons = screen.getAllByText("Subscribe");
    await user.click(subscribeButtons[subscribeButtons.length - 1]);
    expect(mockMutateAsync).toHaveBeenCalledWith(
      expect.objectContaining({
        feed_type: "telegram",
        url: "https://t.me/breachintelligence",
        adapter_config: expect.objectContaining({
          channel: "@breachintelligence",
          include_media: true,
          extract_forwards: true,
        }),
      })
    );
  });

  it("submits a Bluesky author feed", async () => {
    const user = userEvent.setup();
    mockMutateAsync.mockResolvedValueOnce({});
    render(<AddFeedModal onClose={onClose} />);
    await user.click(screen.getByText("Bluesky"));
    await user.type(
      screen.getByPlaceholderText("alice.bsky.social"),
      "taviso.bsky.social"
    );
    // The Bluesky tab has its own Subscribe button after the form
    const subscribeButtons = screen.getAllByText("Subscribe");
    await user.click(subscribeButtons[subscribeButtons.length - 1]);
    expect(mockMutateAsync).toHaveBeenCalledWith(
      expect.objectContaining({
        feed_type: "bluesky",
        adapter_config: expect.objectContaining({
          mode: "author",
          handle: "taviso.bsky.social",
        }),
      })
    );
  });
});
