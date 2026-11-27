import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { LinkPreview } from "@/api/types";

const mockMutateAsync = vi.fn();
const mockImportOpml = vi.fn();
const mockImportPack = vi.fn();
let mockCategories: { id: string; name: string; children?: unknown[] }[] = [];
let mockPreviews: Record<string, LinkPreview | "error"> = {};

vi.mock("@/hooks/useFeeds", () => ({
  useCategories: () => ({ data: mockCategories }),
  useAddFeed: () => ({ mutateAsync: mockMutateAsync, isPending: false, isError: false }),
  useLinkPreview: (url: string) => {
    const found = url ? mockPreviews[url] : undefined;
    if (found === "error") {
      return {
        data: undefined,
        isFetching: false,
        isError: true,
        error: { response: { data: { error: { message: "Couldn't open this link, or it has no feed." } } } },
      };
    }
    return { data: found, isFetching: false, isError: false, error: null };
  },
  useCategorySuggestion: () => ({ data: null }),
  useCreateCategory: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useImportOpml: () => ({
    mutateAsync: mockImportOpml,
    reset: vi.fn(),
    isPending: false,
    isError: false,
    error: null,
    data: undefined,
  }),
  useStarterPacks: () => ({
    data: [
      { id: "core", title: "Core", description: "", feed_count: 3, followed_count: 1, recommended: true, requires: null },
      { id: "podcasts", title: "Podcasts", description: "", feed_count: 2, followed_count: 0, recommended: false, requires: null },
    ],
    isLoading: false,
  }),
  useStarterPackFeeds: (packId: string | null) => ({
    data:
      packId === "core"
        ? [
            { url: "https://a.example/rss", title: "Alpha", feed_type: "rss", followed: true },
            { url: "https://b.example/rss", title: "Bravo", feed_type: "rss", followed: false },
            { url: "https://c.example/rss", title: "Charlie", feed_type: "rss", followed: false },
          ]
        : undefined,
    isLoading: false,
  }),
  useImportStarterPackFeeds: () => ({ mutateAsync: mockImportPack, isPending: false, isError: false }),
}));

vi.mock("@/hooks/useFocusTrap", () => ({ useFocusTrap: () => ({ current: null }) }));
// Look links up the moment they are typed.
vi.mock("@/hooks/useDebouncedValue", () => ({ useDebouncedValue: <T,>(v: T) => v }));

import { AddFeedModal } from "../AddFeedModal";

function preview(overrides: Partial<LinkPreview>): LinkPreview {
  return {
    kind: "feed",
    title: "Example",
    feed_type: "rss",
    url: "https://example.com/feed",
    feeds: [],
    github: null,
    bluesky: null,
    telegram: null,
    mastodon: null,
    page: null,
    warning: null,
    suggested_category_id: null,
    fetch_interval_minutes: 30,
    ...overrides,
  };
}

const YOUTUBE = preview({
  title: "Black Hat",
  feed_type: "youtube",
  url: "https://www.youtube.com/feeds/videos.xml?channel_id=UC1",
  feeds: [{ url: "https://www.youtube.com/feeds/videos.xml?channel_id=UC1", title: "Black Hat", feed_type: "youtube", description: null }],
});

const SITE = preview({
  title: "The DFIR Report",
  url: "https://thedfirreport.com/feed/",
  feeds: [
    { url: "https://thedfirreport.com/feed/", title: "The DFIR Report", feed_type: "rss", description: null },
    { url: "https://thedfirreport.com/comments/feed/", title: "The DFIR Report » Comments Feed", feed_type: "rss", description: null },
  ],
});

const SIGMA = preview({
  kind: "github",
  title: "SigmaHQ/sigma",
  feed_type: "github_repo",
  url: "https://github.com/SigmaHQ/sigma",
  fetch_interval_minutes: 1440,
  github: {
    owner: "SigmaHQ",
    repo: "sigma",
    default_branch: "master",
    has_releases: true,
    rules: { label: "Sigma rules", paths: ["rules/**/*.yml"], folders: ["rules/"], branch: "master" },
  },
});

const PLAIN_REPO = preview({
  kind: "github",
  title: "owner/project",
  feed_type: "github_repo",
  url: "https://github.com/owner/project",
  github: { owner: "owner", repo: "project", default_branch: "main", has_releases: true, rules: null },
});

const PAGE = preview({
  kind: "page",
  title: "Research | Example",
  feed_type: "web_scraper",
  url: "https://example.com/research",
  page: { article_links: 12, label: "example.com/research" },
});

const TELEGRAM = preview({
  kind: "telegram",
  title: "Breach Intel",
  feed_type: "telegram",
  url: "https://t.me/breachintel",
  telegram: { channel: "breachintel" },
  warning: "Telegram isn't connected on this server yet. An admin connects it once in Settings.",
});

async function paste(text: string) {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText("Link"), text);
  return user;
}

describe("AddFeedModal", () => {
  const onClose = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    mockCategories = [];
    mockPreviews = {
      "youtube.com/@BlackHatOfficialYT": YOUTUBE,
      "thedfirreport.com": SITE,
      "github.com/SigmaHQ/sigma": SIGMA,
      "github.com/owner/project": PLAIN_REPO,
      "example.com/research": PAGE,
      "t.me/breachintel": TELEGRAM,
      "nowhere.example": "error",
    };
  });

  it("opens on one paste box and the three other ways in", () => {
    render(<AddFeedModal onClose={onClose} />);
    expect(screen.getByRole("heading", { name: "Add a source" })).toBeInTheDocument();
    expect(screen.getByLabelText("Link")).toBeInTheDocument();
    expect(screen.getByText("Browse starter packs")).toBeInTheDocument();
    expect(screen.getByText("Import OPML")).toBeInTheDocument();
    expect(screen.getByText("Add without a link")).toBeInTheDocument();
    expect(screen.queryByText("Subscribe")).not.toBeInTheDocument();
  });

  it("says what a YouTube channel is and subscribes with Skip Shorts", async () => {
    mockMutateAsync.mockResolvedValueOnce({ id: "f1" });
    const onAdded = vi.fn();
    render(<AddFeedModal onClose={onClose} onAdded={onAdded} />);
    const user = await paste("youtube.com/@BlackHatOfficialYT");

    expect(screen.getByText("Black Hat")).toBeInTheDocument();
    expect(screen.getByText("YouTube channel")).toBeInTheDocument();
    const shorts = screen.getByLabelText("Skip Shorts");
    expect(shorts).toBeChecked();
    await user.click(shorts);

    await user.click(screen.getByText("Subscribe"));
    expect(mockMutateAsync).toHaveBeenCalledWith(
      expect.objectContaining({ url: YOUTUBE.url, exclude_shorts: false })
    );
    expect(onAdded).toHaveBeenCalledWith({ id: "f1" });
    expect(onClose).not.toHaveBeenCalled();
  });

  it("offers Posts or Comments when a site has both", async () => {
    mockMutateAsync.mockResolvedValueOnce({ id: "f2" });
    render(<AddFeedModal onClose={onClose} />);
    const user = await paste("thedfirreport.com");

    expect(screen.getByText("Website · 2 feeds")).toBeInTheDocument();
    expect(screen.getByLabelText("Posts")).toBeChecked();
    await user.click(screen.getByLabelText("Comments"));
    await user.click(screen.getByText("Subscribe"));
    expect(mockMutateAsync).toHaveBeenCalledWith(
      expect.objectContaining({ url: "https://thedfirreport.com/comments/feed/" })
    );
  });

  it("follows a rule repo's rule files by default", async () => {
    mockMutateAsync.mockResolvedValueOnce({ id: "f3" });
    render(<AddFeedModal onClose={onClose} />);
    const user = await paste("github.com/SigmaHQ/sigma");

    expect(screen.getByText(/Found Sigma rules under rules\//)).toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: /File changes/ })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: /Releases/ })).not.toBeChecked();
    expect(screen.getByLabelText("Paths to watch")).toHaveValue("rules/**/*.yml");

    await user.click(screen.getByText("Subscribe"));
    expect(mockMutateAsync).toHaveBeenCalledTimes(1);
    expect(mockMutateAsync).toHaveBeenCalledWith(
      expect.objectContaining({
        url: "https://github.com/SigmaHQ/sigma",
        feed_type: "github_repo",
        adapter_config: expect.objectContaining({ branch: "master", paths: ["rules/**/*.yml"] }),
      })
    );
    // The server's own github_repo default applies unless the user picks one.
    expect(mockMutateAsync.mock.calls[0][0]).not.toHaveProperty("fetch_interval_minutes");
  });

  it("follows any repo for its releases, and adds one feed per choice", async () => {
    mockMutateAsync.mockResolvedValueOnce({ id: "r" }).mockResolvedValueOnce({ id: "c" });
    const onAdded = vi.fn();
    render(<AddFeedModal onClose={onClose} onAdded={onAdded} />);
    const user = await paste("github.com/owner/project");

    expect(screen.getByText("No detection rules in this repo. Pick what to follow.")).toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: /Releases/ })).toBeChecked();
    await user.click(screen.getByRole("checkbox", { name: /Commits/ }));

    await user.click(screen.getByText("Subscribe to 2"));
    expect(mockMutateAsync).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ url: "https://github.com/owner/project/releases", feed_type: "github_releases" })
    );
    expect(mockMutateAsync).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ url: "https://github.com/owner/project/commits/main.atom" })
    );
    // Two feeds: no settings dialog for one of them, just close.
    expect(onAdded).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it("can't subscribe to a repo with nothing ticked", async () => {
    render(<AddFeedModal onClose={onClose} />);
    const user = await paste("github.com/owner/project");
    await user.click(screen.getByRole("checkbox", { name: /Releases/ }));
    expect(screen.getByText("Subscribe")).toBeDisabled();
  });

  it("offers to read a page that has no feed", async () => {
    mockMutateAsync.mockResolvedValueOnce({ id: "f4" });
    render(<AddFeedModal onClose={onClose} />);
    const user = await paste("example.com/research");

    expect(screen.getByText("example.com/research")).toBeInTheDocument();
    expect(screen.getByText(/It found 12 article links on it/)).toBeInTheDocument();
    await user.click(screen.getByText("Follow this page"));
    expect(mockMutateAsync).toHaveBeenCalledWith(
      expect.objectContaining({
        feed_type: "web_scraper",
        adapter_config: expect.objectContaining({ blog_url: "https://example.com/research" }),
      })
    );
    // The page names the feed on its first fetch.
    expect(mockMutateAsync.mock.calls[0][0]).not.toHaveProperty("custom_title");
  });

  it("warns when Telegram isn't connected", async () => {
    render(<AddFeedModal onClose={onClose} />);
    await paste("t.me/breachintel");
    expect(screen.getByText("Telegram channel")).toBeInTheDocument();
    expect(screen.getByText(/Telegram isn't connected on this server yet/)).toBeInTheDocument();
  });

  it("says when a link leads nowhere", async () => {
    render(<AddFeedModal onClose={onClose} />);
    await paste("nowhere.example");
    expect(screen.getByText("Couldn't open this link, or it has no feed.")).toBeInTheDocument();
    expect(screen.queryByText("Subscribe")).not.toBeInTheDocument();
  });

  it("preselects the suggested folder and requires one when folders exist", async () => {
    mockCategories = [
      { id: "cat-yt", name: "YouTube", children: [] },
      { id: "cat-news", name: "News", children: [] },
    ];
    mockPreviews["youtube.com/@BlackHatOfficialYT"] = { ...YOUTUBE, suggested_category_id: "cat-yt" };
    mockPreviews["thedfirreport.com"] = { ...SITE, suggested_category_id: null };
    render(<AddFeedModal onClose={onClose} />);
    const user = await paste("youtube.com/@BlackHatOfficialYT");
    expect(screen.getByLabelText("Folder")).toHaveValue("cat-yt");
    expect(screen.getByText("Subscribe")).toBeEnabled();

    await user.clear(screen.getByLabelText("Link"));
    await user.type(screen.getByLabelText("Link"), "thedfirreport.com");
    expect(screen.getByLabelText("Folder")).toHaveValue("");
    expect(screen.getByText("Subscribe")).toBeDisabled();
    await user.selectOptions(screen.getByLabelText("Folder"), "cat-news");
    expect(screen.getByText("Subscribe")).toBeEnabled();
  });

  it("sends the interval and name only when changed under More options", async () => {
    mockMutateAsync.mockResolvedValueOnce({ id: "f5" });
    render(<AddFeedModal onClose={onClose} />);
    const user = await paste("thedfirreport.com");
    await user.click(screen.getByText("More options"));
    await user.selectOptions(screen.getByLabelText("Check"), "60");
    await user.type(screen.getByLabelText("Name"), "DFIR");
    await user.click(screen.getByText("Subscribe"));
    expect(mockMutateAsync).toHaveBeenCalledWith(
      expect.objectContaining({ fetch_interval_minutes: 60, custom_title: "DFIR" })
    );
  });

  it("Back clears the link", async () => {
    render(<AddFeedModal onClose={onClose} />);
    const user = await paste("thedfirreport.com");
    await user.click(screen.getByText("Back"));
    expect(screen.getByLabelText("Link")).toHaveValue("");
    expect(screen.getByText("Browse starter packs")).toBeInTheDocument();
  });

  it("adds the ticked feeds of one starter pack", async () => {
    mockImportPack.mockResolvedValueOnce({ feeds_added: 1, feeds_skipped: 0, categories_created: 0, errors: [], packs: [] });
    const user = userEvent.setup();
    render(<AddFeedModal onClose={onClose} />);
    await user.click(screen.getByText("Browse starter packs"));

    expect(screen.getByRole("heading", { name: "Starter packs" })).toBeInTheDocument();
    expect(screen.getByText("Following 1 of 3")).toBeInTheDocument();
    expect(screen.getByText("2 sources")).toBeInTheDocument();
    expect(screen.getByText("Pick a pack")).toBeDisabled();

    await user.click(screen.getByText("Core"));
    const alpha = screen.getByRole("checkbox", { name: "Alpha" });
    expect(alpha).toBeChecked();
    expect(alpha).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: "Charlie" }));

    await user.click(screen.getByText("Add 1"));
    expect(mockImportPack).toHaveBeenCalledWith({ packId: "core", urls: ["https://b.example/rss"] });
    expect(onClose).toHaveBeenCalled();
  });

  it("adds an NVD keyword feed without a link", async () => {
    mockMutateAsync.mockResolvedValueOnce({ id: "nvd" });
    const onAdded = vi.fn();
    const user = userEvent.setup();
    render(<AddFeedModal onClose={onClose} onAdded={onAdded} />);
    await user.click(screen.getByText("Add without a link"));

    const sources = screen.getByRole("radiogroup", { name: "Source" });
    expect(within(sources).getByRole("radio", { name: /NVD CVEs/ })).toHaveAttribute("aria-checked", "true");
    await user.type(screen.getByLabelText("Words to match"), "fortinet, ivanti");
    await user.click(screen.getByText("Subscribe"));
    expect(mockMutateAsync).toHaveBeenCalledWith(
      expect.objectContaining({ feed_type: "nvd", adapter_config: { keywords: ["fortinet", "ivanti"] } })
    );
    expect(onAdded).toHaveBeenCalledWith({ id: "nvd" });
  });

  it("adds a Mastodon hashtag without a link", async () => {
    mockMutateAsync.mockResolvedValueOnce({ id: "m" });
    const user = userEvent.setup();
    render(<AddFeedModal onClose={onClose} />);
    await user.click(screen.getByText("Add without a link"));
    await user.click(screen.getByRole("radio", { name: /Mastodon hashtag/ }));
    await user.type(screen.getByLabelText("Hashtag and server"), "#threatintel on infosec.exchange");
    await user.click(screen.getByText("Subscribe"));
    expect(mockMutateAsync).toHaveBeenCalledWith(
      expect.objectContaining({
        url: "https://infosec.exchange/tags/threatintel",
        feed_type: "mastodon",
        adapter_config: { instance_url: "https://infosec.exchange", hashtags: ["threatintel"] },
      })
    );
  });

  it("previews an OPML file and imports it", async () => {
    mockImportOpml.mockResolvedValueOnce({ feeds_added: 2, feeds_skipped: 0, categories_created: 1 });
    const user = userEvent.setup();
    render(<AddFeedModal onClose={onClose} />);
    await user.click(screen.getByText("Import OPML"));

    const opml = `<?xml version="1.0"?><opml version="1.0"><body>
      <outline text="Security">
        <outline type="rss" text="A" xmlUrl="https://a.example.com/rss" />
        <outline type="rss" text="B" xmlUrl="https://b.example.com/rss" />
      </outline>
    </body></opml>`;
    const file = new File([opml], "subs.opml", { type: "text/xml" });
    Object.defineProperty(file, "text", { value: () => Promise.resolve(opml) });

    await user.upload(screen.getByTestId("opml-file-input"), file);
    const importBtn = await screen.findByText("Import 2 feeds");
    expect(screen.getByText(/2 feeds in 1 folder/)).toBeInTheDocument();
    await user.click(importBtn);
    expect(mockImportOpml).toHaveBeenCalledWith(file);
  });

  it("rejects a file that is not OPML", async () => {
    const user = userEvent.setup();
    render(<AddFeedModal onClose={onClose} />);
    await user.click(screen.getByText("Import OPML"));
    const file = new File(["not xml at all"], "notes.opml", { type: "text/xml" });
    Object.defineProperty(file, "text", { value: () => Promise.resolve("not xml at all") });
    await user.upload(screen.getByTestId("opml-file-input"), file);
    expect(await screen.findByText("This file is not an OPML subscription file.")).toBeInTheDocument();
    expect(mockImportOpml).not.toHaveBeenCalled();
  });

  it("closes from the close button", async () => {
    const user = userEvent.setup();
    render(<AddFeedModal onClose={onClose} />);
    await user.click(screen.getByLabelText("Close"));
    expect(onClose).toHaveBeenCalled();
  });
});
