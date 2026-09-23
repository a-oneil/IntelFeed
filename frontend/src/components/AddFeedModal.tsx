import { useState } from "react";
import {
  useCategories,
  useAddFeed,
  useDiscoverFeed,
  useBulkSetupGitHubRepos,
  useResolveBlueskyFeedUrl,
  useImportOpml,
} from "@/hooks/useFeeds";
import { useThreatActors, useVendors, useProducts } from "@/hooks/useIntelligence";
import { useCampaigns } from "@/hooks/useCampaigns";
import {
  useDiscoverTelegramChannelsLazy,
  type TelegramDiscoveredChannel,
} from "@/hooks/useTelegram";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import styles from "./AddFeedModal.module.css";

type FeedMode = "url" | "github_repo" | "web_scraper" | "bluesky" | "telegram" | "opml";
type BlueskyMode = "author" | "feed" | "search";
type AuthorEntityType = "" | "threat_actor" | "vendor" | "product";

interface Props {
  onClose: () => void;
}

function parseGitHubUrl(input: string): { owner: string; repo: string } | null {
  const trimmed = input.trim();
  // owner/repo format
  const slashMatch = trimmed.match(/^([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)$/);
  if (slashMatch) return { owner: slashMatch[1], repo: slashMatch[2] };
  // Full GitHub URL
  const urlMatch = trimmed.match(/github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)/);
  if (urlMatch) return { owner: urlMatch[1], repo: urlMatch[2] };
  return null;
}

interface OpmlPreview {
  feeds: number;
  categories: string[];
  invalid: number;
}

/** Walk an OPML document the same way the server does (app/api/opml.py): one
 *  level of outline groups becomes categories, and a feed is any outline
 *  carrying an http(s) xmlUrl. Keeping the two walks in step means the counts
 *  shown before importing match what actually gets created. */
function parseOpml(text: string): OpmlPreview | null {
  const doc = new DOMParser().parseFromString(text, "application/xml");
  if (doc.getElementsByTagName("parsererror").length > 0) return null;
  const root = doc.documentElement;
  if (!root) return null;
  const body = Array.from(root.children).find(
    (el) => el.nodeName.toLowerCase() === "body"
  );
  if (!body) return null;

  const preview: OpmlPreview = { feeds: 0, categories: [], invalid: 0 };
  const countFeed = (el: Element) => {
    const xmlUrl = el.getAttribute("xmlUrl");
    if (!xmlUrl) return;
    if (/^https?:\/\//.test(xmlUrl)) preview.feeds += 1;
    else preview.invalid += 1;
  };

  for (const outline of Array.from(body.children)) {
    const children = Array.from(outline.children);
    if (children.length > 0) {
      preview.categories.push(
        outline.getAttribute("text") || outline.getAttribute("title") || "Unnamed"
      );
      children.forEach(countFeed);
    } else {
      countFeed(outline);
    }
  }
  return preview;
}

export function AddFeedModal({ onClose }: Props) {
  const [mode, setMode] = useState<FeedMode>("url");
  const [url, setUrl] = useState("");
  const [categoryId, setCategoryId] = useState<string>("");
  const [customInterval, setCustomInterval] = useState<string>("");
  const { data: categories } = useCategories();
  const discover = useDiscoverFeed();
  const addFeed = useAddFeed();
  const bulkSetup = useBulkSetupGitHubRepos();

  // GitHub repo state
  const [repoInput, setRepoInput] = useState("");
  const [branch, setBranch] = useState("main");
  const [filePatterns, setFilePatterns] = useState("**/*.yml\n**/*.yaml");
  const [includeContent, setIncludeContent] = useState(true);

  // Web scraper state
  const [scraperUrl, setScraperUrl] = useState("");
  const [linkSelector, setLinkSelector] = useState("");
  const [urlPattern, setUrlPattern] = useState("");
  const [maxArticles, setMaxArticles] = useState("20");
  const [followPagination, setFollowPagination] = useState(false);

  // Bluesky state
  const [bskyMode, setBskyMode] = useState<BlueskyMode>("author");
  const [bskyHandle, setBskyHandle] = useState("");
  const [bskyFeedUri, setBskyFeedUri] = useState("");
  const [bskyQuery, setBskyQuery] = useState("");
  const [bskyLang, setBskyLang] = useState("");
  const [bskyIncludeReposts, setBskyIncludeReposts] = useState(false);
  const [bskyIdentifier, setBskyIdentifier] = useState("");
  const [bskyAppPassword, setBskyAppPassword] = useState("");
  const [bskyAuthorType, setBskyAuthorType] = useState<AuthorEntityType>("");
  const [bskyAuthorId, setBskyAuthorId] = useState("");
  const [bskyFeedUrlInput, setBskyFeedUrlInput] = useState("");
  const resolveBskyFeed = useResolveBlueskyFeedUrl();

  // Telegram state
  const [tgChannel, setTgChannel] = useState("");
  const [tgIncludeMedia, setTgIncludeMedia] = useState(true);
  const [tgDiscoveryOpen, setTgDiscoveryOpen] = useState(false);
  const tgDiscover = useDiscoverTelegramChannelsLazy();
  const [tgMaxAgeDays, setTgMaxAgeDays] = useState("30");
  const [tgExtractForwards, setTgExtractForwards] = useState(true);
  const [tgThreatActorId, setTgThreatActorId] = useState("");
  const [tgCampaignId, setTgCampaignId] = useState("");

  // OPML state
  const [opmlFile, setOpmlFile] = useState<File | null>(null);
  const [opmlPreview, setOpmlPreview] = useState<OpmlPreview | null>(null);
  const [opmlFileError, setOpmlFileError] = useState<string | null>(null);
  const [opmlDragging, setOpmlDragging] = useState(false);
  const importOpml = useImportOpml();

  const { data: actorsData } = useThreatActors(
    bskyAuthorType === "threat_actor" || mode === "telegram" ? { limit: 500 } : undefined
  );
  const { data: tgCampaignsData } = useCampaigns(
    mode === "telegram" ? { status: "active", limit: 200 } : undefined
  );
  const { data: vendorsData } = useVendors(
    bskyAuthorType === "vendor" ? { limit: 200 } : undefined
  );
  const { data: productsData } = useProducts(
    bskyAuthorType === "product" ? { limit: 200 } : undefined
  );

  const preview = discover.data;
  const isDiscovering = discover.isPending;
  const isAdding = addFeed.isPending;

  const handleDiscover = async () => {
    if (!url.trim()) return;
    discover.mutate(url.trim());
  };

  const handleAddUrl = async () => {
    if (!preview) return;
    try {
      await addFeed.mutateAsync({
        url: preview.url,
        category_id: categoryId || undefined,
        ...(customInterval ? { fetch_interval_minutes: parseInt(customInterval, 10) } : {}),
      });
      onClose();
    } catch {
      // error handled by mutation
    }
  };

  const handleAddRepo = async () => {
    const parsed = parseGitHubUrl(repoInput);
    if (!parsed) return;

    const patterns = filePatterns
      .split("\n")
      .map((p) => p.trim())
      .filter(Boolean);

    try {
      await addFeed.mutateAsync({
        url: `https://github.com/${parsed.owner}/${parsed.repo}`,
        feed_type: "github_repo",
        custom_title: `${parsed.owner}/${parsed.repo}`,
        adapter_config: {
          owner: parsed.owner,
          repo: parsed.repo,
          branch,
          paths: patterns,
          include_content: includeContent,
        },
        category_id: categoryId || undefined,
        fetch_interval_minutes: customInterval ? parseInt(customInterval, 10) : 120,
        intel_extraction_mode: "full",
        auto_extract_on_ingest: true,
      });
      onClose();
    } catch {
      // error handled by mutation
    }
  };

  const handleAddScraper = async () => {
    if (!scraperUrl.trim()) return;
    try {
      let title: string;
      try {
        title = new URL(scraperUrl.trim()).hostname;
      } catch {
        title = scraperUrl.trim();
      }
      await addFeed.mutateAsync({
        url: scraperUrl.trim(),
        feed_type: "web_scraper",
        custom_title: title,
        adapter_config: {
          blog_url: scraperUrl.trim(),
          ...(linkSelector ? { link_selector: linkSelector } : {}),
          ...(urlPattern ? { url_pattern: urlPattern } : {}),
          max_articles: parseInt(maxArticles, 10),
          follow_pagination: followPagination,
        },
        category_id: categoryId || undefined,
        fetch_interval_minutes: customInterval ? parseInt(customInterval, 10) : 360,
      });
      onClose();
    } catch {
      // error handled by mutation
    }
  };

  const handleAddBluesky = async () => {
    const adapter_config: Record<string, unknown> = { mode: bskyMode };
    let synthetic_url = "";
    let title = "";
    if (bskyMode === "author") {
      const handle = bskyHandle.trim().replace(/^@/, "");
      if (!handle) return;
      adapter_config.handle = handle;
      adapter_config.include_reposts = bskyIncludeReposts;
      synthetic_url = `bluesky://author/${handle}`;
      title = `Bluesky @${handle}`;
    } else if (bskyMode === "feed") {
      const uri = bskyFeedUri.trim();
      if (!uri.startsWith("at://")) return;
      adapter_config.feed_uri = uri;
      synthetic_url = `bluesky://feed/${encodeURIComponent(uri)}`;
      title = `Bluesky feed: ${uri.split("/").pop()}`;
    } else {
      const q = bskyQuery.trim();
      if (!q) return;
      adapter_config.query = q;
      if (bskyLang.trim()) adapter_config.lang = bskyLang.trim();
      synthetic_url = `bluesky://search/${encodeURIComponent(q)}`;
      title = `Bluesky: "${q}"`;
    }
    if (bskyIdentifier.trim() && bskyAppPassword.trim()) {
      adapter_config.identifier = bskyIdentifier.trim();
      adapter_config.app_password = bskyAppPassword;
    }
    if (bskyAuthorType && bskyAuthorId) {
      adapter_config.author_entity = { type: bskyAuthorType, id: bskyAuthorId };
    }
    try {
      await addFeed.mutateAsync({
        url: synthetic_url,
        feed_type: "bluesky",
        custom_title: title,
        adapter_config,
        category_id: categoryId || undefined,
        ...(customInterval ? { fetch_interval_minutes: parseInt(customInterval, 10) } : {}),
      });
      onClose();
    } catch {
      // error handled by mutation
    }
  };

  const handleAddTelegram = async () => {
    const handle = tgChannel.trim().replace(/^@/, "");
    if (!handle) return;
    const channelInput = handle.startsWith("http") || handle.startsWith("t.me/") ? handle : `@${handle}`;
    const adapterConfig: Record<string, unknown> = {
      channel: channelInput,
      include_media: tgIncludeMedia,
      max_message_age_days: tgMaxAgeDays === "0" ? 0 : parseInt(tgMaxAgeDays, 10),
      max_messages_per_fetch: 200,
      extract_forwards: tgExtractForwards,
    };
    if (tgThreatActorId) adapterConfig.threat_actor_id = tgThreatActorId;
    if (tgCampaignId) adapterConfig.campaign_id = tgCampaignId;
    try {
      await addFeed.mutateAsync({
        url: `https://t.me/${handle}`,
        feed_type: "telegram",
        custom_title: `Telegram: @${handle}`,
        adapter_config: adapterConfig,
        category_id: categoryId || undefined,
        fetch_interval_minutes: customInterval ? parseInt(customInterval, 10) : 30,
      });
      onClose();
    } catch {
      // error handled by mutation
    }
  };

  const handleOpmlFile = async (file: File | null | undefined) => {
    importOpml.reset();
    setOpmlPreview(null);
    setOpmlFileError(null);
    setOpmlFile(file ?? null);
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) {
      setOpmlFileError("File is larger than the 10 MB limit.");
      return;
    }
    const parsed = parseOpml(await file.text());
    if (!parsed) {
      setOpmlFileError("This doesn't look like an OPML subscription file.");
      return;
    }
    if (parsed.feeds === 0) {
      setOpmlFileError("No feed URLs found in this file.");
      return;
    }
    setOpmlPreview(parsed);
  };

  const handleImportOpml = async () => {
    if (!opmlFile || !opmlPreview) return;
    try {
      await importOpml.mutateAsync(opmlFile);
    } catch {
      // surfaced via opmlImportError
    }
  };

  const opmlResult = importOpml.data && !importOpml.data.error ? importOpml.data : null;
  const opmlImportError = importOpml.isError
    ? ((importOpml.error as { response?: { data?: { detail?: { message?: string } } } })
        ?.response?.data?.detail?.message ?? "Import failed.")
    : (importOpml.data?.error ?? null);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") onClose();
  };

  const trapRef = useFocusTrap<HTMLDivElement>();

  const parsedRepo = parseGitHubUrl(repoInput);

  return (
    <div className={styles.overlay} onClick={onClose} onKeyDown={handleKeyDown}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()} ref={trapRef} role="dialog" aria-modal="true" aria-label="Add feed">
        <div className={styles.header}>
          <h2>Add Feed</h2>
          <button onClick={onClose} className={styles.closeBtn} aria-label="Close">
            &times;
          </button>
        </div>

        <div className={styles.body}>
          {/* Mode tabs */}
          <div className={styles.modeTabs}>
            <button
              className={`${styles.modeTab} ${mode === "url" ? styles.modeTabActive : ""}`}
              onClick={() => setMode("url")}
            >
              Feed URL
            </button>
            <button
              className={`${styles.modeTab} ${mode === "github_repo" ? styles.modeTabActive : ""}`}
              onClick={() => setMode("github_repo")}
            >
              GitHub Repo
            </button>
            <button
              className={`${styles.modeTab} ${mode === "web_scraper" ? styles.modeTabActive : ""}`}
              onClick={() => setMode("web_scraper")}
            >
              Web Scraper
            </button>
            <button
              className={`${styles.modeTab} ${mode === "bluesky" ? styles.modeTabActive : ""}`}
              onClick={() => setMode("bluesky")}
            >
              Bluesky
            </button>
            <button
              className={`${styles.modeTab} ${mode === "telegram" ? styles.modeTabActive : ""}`}
              onClick={() => setMode("telegram")}
            >
              Telegram
            </button>
            <button
              className={`${styles.modeTab} ${mode === "opml" ? styles.modeTabActive : ""}`}
              onClick={() => setMode("opml")}
            >
              OPML
            </button>
          </div>

          {mode === "url" && (
            <>
              {/* URL input + discover */}
              <div className={styles.urlRow}>
                <input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleDiscover()}
                  placeholder="Enter feed URL or website URL..."
                  className={styles.urlInput}
                  autoFocus
                />
                <button
                  onClick={handleDiscover}
                  disabled={isDiscovering || !url.trim()}
                  className={styles.discoverBtn}
                >
                  {isDiscovering ? "Checking..." : "Discover"}
                </button>
              </div>

              {discover.isError && (
                <p className={styles.error}>
                  Could not find a valid feed at this URL.
                </p>
              )}

              {/* Preview */}
              {preview && (
                <div className={styles.preview}>
                  <div className={styles.previewInfo}>
                    <h3 className={styles.previewTitle}>
                      {preview.title || preview.url}
                    </h3>
                    {preview.description && (
                      <p className={styles.previewDesc}>{preview.description}</p>
                    )}
                    <span className={styles.previewMeta}>
                      {preview.feed_type.toUpperCase()} &middot; {preview.url}
                    </span>
                  </div>

                  {/* Category picker */}
                  <div className={styles.optionRow}>
                    <label>Category</label>
                    <select
                      value={categoryId}
                      onChange={(e) => setCategoryId(e.target.value)}
                      className={styles.select}
                    >
                      <option value="">Uncategorized</option>
                      {categories?.map((cat) => (
                        <option key={cat.id} value={cat.id}>
                          {cat.name}
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Custom interval */}
                  <div className={styles.optionRow}>
                    <label>Poll Interval</label>
                    <select
                      value={customInterval}
                      onChange={(e) => setCustomInterval(e.target.value)}
                      className={styles.select}
                    >
                      <option value="">Default (30 min)</option>
                      <option value="15">Every 15 min</option>
                      <option value="30">Every 30 min</option>
                      <option value="60">Every hour</option>
                      <option value="360">Every 6 hours</option>
                      <option value="1440">Once a day</option>
                    </select>
                  </div>

                  <button
                    onClick={handleAddUrl}
                    disabled={isAdding}
                    className={styles.addBtn}
                  >
                    {isAdding ? "Subscribing..." : "Subscribe"}
                  </button>
                </div>
              )}
            </>
          )}

          {mode === "github_repo" && (
            <div className={styles.repoForm}>
              {/* Bulk setup for detection repos */}
              <div className={styles.bulkSetup}>
                <p className={styles.bulkSetupDesc}>
                  Subscribe to {19} pre-configured detection rule repositories (SigmaHQ, Elastic, Splunk, YARA, LOLBAS, Atomic Red Team, and more).
                </p>
                <button
                  onClick={async () => {
                    try {
                      const result = await bulkSetup.mutateAsync();
                      if (result.total_created === 0 && result.total_skipped > 0) {
                        // All already subscribed — just close
                        onClose();
                      } else {
                        onClose();
                      }
                    } catch {
                      // error handled by mutation
                    }
                  }}
                  disabled={bulkSetup.isPending}
                  className={styles.bulkSetupBtn}
                >
                  {bulkSetup.isPending ? "Setting up..." : "Set Up All Detection Repos"}
                </button>
                {bulkSetup.isSuccess && (
                  <p className={styles.bulkSetupResult}>
                    Created {bulkSetup.data.total_created}, skipped {bulkSetup.data.total_skipped} (already subscribed).
                    Category: {bulkSetup.data.category_name}
                  </p>
                )}
                {bulkSetup.isError && (
                  <p className={styles.error}>Failed to set up detection repos.</p>
                )}
              </div>

              <div className={styles.dividerRow}>
                <span className={styles.dividerLine} />
                <span className={styles.dividerText}>or add a single repo</span>
                <span className={styles.dividerLine} />
              </div>

              <div className={styles.field}>
                <label>Repository</label>
                <input
                  type="text"
                  value={repoInput}
                  onChange={(e) => setRepoInput(e.target.value)}
                  placeholder="owner/repo or GitHub URL"
                  className={styles.urlInput}
                  autoFocus
                />
                {repoInput && !parsedRepo && (
                  <span className={styles.fieldHint + " " + styles.fieldHintError}>
                    Enter as owner/repo (e.g., SigmaHQ/sigma)
                  </span>
                )}
                {parsedRepo && (
                  <span className={styles.fieldHint}>
                    {parsedRepo.owner}/{parsedRepo.repo}
                  </span>
                )}
              </div>

              <div className={styles.field}>
                <label>Branch</label>
                <input
                  type="text"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  placeholder="main"
                  className={styles.urlInput}
                />
              </div>

              <div className={styles.field}>
                <label>File Patterns</label>
                <textarea
                  value={filePatterns}
                  onChange={(e) => setFilePatterns(e.target.value)}
                  placeholder={"**/*.yml\n**/*.yaml\nrules/**/*.toml"}
                  className={styles.textarea}
                  rows={3}
                />
                <span className={styles.fieldHint}>
                  One glob pattern per line. Use ** for recursive matching.
                </span>
              </div>

              <label className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={includeContent}
                  onChange={(e) => setIncludeContent(e.target.checked)}
                />
                <span>Include file content</span>
              </label>

              <div className={styles.optionRow}>
                <label>Category</label>
                <select
                  value={categoryId}
                  onChange={(e) => setCategoryId(e.target.value)}
                  className={styles.select}
                >
                  <option value="">Uncategorized</option>
                  {categories?.map((cat) => (
                    <option key={cat.id} value={cat.id}>
                      {cat.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className={styles.optionRow}>
                <label>Poll Interval</label>
                <select
                  value={customInterval}
                  onChange={(e) => setCustomInterval(e.target.value)}
                  className={styles.select}
                >
                  <option value="">Default (2 hours)</option>
                  <option value="60">Every hour</option>
                  <option value="120">Every 2 hours</option>
                  <option value="360">Every 6 hours</option>
                  <option value="720">Every 12 hours</option>
                  <option value="1440">Once a day</option>
                </select>
              </div>

              {addFeed.isError && (
                <p className={styles.error}>
                  Failed to subscribe. Check the repository name and try again.
                </p>
              )}

              <button
                onClick={handleAddRepo}
                disabled={isAdding || !parsedRepo}
                className={styles.addBtn}
              >
                {isAdding ? "Subscribing..." : "Subscribe to Repository"}
              </button>
            </div>
          )}

          {mode === "web_scraper" && (
            <div className={styles.repoForm}>
              <div className={styles.field}>
                <label>Blog URL</label>
                <input
                  type="url"
                  value={scraperUrl}
                  onChange={(e) => setScraperUrl(e.target.value)}
                  placeholder="https://example.com/blog"
                  className={styles.urlInput}
                  autoFocus
                />
                <span className={styles.fieldHint}>
                  URL of the blog index page that lists articles
                </span>
              </div>

              <div className={styles.field}>
                <label>Link Selector (optional)</label>
                <input
                  type="text"
                  value={linkSelector}
                  onChange={(e) => setLinkSelector(e.target.value)}
                  placeholder="a.post-title, article a"
                  className={styles.urlInput}
                />
                <span className={styles.fieldHint}>
                  CSS selector for article links. Leave blank for auto-detection.
                </span>
              </div>

              <div className={styles.field}>
                <label>URL Pattern (optional)</label>
                <input
                  type="text"
                  value={urlPattern}
                  onChange={(e) => setUrlPattern(e.target.value)}
                  placeholder="/blog/.*"
                  className={styles.urlInput}
                />
                <span className={styles.fieldHint}>
                  Regex to filter discovered links (e.g., only match /blog/ paths)
                </span>
              </div>

              <div className={styles.optionRow}>
                <label>Max Articles</label>
                <select
                  value={maxArticles}
                  onChange={(e) => setMaxArticles(e.target.value)}
                  className={styles.select}
                >
                  <option value="10">10</option>
                  <option value="20">20 (default)</option>
                  <option value="50">50</option>
                </select>
              </div>

              <label className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={followPagination}
                  onChange={(e) => setFollowPagination(e.target.checked)}
                />
                <span>Follow pagination</span>
              </label>

              <div className={styles.optionRow}>
                <label>Category</label>
                <select
                  value={categoryId}
                  onChange={(e) => setCategoryId(e.target.value)}
                  className={styles.select}
                >
                  <option value="">Uncategorized</option>
                  {categories?.map((cat) => (
                    <option key={cat.id} value={cat.id}>
                      {cat.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className={styles.optionRow}>
                <label>Poll Interval</label>
                <select
                  value={customInterval}
                  onChange={(e) => setCustomInterval(e.target.value)}
                  className={styles.select}
                >
                  <option value="">Default (6 hours)</option>
                  <option value="360">Every 6 hours</option>
                  <option value="720">Every 12 hours</option>
                  <option value="1440">Once a day</option>
                </select>
              </div>

              {addFeed.isError && (
                <p className={styles.error}>
                  Failed to add scraper feed. Check the URL and try again.
                </p>
              )}

              <button
                onClick={handleAddScraper}
                disabled={isAdding || !scraperUrl.trim()}
                className={styles.addBtn}
              >
                {isAdding ? "Subscribing..." : "Subscribe"}
              </button>
            </div>
          )}

          {mode === "bluesky" && (
            <div className={styles.repoForm}>
              <div className={styles.field}>
                <label>Mode</label>
                <select
                  value={bskyMode}
                  onChange={(e) => setBskyMode(e.target.value as BlueskyMode)}
                  className={styles.select}
                >
                  <option value="author">Author — every post from a handle</option>
                  <option value="feed">Custom feed — a feed-generator AT URI</option>
                  <option value="search">Search — posts matching a query</option>
                </select>
              </div>

              {bskyMode === "author" && (
                <>
                  <div className={styles.field}>
                    <label>Handle</label>
                    <input
                      type="text"
                      value={bskyHandle}
                      onChange={(e) => setBskyHandle(e.target.value)}
                      placeholder="alice.bsky.social"
                      className={styles.urlInput}
                      autoFocus
                    />
                    <span className={styles.fieldHint}>
                      Bluesky handle (with or without leading @)
                    </span>
                  </div>
                  <label className={styles.checkboxRow}>
                    <input
                      type="checkbox"
                      checked={bskyIncludeReposts}
                      onChange={(e) => setBskyIncludeReposts(e.target.checked)}
                    />
                    <span>Include reposts</span>
                  </label>
                </>
              )}

              {bskyMode === "feed" && (
                <>
                  <div className={styles.field}>
                    <label>Paste a bsky.app feed URL</label>
                    <div className={styles.urlRow}>
                      <input
                        type="url"
                        value={bskyFeedUrlInput}
                        onChange={(e) => setBskyFeedUrlInput(e.target.value)}
                        placeholder="https://bsky.app/profile/<handle>/feed/<rkey>"
                        className={styles.urlInput}
                      />
                      <button
                        type="button"
                        onClick={async () => {
                          try {
                            const result = await resolveBskyFeed.mutateAsync(
                              bskyFeedUrlInput.trim()
                            );
                            setBskyFeedUri(result.feed_uri);
                          } catch {
                            // surfaced via resolveBskyFeed.isError below
                          }
                        }}
                        disabled={
                          resolveBskyFeed.isPending || !bskyFeedUrlInput.trim()
                        }
                        className={styles.discoverBtn}
                      >
                        {resolveBskyFeed.isPending ? "Resolving..." : "Resolve"}
                      </button>
                    </div>
                    {resolveBskyFeed.isError && (
                      <span className={styles.fieldHint + " " + styles.fieldHintError}>
                        Could not resolve that URL. Paste the at:// URI directly below.
                      </span>
                    )}
                  </div>
                  <div className={styles.field}>
                    <label>Feed URI</label>
                    <input
                      type="text"
                      value={bskyFeedUri}
                      onChange={(e) => setBskyFeedUri(e.target.value)}
                      placeholder="at://did:plc:.../app.bsky.feed.generator/whats-hot"
                      className={styles.urlInput}
                    />
                    <span className={styles.fieldHint}>
                      Auto-filled from the URL above, or paste the at:// URI directly.
                    </span>
                  </div>
                </>
              )}

              {bskyMode === "search" && (
                <>
                  <div className={styles.field}>
                    <label>Query</label>
                    <input
                      type="text"
                      value={bskyQuery}
                      onChange={(e) => setBskyQuery(e.target.value)}
                      placeholder='ransomware OR "zero day"'
                      className={styles.urlInput}
                      autoFocus
                    />
                  </div>
                  <div className={styles.field}>
                    <label>Language (optional)</label>
                    <input
                      type="text"
                      value={bskyLang}
                      onChange={(e) => setBskyLang(e.target.value)}
                      placeholder="en"
                      className={styles.urlInput}
                    />
                  </div>
                </>
              )}

              <details>
                <summary>Auth (optional, lifts rate limits)</summary>
                <div className={styles.field}>
                  <label>Identifier</label>
                  <input
                    type="text"
                    value={bskyIdentifier}
                    onChange={(e) => setBskyIdentifier(e.target.value)}
                    placeholder="your.handle.bsky.social"
                    className={styles.urlInput}
                  />
                </div>
                <div className={styles.field}>
                  <label>App Password</label>
                  <input
                    type="password"
                    value={bskyAppPassword}
                    onChange={(e) => setBskyAppPassword(e.target.value)}
                    placeholder="xxxx-xxxx-xxxx-xxxx"
                    className={styles.urlInput}
                  />
                  <span className={styles.fieldHint}>
                    Generate a dedicated app password — never your account password.
                  </span>
                </div>
              </details>

              <details>
                <summary>Attribute all posts to (optional)</summary>
                <div className={styles.field}>
                  <label>Entity Type</label>
                  <select
                    value={bskyAuthorType}
                    onChange={(e) => {
                      setBskyAuthorType(e.target.value as AuthorEntityType);
                      setBskyAuthorId("");
                    }}
                    className={styles.select}
                  >
                    <option value="">None</option>
                    <option value="threat_actor">Threat Actor</option>
                    <option value="vendor">Vendor</option>
                    <option value="product">Product</option>
                  </select>
                </div>
                {bskyAuthorType && (
                  <div className={styles.field}>
                    <label>Entity</label>
                    <select
                      value={bskyAuthorId}
                      onChange={(e) => setBskyAuthorId(e.target.value)}
                      className={styles.select}
                    >
                      <option value="">Select...</option>
                      {bskyAuthorType === "threat_actor" &&
                        actorsData?.items?.map((a: { id: string; name: string }) => (
                          <option key={a.id} value={a.id}>
                            {a.name}
                          </option>
                        ))}
                      {bskyAuthorType === "vendor" &&
                        vendorsData?.items?.map((v: { id: string; name: string }) => (
                          <option key={v.id} value={v.id}>
                            {v.name}
                          </option>
                        ))}
                      {bskyAuthorType === "product" &&
                        productsData?.items?.map((p: { id: string; name: string }) => (
                          <option key={p.id} value={p.id}>
                            {p.name}
                          </option>
                        ))}
                    </select>
                    <span className={styles.fieldHint}>
                      Every post from this feed will be attributed to the chosen entity.
                    </span>
                  </div>
                )}
              </details>

              <div className={styles.optionRow}>
                <label>Category</label>
                <select
                  value={categoryId}
                  onChange={(e) => setCategoryId(e.target.value)}
                  className={styles.select}
                >
                  <option value="">Uncategorized</option>
                  {categories?.map((cat) => (
                    <option key={cat.id} value={cat.id}>
                      {cat.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className={styles.optionRow}>
                <label>Poll Interval</label>
                <select
                  value={customInterval}
                  onChange={(e) => setCustomInterval(e.target.value)}
                  className={styles.select}
                >
                  <option value="">Default (15 min)</option>
                  <option value="15">Every 15 min</option>
                  <option value="30">Every 30 min</option>
                  <option value="60">Every hour</option>
                </select>
              </div>

              {addFeed.isError && (
                <p className={styles.error}>
                  Failed to subscribe. Check the handle/URI/query and try again.
                </p>
              )}

              <button
                onClick={handleAddBluesky}
                disabled={
                  isAdding ||
                  (bskyMode === "author" && !bskyHandle.trim()) ||
                  (bskyMode === "feed" && !bskyFeedUri.trim().startsWith("at://")) ||
                  (bskyMode === "search" && !bskyQuery.trim())
                }
                className={styles.addBtn}
              >
                {isAdding ? "Subscribing..." : "Subscribe"}
              </button>
            </div>
          )}

          {mode === "telegram" && (
            <div className={styles.repoForm}>
              <p className={styles.fieldHint}>
                Requires a server-side Telegram account. If you haven&apos;t completed Telegram setup yet,
                this feed will fail with &quot;Telegram session not authorized&quot; — ask your administrator.
                See deployment docs.
              </p>

              <div className={styles.field}>
                <button
                  type="button"
                  className={styles.discoverBtn}
                  onClick={() => {
                    setTgDiscoveryOpen(true);
                    if (!tgDiscover.data && !tgDiscover.isPending) {
                      tgDiscover.mutate("");
                    }
                  }}
                  disabled={tgDiscover.isPending}
                >
                  {tgDiscover.isPending ? "Loading…" : "Discover from my Telegram account"}
                </button>
                <span className={styles.fieldHint}>
                  Lists every channel the IntelFeed account is joined to. Click one to fill the channel
                  field below — or just type the handle directly.
                </span>
              </div>

              {tgDiscoveryOpen && (
                <div className={styles.field}>
                  {tgDiscover.isError && (
                    <p className={styles.error}>
                      Discovery failed. Telegram may be unconfigured on the server.
                    </p>
                  )}
                  {tgDiscover.data && (
                    <div
                      style={{
                        maxHeight: "240px",
                        overflowY: "auto",
                        border: "1px solid var(--border, #ccc)",
                        borderRadius: "4px",
                        padding: "0.25rem",
                      }}
                    >
                      <div className={styles.fieldHint} style={{ padding: "0.25rem 0.5rem" }}>
                        {tgDiscover.data.unsubscribed_count} not yet ingested,{" "}
                        {tgDiscover.data.subscribed_count} already subscribed.
                      </div>
                      {tgDiscover.data.items.map((c: TelegramDiscoveredChannel) => {
                        const handle = c.username
                          ? `@${c.username}`
                          : `Private channel ${c.channel_id}`;
                        const tags: string[] = [];
                        if (c.verified) tags.push("verified");
                        if (c.scam) tags.push("⚠ scam");
                        if (c.fake) tags.push("⚠ fake");
                        if (c.is_subscribed) tags.push("already added");
                        return (
                          <button
                            key={c.channel_id}
                            type="button"
                            disabled={c.is_subscribed}
                            onClick={() => {
                              setTgChannel(c.username ? `@${c.username}` : String(c.channel_id));
                              setTgDiscoveryOpen(false);
                            }}
                            style={{
                              width: "100%",
                              textAlign: "left",
                              padding: "0.4rem 0.6rem",
                              // --bg-muted was never defined, so this fell back to #f4f4f4 — a
                              // near-white light-theme leftover. On the dark ground that put
                              // --text-primary at 1.07:1, i.e. invisible.
                              background: c.is_subscribed ? "var(--bg-tertiary)" : "transparent",
                              border: "none",
                              borderBottom: "1px solid var(--border, #eee)",
                              cursor: c.is_subscribed ? "not-allowed" : "pointer",
                              opacity: c.is_subscribed ? 0.55 : 1,
                            }}
                          >
                            <div style={{ fontWeight: 500 }}>{c.title}</div>
                            <div className={styles.fieldHint}>
                              {handle}
                              {c.subscribers ? ` · ${c.subscribers.toLocaleString()} subscribers` : ""}
                              {tags.length ? ` · ${tags.join(" · ")}` : ""}
                            </div>
                          </button>
                        );
                      })}
                      {tgDiscover.data.items.length === 0 && (
                        <p className={styles.fieldHint}>
                          No channels found. The bootstrap account isn&apos;t joined to any.
                        </p>
                      )}
                    </div>
                  )}
                </div>
              )}

              <div className={styles.field}>
                <label>Channel</label>
                <input
                  type="text"
                  value={tgChannel}
                  onChange={(e) => setTgChannel(e.target.value)}
                  placeholder="@channelname or t.me/channel"
                  className={styles.urlInput}
                  autoFocus
                />
                <span className={styles.fieldHint}>
                  Public channel username (with or without @) or a t.me link. Private channels must be joined
                  by the IntelFeed account first.
                </span>
              </div>

              <label className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={tgIncludeMedia}
                  onChange={(e) => setTgIncludeMedia(e.target.checked)}
                />
                <span>Download media (photos, videos, voice notes, documents)</span>
              </label>

              <label className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={tgExtractForwards}
                  onChange={(e) => setTgExtractForwards(e.target.checked)}
                />
                <span>Show &quot;Forwarded from&quot; attribution</span>
              </label>

              <div className={styles.optionRow}>
                <label>Max message age</label>
                <select
                  value={tgMaxAgeDays}
                  onChange={(e) => setTgMaxAgeDays(e.target.value)}
                  className={styles.select}
                >
                  <option value="30">Last 30 days</option>
                  <option value="60">Last 60 days</option>
                  <option value="90">Last 90 days</option>
                  <option value="0">No limit</option>
                </select>
                <span className={styles.fieldHint}>Only applies to the first fetch.</span>
              </div>

              <details>
                <summary>Auto-attribute every message (optional)</summary>
                <div className={styles.field}>
                  <label>Threat actor</label>
                  <select
                    value={tgThreatActorId}
                    onChange={(e) => setTgThreatActorId(e.target.value)}
                    className={styles.select}
                  >
                    <option value="">None</option>
                    {actorsData?.items?.map((a: { id: string; name: string }) => (
                      <option key={a.id} value={a.id}>
                        {a.name}
                      </option>
                    ))}
                  </select>
                  <span className={styles.fieldHint}>
                    If this channel <strong>is</strong> a threat actor (ransomware leak site, hacktivist
                    channel, broker), pick the actor here. Every message will be auto-linked with high
                    confidence — no autolinker guessing required.
                  </span>
                </div>
                <div className={styles.field}>
                  <label>Campaign</label>
                  <select
                    value={tgCampaignId}
                    onChange={(e) => setTgCampaignId(e.target.value)}
                    className={styles.select}
                  >
                    <option value="">None</option>
                    {tgCampaignsData?.items?.map((c: { id: string; name: string }) => (
                      <option key={c.id} value={c.id}>
                        {c.name}
                      </option>
                    ))}
                  </select>
                  <span className={styles.fieldHint}>
                    Link every message from this channel to a tracked operation (e.g. an ongoing intrusion
                    campaign). Useful for live coverage of an active incident.
                  </span>
                </div>
              </details>

              <div className={styles.optionRow}>
                <label>Category</label>
                <select
                  value={categoryId}
                  onChange={(e) => setCategoryId(e.target.value)}
                  className={styles.select}
                >
                  <option value="">Uncategorized</option>
                  {categories?.map((cat) => (
                    <option key={cat.id} value={cat.id}>
                      {cat.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className={styles.optionRow}>
                <label>Poll Interval</label>
                <select
                  value={customInterval}
                  onChange={(e) => setCustomInterval(e.target.value)}
                  className={styles.select}
                >
                  <option value="">Default (30 min)</option>
                  <option value="30">Every 30 min</option>
                  <option value="60">Every hour</option>
                  <option value="120">Every 2 hours</option>
                  <option value="360">Every 6 hours</option>
                </select>
              </div>

              {addFeed.isError && (
                <p className={styles.error}>
                  Failed to subscribe. Telegram may be unconfigured on the server, or the channel may be
                  unavailable.
                </p>
              )}

              <button
                onClick={handleAddTelegram}
                disabled={isAdding || !tgChannel.trim()}
                className={styles.addBtn}
              >
                {isAdding ? "Subscribing..." : "Subscribe"}
              </button>
            </div>
          )}

          {mode === "opml" && (
            <div className={styles.repoForm}>
              {opmlResult ? (
                <div className={styles.preview}>
                  <div className={styles.previewInfo}>
                    <h3 className={styles.previewTitle}>Import complete</h3>
                    <p className={styles.previewDesc}>
                      {opmlResult.feeds_added} feed
                      {opmlResult.feeds_added === 1 ? "" : "s"} added
                      {opmlResult.feeds_skipped > 0 &&
                        ` \u00b7 ${opmlResult.feeds_skipped} already subscribed`}
                      {opmlResult.categories_created > 0 &&
                        ` \u00b7 ${opmlResult.categories_created} categor${
                          opmlResult.categories_created === 1 ? "y" : "ies"
                        } created`}
                    </p>
                    {!!opmlResult.feeds_skipped_invalid && (
                      <p className={styles.fieldHint}>
                        {opmlResult.feeds_skipped_invalid} outline
                        {opmlResult.feeds_skipped_invalid === 1 ? "" : "s"} skipped — no
                        usable feed URL.
                      </p>
                    )}
                    {!!opmlResult.errors?.length && (
                      <p className={styles.fieldHintError}>{opmlResult.errors.join(", ")}</p>
                    )}
                    <span className={styles.previewMeta}>
                      New feeds are queued for their first fetch now.
                    </span>
                  </div>
                  <button onClick={onClose} className={styles.addBtn}>
                    Done
                  </button>
                </div>
              ) : (
                <>
                  <label
                    className={`${styles.dropzone} ${opmlDragging ? styles.dropzoneActive : ""}`}
                    onDragOver={(e) => {
                      e.preventDefault();
                      setOpmlDragging(true);
                    }}
                    onDragLeave={() => setOpmlDragging(false)}
                    onDrop={(e) => {
                      e.preventDefault();
                      setOpmlDragging(false);
                      handleOpmlFile(e.dataTransfer.files?.[0]);
                    }}
                  >
                    <input
                      type="file"
                      accept=".opml,.xml,application/xml,text/xml"
                      className={styles.fileInput}
                      data-testid="opml-file-input"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        // Clear so re-picking the same file after an error still fires.
                        e.target.value = "";
                        handleOpmlFile(file);
                      }}
                    />
                    <span className={styles.dropzoneTitle}>
                      {opmlFile ? opmlFile.name : "Drop an OPML file here"}
                    </span>
                    <span className={styles.dropzoneHint}>
                      {opmlFile
                        ? "Click to choose a different file"
                        : "or click to browse \u2014 exports from Feedly, Inoreader, NewsBlur, and other readers"}
                    </span>
                  </label>

                  {opmlPreview && (
                    <p className={styles.fieldHint}>
                      {opmlPreview.feeds} feed{opmlPreview.feeds === 1 ? "" : "s"}
                      {opmlPreview.categories.length > 0 &&
                        ` in ${opmlPreview.categories.length} categor${
                          opmlPreview.categories.length === 1 ? "y" : "ies"
                        }`}
                      {opmlPreview.categories.length > 0 &&
                        ` (${opmlPreview.categories.slice(0, 4).join(", ")}${
                          opmlPreview.categories.length > 4 ? ", \u2026" : ""
                        })`}
                      . Feeds already in the pool are skipped.
                      {opmlPreview.invalid > 0 &&
                        ` ${opmlPreview.invalid} entr${
                          opmlPreview.invalid === 1 ? "y" : "ies"
                        } without a usable URL will be ignored.`}
                    </p>
                  )}

                  {opmlFileError && <p className={styles.error}>{opmlFileError}</p>}
                  {opmlImportError && <p className={styles.error}>{opmlImportError}</p>}

                  <button
                    onClick={handleImportOpml}
                    disabled={!opmlPreview || importOpml.isPending}
                    className={styles.addBtn}
                  >
                    {importOpml.isPending
                      ? "Importing..."
                      : opmlPreview
                        ? `Import ${opmlPreview.feeds} feed${opmlPreview.feeds === 1 ? "" : "s"}`
                        : "Import"}
                  </button>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
