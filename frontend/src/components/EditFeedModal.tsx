import { useState } from "react";
import { useCategories, useUpdateFeed, useDeleteFeed } from "@/hooks/useFeeds";
import { useThreatActors, useVendors, useProducts } from "@/hooks/useIntelligence";
import { useCampaigns } from "@/hooks/useCampaigns";
import { useTelegramFeedHealth, useTelegramListenerStatus } from "@/hooks/useTelegram";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { useAuthStore } from "@/stores/authStore";
import { FeedSubscribersPanel } from "./FeedSubscribersPanel";
import type { Feed } from "@/api/types";
import styles from "./EditFeedModal.module.css";

type AuthorEntityType = "" | "threat_actor" | "vendor" | "product";

interface Props {
  subscription: Feed;
  onClose: () => void;
}

export function EditFeedModal({ subscription, onClose }: Props) {
  const [feedUrl, setFeedUrl] = useState(subscription.url);
  const [customTitle, setCustomTitle] = useState(subscription.custom_title || "");
  const [categoryId, setCategoryId] = useState(subscription.category_id || "");
  const [interval, setInterval] = useState(String(subscription.fetch_interval_minutes));
  const [isMuted, setIsMuted] = useState(subscription.is_muted);
  const [retentionDays, setRetentionDays] = useState(
    subscription.retention_days != null ? String(subscription.retention_days) : ""
  );
  const [feedType, setFeedType] = useState(subscription.feed_type);
  const [excludeShorts, setExcludeShorts] = useState(
    (subscription.adapter_config?.exclude_shorts as boolean) ?? false
  );
  const adapterConfig = subscription.adapter_config || {};
  const [branch, setBranch] = useState(
    (adapterConfig.branch as string) || "main"
  );
  const [filePatterns, setFilePatterns] = useState(
    ((adapterConfig.paths as string[]) || []).join("\n")
  );
  const [includeContent, setIncludeContent] = useState(
    (adapterConfig.include_content as boolean) ?? true
  );
  const [backfillDays, setBackfillDays] = useState(
    String((adapterConfig.backfill_days as number) ?? 90)
  );
  // Web scraper config
  const [scraperLinkSelector, setScraperLinkSelector] = useState(
    (adapterConfig.link_selector as string) || ""
  );
  const [scraperUrlPattern, setScraperUrlPattern] = useState(
    (adapterConfig.url_pattern as string) || ""
  );
  const [scraperMaxArticles, setScraperMaxArticles] = useState(
    String((adapterConfig.max_articles as number) ?? 20)
  );
  const [scraperFollowPagination, setScraperFollowPagination] = useState(
    (adapterConfig.follow_pagination as boolean) ?? false
  );
  // Bluesky config
  const [bskyMode, setBskyMode] = useState<string>(
    (adapterConfig.mode as string) || "author"
  );
  const [bskyHandle, setBskyHandle] = useState((adapterConfig.handle as string) || "");
  const [bskyFeedUri, setBskyFeedUri] = useState((adapterConfig.feed_uri as string) || "");
  const [bskyQuery, setBskyQuery] = useState((adapterConfig.query as string) || "");
  const [bskyLang, setBskyLang] = useState((adapterConfig.lang as string) || "");
  const [bskyIncludeReposts, setBskyIncludeReposts] = useState(
    (adapterConfig.include_reposts as boolean) ?? false
  );
  const [bskyIdentifier, setBskyIdentifier] = useState(
    (adapterConfig.identifier as string) || ""
  );
  // Existing app_password is already encrypted server-side; we never display it.
  // Empty input = keep existing; non-empty = replace with new plaintext (server encrypts).
  const [bskyAppPassword, setBskyAppPassword] = useState("");
  const existingAuthorEntity =
    (adapterConfig.author_entity as { type?: string; id?: string } | undefined) || undefined;
  const [bskyAuthorType, setBskyAuthorType] = useState<AuthorEntityType>(
    (existingAuthorEntity?.type as AuthorEntityType) || ""
  );
  const [bskyAuthorId, setBskyAuthorId] = useState<string>(existingAuthorEntity?.id || "");

  // Telegram per-feed attribution
  const [tgThreatActorId, setTgThreatActorId] = useState<string>(
    (adapterConfig.threat_actor_id as string) || ""
  );
  const [tgCampaignId, setTgCampaignId] = useState<string>(
    (adapterConfig.campaign_id as string) || ""
  );
  const [tgIncludeMedia, setTgIncludeMedia] = useState(
    (adapterConfig.include_media as boolean) ?? true
  );
  const [tgExtractForwards, setTgExtractForwards] = useState(
    (adapterConfig.extract_forwards as boolean) ?? true
  );
  const [tgRealtime, setTgRealtime] = useState(
    (adapterConfig.realtime as boolean) ?? false
  );
  const [autoTranslate, setAutoTranslate] = useState(
    (adapterConfig.auto_translate as boolean) ?? false
  );

  const needTelegramActors = feedType === "telegram";
  const needTelegramCampaigns = feedType === "telegram";

  const tgHealth = useTelegramFeedHealth(
    feedType === "telegram" ? subscription.id : null
  );
  const tgListener = useTelegramListenerStatus(feedType === "telegram");

  const { data: actorsData } = useThreatActors(
    (feedType === "bluesky" && bskyAuthorType === "threat_actor") || needTelegramActors
      ? { limit: 500 }
      : undefined
  );
  const { data: tgCampaignsData } = useCampaigns(
    needTelegramCampaigns ? { status: "active", limit: 200 } : undefined
  );
  const { data: vendorsData } = useVendors(
    feedType === "bluesky" && bskyAuthorType === "vendor" ? { limit: 200 } : undefined
  );
  const { data: productsData } = useProducts(
    feedType === "bluesky" && bskyAuthorType === "product" ? { limit: 200 } : undefined
  );
  // Unified intel level derived from two backend fields
  const deriveIntelLevel = (): string => {
    const mode = subscription.intel_extraction_mode || "selective";
    const extract = subscription.auto_extract_on_ingest ?? false;
    if (mode === "none") return "none";
    if (mode === "manual") return "manual";
    if (mode === "full" && extract) return "full";
    if (mode === "selective" && extract) return "selective";
    if ((mode === "full" || mode === "selective") && !extract) return "known_only";
    return "selective";
  };
  const [intelLevel, setIntelLevel] = useState(deriveIntelLevel);
  const [extractRules, setExtractRules] = useState(subscription.extract_detection_rules ?? false);
  const [extractTools, setExtractTools] = useState(subscription.extract_tools ?? true);
  const [reliability, setReliability] = useState(subscription.reliability_rating || "");
  const [analystNotes, setAnalystNotes] = useState(subscription.analyst_notes || "");
  const { data: categories } = useCategories();
  const updateFeed = useUpdateFeed();
  const deleteFeed = useDeleteFeed();
  const undoableDelete = useUndoableDelete();
  // With per-user subscriptions on, unsubscribing only affects the caller;
  // otherwise removal deletes the feed for everyone and is admin-only.
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  const canUnsubscribe = isAdmin || Boolean(subscription.per_user);

  const handleSave = async () => {
    // Curation fields any analyst may change. Feed infrastructure — URL,
    // adapter config (credentials included), type, cadence, retention and
    // extraction wiring — is shared plumbing the API only accepts from an
    // admin, so a non-admin must not send those keys at all.
    const curation = {
      custom_title: customTitle.trim() || undefined,
      category_id: categoryId || null,
      is_muted: isMuted,
      reliability_rating: reliability || undefined,
      analyst_notes: analystNotes.trim() || undefined,
    };
    const infrastructure = !isAdmin
      ? {}
      : {
          url: feedUrl.trim() !== subscription.url ? feedUrl.trim() : undefined,
          fetch_interval_minutes: parseInt(interval, 10),
          feed_type: feedType !== subscription.feed_type ? feedType : undefined,
          retention_days: retentionDays === "" ? null : parseInt(retentionDays, 10),
          ...(feedType === "youtube" && {
            exclude_shorts: excludeShorts,
          }),
          ...(feedType === "github_repo" && {
            adapter_config: {
              ...adapterConfig,
              branch,
              paths: filePatterns.split("\n").map((p) => p.trim()).filter(Boolean),
              include_content: includeContent,
              backfill_days: backfillDays === "" ? 90 : parseInt(backfillDays, 10),
              auto_translate: autoTranslate,
            },
          }),
          ...(feedType === "web_scraper" && {
            adapter_config: {
              ...adapterConfig,
              link_selector: scraperLinkSelector || null,
              url_pattern: scraperUrlPattern || null,
              max_articles: parseInt(scraperMaxArticles, 10) || 20,
              follow_pagination: scraperFollowPagination,
              auto_translate: autoTranslate,
            },
          }),
          ...(feedType === "telegram" && {
            adapter_config: (() => {
              const cfg: Record<string, unknown> = {
                ...adapterConfig,
                include_media: tgIncludeMedia,
                extract_forwards: tgExtractForwards,
                realtime: tgRealtime,
                auto_translate: autoTranslate,
              };
              if (tgThreatActorId) cfg.threat_actor_id = tgThreatActorId;
              else delete cfg.threat_actor_id;
              if (tgCampaignId) cfg.campaign_id = tgCampaignId;
              else delete cfg.campaign_id;
              return cfg;
            })(),
          }),
          ...(feedType === "bluesky" && {
            adapter_config: (() => {
              const cfg: Record<string, unknown> = { mode: bskyMode };
              if (bskyMode === "author") {
                cfg.handle = bskyHandle.trim().replace(/^@/, "");
                cfg.include_reposts = bskyIncludeReposts;
              } else if (bskyMode === "feed") {
                cfg.feed_uri = bskyFeedUri.trim();
              } else if (bskyMode === "search") {
                cfg.query = bskyQuery.trim();
                if (bskyLang.trim()) cfg.lang = bskyLang.trim();
              }
              cfg.identifier = bskyIdentifier.trim() || null;
              if (bskyAppPassword !== "") {
                cfg.app_password = bskyAppPassword;
              }
              cfg.author_entity =
                bskyAuthorType && bskyAuthorId
                  ? { type: bskyAuthorType, id: bskyAuthorId }
                  : null;
              cfg.auto_translate = autoTranslate;
              return cfg;
            })(),
          }),
          ...(!["github_repo", "web_scraper", "telegram", "bluesky"].includes(feedType) && {
            adapter_config: { ...adapterConfig, auto_translate: autoTranslate },
          }),
          ...(() => {
            const map: Record<string, { mode: "full" | "selective" | "manual" | "none"; extract: boolean }> = {
              full: { mode: "full", extract: true },
              selective: { mode: "selective", extract: true },
              known_only: { mode: "full", extract: false },
              manual: { mode: "manual", extract: false },
              none: { mode: "none", extract: false },
            };
            const { mode, extract } = map[intelLevel];
            const origMode = subscription.intel_extraction_mode || "selective";
            const origExtract = subscription.auto_extract_on_ingest ?? false;
            return {
              ...(mode !== origMode ? { intel_extraction_mode: mode } : {}),
              ...(extract !== origExtract ? { auto_extract_on_ingest: extract } : {}),
            };
          })(),
          ...(extractRules !== (subscription.extract_detection_rules ?? false)
            ? { extract_detection_rules: extractRules }
            : {}),
          ...(extractTools !== (subscription.extract_tools ?? true) ? { extract_tools: extractTools } : {}),
        };
    try {
      await updateFeed.mutateAsync({
        feedId: subscription.id,
        data: { ...curation, ...infrastructure },
      });
      onClose();
    } catch {
      // error handled by mutation
    }
  };

  const handleUnsubscribe = () => {
    const title = subscription.custom_title || subscription.title;
    undoableDelete({
      label: `Feed "${title}"`,
      key: `feed-${subscription.id}`,
      onDelete: () => deleteFeed.mutate(subscription.id),
      onInitiate: () => onClose(),
    });
  };

  const trapRef = useFocusTrap<HTMLDivElement>();

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.key === "Escape" && onClose()} ref={trapRef} role="dialog" aria-modal="true" aria-label="Edit feed">
        <div className={styles.header}>
          <h2>Edit Feed</h2>
          <button onClick={onClose} className={styles.closeBtn} aria-label="Close">&times;</button>
        </div>

        <div className={styles.body}>
          {!isAdmin && (
            <div className={styles.adminScopeNote}>
              Sync and extraction settings are managed by admins. You can change this feed's
              display name, category, mute state and source assessment.
            </div>
          )}

          {isAdmin && (
          <>
          <div className={styles.field}>
            <label>Feed URL</label>
            <input
              type="url"
              value={feedUrl}
              onChange={(e) => setFeedUrl(e.target.value)}
              placeholder="https://example.com/feed.xml"
              className={styles.input}
            />
          </div>

          <div className={styles.field}>
            <label>Feed Type</label>
            <select
              value={feedType}
              onChange={(e) => setFeedType(e.target.value)}
              className={styles.select}
            >
              <option value="rss">RSS</option>
              <option value="atom">Atom</option>
              <option value="youtube">YouTube</option>
              <option value="podcast">Podcast</option>
              <option value="reddit">Reddit</option>
              <option value="github">GitHub</option>
              <option value="github_repo">GitHub Repo</option>
              <option value="github_releases">GitHub Releases</option>
              <option value="github_advisories">GitHub Advisories</option>
              <option value="nvd">NVD</option>
              <option value="mastodon">Mastodon</option>
              <option value="web_scraper">Web Scraper</option>
              <option value="bluesky">Bluesky</option>
              <option value="telegram">Telegram</option>
            </select>
          </div>
          </>
          )}

          <div className={styles.field}>
            <label>Display Name</label>
            <input
              type="text"
              value={customTitle}
              onChange={(e) => setCustomTitle(e.target.value)}
              placeholder={subscription.title}
              className={styles.input}
              autoFocus
            />
          </div>

          <div className={styles.field}>
            <label>Category</label>
            <select
              value={categoryId}
              onChange={(e) => setCategoryId(e.target.value)}
              className={styles.select}
            >
              <option value="">Uncategorized</option>
              {categories?.map((cat) => (
                <option key={cat.id} value={cat.id}>{cat.name}</option>
              ))}
            </select>
          </div>

          {isAdmin && (
          <>
          <div className={styles.field}>
            <label>Poll Interval</label>
            <select
              value={interval}
              onChange={(e) => setInterval(e.target.value)}
              className={styles.select}
            >
              <option value="15">Every 15 min</option>
              <option value="30">Every 30 min</option>
              <option value="60">Every hour</option>
              <option value="360">Every 6 hours</option>
              <option value="1440">Once a day</option>
            </select>
          </div>

          <div className={styles.field}>
            <label>Article Retention</label>
            <select
              value={retentionDays}
              onChange={(e) => setRetentionDays(e.target.value)}
              className={styles.select}
            >
              <option value="">Keep forever</option>
              <option value="30">30 days</option>
              <option value="90">90 days</option>
              <option value="180">180 days</option>
              <option value="365">1 year</option>
            </select>
          </div>
          </>
          )}

          <label className={styles.checkboxRow}>
            <input
              type="checkbox"
              checked={isMuted}
              onChange={(e) => setIsMuted(e.target.checked)}
            />
            <span>Muted</span>
            <span className={styles.hint}>Muted feeds still sync but don't appear in unread counts</span>
          </label>

          {isAdmin && (
          <label className={styles.checkboxRow}>
            <input
              type="checkbox"
              checked={autoTranslate}
              onChange={(e) => setAutoTranslate(e.target.checked)}
            />
            <span>Auto-translate on ingest</span>
            <span className={styles.hint}>
              Detect language and translate to English via the LibreTranslate sidecar.
              Original is preserved; translation is shown alongside.
            </span>
          </label>
          )}

          {isAdmin && feedType === "youtube" && (
            <label className={styles.checkboxRow}>
              <input
                type="checkbox"
                checked={excludeShorts}
                onChange={(e) => setExcludeShorts(e.target.checked)}
              />
              <span>Exclude Shorts</span>
              <span className={styles.hint}>Skip YouTube Shorts during feed sync</span>
            </label>
          )}

          {isAdmin && feedType === "github_repo" && (
            <>
              <div className={styles.field}>
                <label>Branch</label>
                <input
                  type="text"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  placeholder="main"
                  className={styles.input}
                />
              </div>
              <div className={styles.field}>
                <label>File Patterns</label>
                <textarea
                  value={filePatterns}
                  onChange={(e) => setFilePatterns(e.target.value)}
                  placeholder={"**/*.yml\n**/*.yaml"}
                  className={styles.textarea}
                  rows={3}
                />
                <span className={styles.fieldHint}>One glob pattern per line</span>
              </div>
              <div className={styles.field}>
                <label>Backfill Days</label>
                <input
                  type="number"
                  value={backfillDays}
                  onChange={(e) => setBackfillDays(e.target.value)}
                  min="0"
                  className={styles.input}
                />
                <span className={styles.fieldHint}>Days of history to import on first fetch. 0 = all history (default 90)</span>
              </div>
              <label className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={includeContent}
                  onChange={(e) => setIncludeContent(e.target.checked)}
                />
                <span>Include file content</span>
                <span className={styles.hint}>Fetch and display full file contents (uses more API quota)</span>
              </label>
            </>
          )}

          {isAdmin && feedType === "web_scraper" && (
            <>
              <div className={styles.field}>
                <label>Link Selector</label>
                <input
                  type="text"
                  value={scraperLinkSelector}
                  onChange={(e) => setScraperLinkSelector(e.target.value)}
                  placeholder="a.post-title, article a"
                  className={styles.input}
                />
                <span className={styles.fieldHint}>CSS selector for article links. Leave blank for auto-detection.</span>
              </div>
              <div className={styles.field}>
                <label>URL Pattern</label>
                <input
                  type="text"
                  value={scraperUrlPattern}
                  onChange={(e) => setScraperUrlPattern(e.target.value)}
                  placeholder="/blog/.*"
                  className={styles.input}
                />
                <span className={styles.fieldHint}>Regex filter for discovered links</span>
              </div>
              <div className={styles.field}>
                <label>Max Articles per Poll</label>
                <input
                  type="number"
                  value={scraperMaxArticles}
                  onChange={(e) => setScraperMaxArticles(e.target.value)}
                  min="1"
                  max="100"
                  className={styles.input}
                />
              </div>
              <label className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={scraperFollowPagination}
                  onChange={(e) => setScraperFollowPagination(e.target.checked)}
                />
                <span>Follow pagination</span>
                <span className={styles.hint}>Discover articles across multiple index pages</span>
              </label>
            </>
          )}

          {isAdmin && feedType === "bluesky" && (
            <>
              <div className={styles.field}>
                <label>Mode</label>
                <select
                  value={bskyMode}
                  onChange={(e) => setBskyMode(e.target.value)}
                  className={styles.select}
                >
                  <option value="author">Author</option>
                  <option value="feed">Custom feed</option>
                  <option value="search">Search</option>
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
                      className={styles.input}
                    />
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
                <div className={styles.field}>
                  <label>Feed URI</label>
                  <input
                    type="text"
                    value={bskyFeedUri}
                    onChange={(e) => setBskyFeedUri(e.target.value)}
                    placeholder="at://..."
                    className={styles.input}
                  />
                </div>
              )}
              {bskyMode === "search" && (
                <>
                  <div className={styles.field}>
                    <label>Query</label>
                    <input
                      type="text"
                      value={bskyQuery}
                      onChange={(e) => setBskyQuery(e.target.value)}
                      className={styles.input}
                    />
                  </div>
                  <div className={styles.field}>
                    <label>Language</label>
                    <input
                      type="text"
                      value={bskyLang}
                      onChange={(e) => setBskyLang(e.target.value)}
                      placeholder="en"
                      className={styles.input}
                    />
                  </div>
                </>
              )}
              <div className={styles.field}>
                <label>Auth Identifier (optional)</label>
                <input
                  type="text"
                  value={bskyIdentifier}
                  onChange={(e) => setBskyIdentifier(e.target.value)}
                  className={styles.input}
                  placeholder="your.handle.bsky.social"
                />
              </div>
              <div className={styles.field}>
                <label>App Password</label>
                <input
                  type="password"
                  value={bskyAppPassword}
                  onChange={(e) => setBskyAppPassword(e.target.value)}
                  placeholder="Leave blank to keep current"
                  className={styles.input}
                />
                <span className={styles.fieldHint}>
                  Stored encrypted. Submit blank to keep the existing value.
                </span>
              </div>
              <div className={styles.field}>
                <label>Attribute posts to (optional)</label>
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
                </div>
              )}
            </>
          )}

          {isAdmin && feedType === "telegram" && (
            <>
              {tgHealth.data && (
                <div className={styles.tgHealth}>
                  <div className={styles.tgHealthHeader}>
                    <strong>Telegram Channel Health</strong>
                    <span className={styles.hint}>
                      Last fetch:{" "}
                      {tgHealth.data.last_fetched_at
                        ? new Date(tgHealth.data.last_fetched_at).toLocaleString()
                        : "never"}
                    </span>
                  </div>
                  <div className={styles.tgHealthGrid}>
                    <div>
                      <span className={styles.hint}>Channel:</span>{" "}
                      {tgHealth.data.channel.channel_username
                        ? `@${tgHealth.data.channel.channel_username}`
                        : tgHealth.data.channel.channel_id || "(unresolved)"}
                    </div>
                    <div>
                      <span className={styles.hint}>Watermark:</span>{" "}
                      msg #{tgHealth.data.watermark.last_seen_id ?? "—"}
                    </div>
                    <div>
                      <span className={styles.hint}>Subscribers:</span>{" "}
                      {tgHealth.data.live.subscribers?.toLocaleString() ?? "—"}
                    </div>
                    <div>
                      <span className={styles.hint}>Session:</span> {tgHealth.data.session.name}
                    </div>
                    <div>
                      <span className={styles.hint}>Recent (7d):</span>{" "}
                      {tgHealth.data.recent_7d.total} ingested,{" "}
                      {tgHealth.data.recent_7d.edited} edited,{" "}
                      {tgHealth.data.recent_7d.deleted} deleted
                    </div>
                    <div>
                      <span className={styles.hint}>Realtime:</span>{" "}
                      {tgHealth.data.realtime_enabled ? (
                        tgListener.data?.running ? (
                          <span className={styles.tgHealthLive}>● live</span>
                        ) : (
                          <span className={styles.tgHealthDown}>● enabled, listener down</span>
                        )
                      ) : (
                        "off"
                      )}
                    </div>
                  </div>
                  {tgHealth.data.flood_wait_seconds !== null && (
                    <div className={`${styles.tgHealthBanner} ${styles.tgHealthBannerWarn}`}>
                      ⚠ Flood wait: {tgHealth.data.flood_wait_seconds}s — Telegram is rate-limiting
                      this account.
                    </div>
                  )}
                  {tgHealth.data.live.scam || tgHealth.data.live.fake ? (
                    <div className={`${styles.tgHealthBanner} ${styles.tgHealthBannerError}`}>
                      ⚠ Telegram has flagged this channel as{" "}
                      {tgHealth.data.live.scam ? "scam" : "fake"}.
                    </div>
                  ) : null}
                </div>
              )}

              <label className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={tgIncludeMedia}
                  onChange={(e) => setTgIncludeMedia(e.target.checked)}
                />
                <span>Download media</span>
                <span className={styles.hint}>Photos, videos, voice notes, and documents</span>
              </label>
              <label className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={tgExtractForwards}
                  onChange={(e) => setTgExtractForwards(e.target.checked)}
                />
                <span>Show forward attribution</span>
              </label>
              <label className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={tgRealtime}
                  onChange={(e) => setTgRealtime(e.target.checked)}
                />
                <span>Realtime ingest</span>
                <span className={styles.hint}>
                  Push updates from Telethon as they arrive (requires telegram-listener container).
                  Falls back to 30-min polling if the listener is down.
                </span>
              </label>
              <div className={styles.field}>
                <label>Auto-attribute every message to threat actor</label>
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
                  Future entries will be auto-linked. Existing entries are not retroactively backfilled.
                </span>
              </div>
              <div className={styles.field}>
                <label>Auto-link every message to campaign</label>
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
              </div>
            </>
          )}

          {isAdmin && (
          <>
          <div className={styles.sectionDivider}>
            <span>Readers</span>
          </div>

          <div className={styles.field}>
            <FeedSubscribersPanel feedId={subscription.id} feedTitle={subscription.title} />
          </div>

          <div className={styles.sectionDivider}>
            <span>Intelligence</span>
          </div>

          <div className={styles.field}>
            <label>Intelligence Extraction</label>
            <select
              value={intelLevel}
              onChange={(e) => setIntelLevel(e.target.value)}
              className={styles.select}
            >
              <option value="full">Full — Extract all intelligence automatically</option>
              <option value="selective">Selective — Security-relevant articles only</option>
              <option value="known_only">Known entities only — Match against existing database</option>
              <option value="manual">Manual — Only when triggered</option>
              <option value="none">None — Disabled</option>
            </select>
            <span className={styles.fieldHint}>
              {intelLevel === "full" && "Best for dedicated threat intel feeds (CISA, Mandiant, CrowdStrike)"}
              {intelLevel === "selective" && "Runs a relevance check, then extracts TTPs, CVEs, and matches known entities"}
              {intelLevel === "known_only" && "Matches articles against threat actors, malware, and TTPs already in your database"}
              {intelLevel === "manual" && "No automatic processing — extract per-article from the context menu"}
              {intelLevel === "none" && "For non-security feeds (YouTube entertainment, general news)"}
            </span>
          </div>

          <label className={styles.checkboxRow}>
            <input
              type="checkbox"
              checked={extractRules}
              onChange={(e) => setExtractRules(e.target.checked)}
            />
            <span>Extract Detection Rules</span>
            <span className={styles.hint}>Auto-extract SIGMA, YARA, Elastic, Snort/Suricata, and Splunk rules from article content</span>
          </label>

          <label className={styles.checkboxRow}>
            <input
              type="checkbox"
              checked={extractTools}
              onChange={(e) => setExtractTools(e.target.checked)}
            />
            <span>Extract Tools</span>
            <span className={styles.hint}>Let AI extraction create tool entities from this feed. Turn off for advisory and rule-repository feeds — they name affected or referenced software, not tooling an adversary wielded</span>
          </label>
          </>
          )}

          <div className={styles.field}>
            <label>Source Reliability</label>
            <select
              value={reliability}
              onChange={(e) => setReliability(e.target.value)}
              className={styles.select}
            >
              <option value="">Not rated</option>
              <option value="A">A — Reliable</option>
              <option value="B">B — Usually reliable</option>
              <option value="C">C — Fairly reliable</option>
              <option value="D">D — Not usually reliable</option>
              <option value="E">E — Unreliable</option>
              <option value="F">F — Cannot be judged</option>
            </select>
          </div>

          <div className={styles.field}>
            <label>Analyst Notes</label>
            <textarea
              value={analystNotes}
              onChange={(e) => setAnalystNotes(e.target.value)}
              placeholder="Notes about this source..."
              className={styles.textarea}
              rows={2}
            />
          </div>

          {subscription.last_error && (
            <div className={styles.errorInfo}>
              <span className={styles.errorLabel}>Last Error</span>
              <span className={styles.errorText}>{subscription.last_error}</span>
            </div>
          )}

          <div className={styles.actions}>
            {canUnsubscribe && (
              <button onClick={handleUnsubscribe} className={styles.dangerBtn}>
                Unsubscribe
              </button>
            )}
            <div className={styles.actionsSpacer} />
            <button onClick={onClose} className={styles.cancelBtn}>Cancel</button>
            <button
              onClick={handleSave}
              disabled={updateFeed.isPending}
              className={styles.saveBtn}
            >
              {updateFeed.isPending ? "Saving..." : "Save"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
