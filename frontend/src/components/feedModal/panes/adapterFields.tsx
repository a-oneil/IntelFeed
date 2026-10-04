import { useCampaigns } from "@/hooks/useCampaigns";
import { useProducts, useThreatActors, useVendors } from "@/hooks/useIntelligence";
import { useTelegramFeedHealth, useTelegramListenerStatus } from "@/hooks/useTelegram";
import type { FeedForm } from "../useFeedForm";
import styles from "../fields.module.css";

type AuthorEntityType = "" | "threat_actor" | "vendor" | "product";

interface AdapterProps {
  feedId: string;
  form: FeedForm;
}

const str = (v: unknown, fallback = ""): string => (v == null ? fallback : String(v));
const bool = (v: unknown, fallback = false): boolean => (v == null ? fallback : Boolean(v));

/** The per-type half of the Source pane. Returns null for types with no config. */
export function AdapterFields({ feedId, form }: AdapterProps) {
  switch (form.values.feed_type) {
    case "youtube":
      return <YouTubeFields form={form} feedId={feedId} />;
    case "github_repo":
      return <GitHubRepoFields form={form} feedId={feedId} />;
    case "web_scraper":
      return <WebScraperFields form={form} feedId={feedId} />;
    case "bluesky":
      return <BlueskyFields form={form} feedId={feedId} />;
    case "telegram":
      return <TelegramFields form={form} feedId={feedId} />;
    default:
      return null;
  }
}

/** True when the type has its own fields, so the pane can label the section. */
export function hasAdapterFields(feedType: string): boolean {
  return ["youtube", "github_repo", "web_scraper", "bluesky", "telegram"].includes(feedType);
}

function YouTubeFields({ form }: AdapterProps) {
  const { values, setAdapter } = form;
  return (
    <label className={styles.checkRow}>
      <input
        type="checkbox"
        checked={bool(values.adapter.exclude_shorts)}
        onChange={(e) => setAdapter("exclude_shorts", e.target.checked)}
      />
      <span className={styles.checkText}>
        <span className={styles.checkLabel}>Exclude Shorts</span>
        <span className={styles.hint}>Skip YouTube Shorts during sync.</span>
      </span>
    </label>
  );
}

function GitHubRepoFields({ form }: AdapterProps) {
  const { values, setAdapter } = form;
  const paths = Array.isArray(values.adapter.paths) ? (values.adapter.paths as string[]) : [];

  return (
    <>
      <div className={styles.row}>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="gh-branch">
            Branch
          </label>
          <input
            id="gh-branch"
            type="text"
            className={styles.input}
            value={str(values.adapter.branch, "main")}
            placeholder="main"
            onChange={(e) => setAdapter("branch", e.target.value)}
          />
        </div>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="gh-backfill">
            Backfill days
          </label>
          <input
            id="gh-backfill"
            type="number"
            min="0"
            className={styles.input}
            value={str(values.adapter.backfill_days, "90")}
            onChange={(e) =>
              setAdapter("backfill_days", e.target.value === "" ? 90 : Number(e.target.value))
            }
          />
          <span className={styles.hint}>
            History to import on first fetch. 0 = everything. Changing this resets
            the fetch state and re-imports.
          </span>
        </div>
      </div>

      <div className={styles.field}>
        <label className={styles.label} htmlFor="gh-paths">
          File patterns
        </label>
        <textarea
          id="gh-paths"
          rows={3}
          className={styles.textarea}
          value={paths.join("\n")}
          placeholder={"**/*.yml\n**/*.yaml"}
          onChange={(e) =>
            setAdapter(
              "paths",
              e.target.value
                .split("\n")
                .map((p) => p.trim())
                .filter(Boolean)
            )
          }
        />
        <span className={styles.hint}>One glob pattern per line.</span>
      </div>

      <label className={styles.checkRow}>
        <input
          type="checkbox"
          checked={bool(values.adapter.include_content, true)}
          onChange={(e) => setAdapter("include_content", e.target.checked)}
        />
        <span className={styles.checkText}>
          <span className={styles.checkLabel}>Include file content</span>
          <span className={styles.hint}>Fetch full file bodies. Uses more API quota.</span>
        </span>
      </label>
    </>
  );
}

function WebScraperFields({ form }: AdapterProps) {
  const { values, setAdapter } = form;
  return (
    <>
      <div className={styles.field}>
        <label className={styles.label} htmlFor="ws-selector">
          Link selector
        </label>
        <input
          id="ws-selector"
          type="text"
          className={styles.input}
          value={str(values.adapter.link_selector)}
          placeholder="a.post-title, article a"
          onChange={(e) => setAdapter("link_selector", e.target.value || null)}
        />
        <span className={styles.hint}>
          CSS selector for article links. Blank auto-detects.
        </span>
      </div>

      <div className={styles.row}>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="ws-pattern">
            URL pattern
          </label>
          <input
            id="ws-pattern"
            type="text"
            className={styles.input}
            value={str(values.adapter.url_pattern)}
            placeholder="/blog/.*"
            onChange={(e) => setAdapter("url_pattern", e.target.value || null)}
          />
          <span className={styles.hint}>Regex filter for discovered links.</span>
        </div>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="ws-max">
            Max articles per poll
          </label>
          <input
            id="ws-max"
            type="number"
            min="1"
            max="100"
            className={styles.input}
            value={str(values.adapter.max_articles, "20")}
            onChange={(e) =>
              setAdapter("max_articles", Number(e.target.value) || 20)
            }
          />
        </div>
      </div>

      <label className={styles.checkRow}>
        <input
          type="checkbox"
          checked={bool(values.adapter.follow_pagination)}
          onChange={(e) => setAdapter("follow_pagination", e.target.checked)}
        />
        <span className={styles.checkText}>
          <span className={styles.checkLabel}>Follow pagination</span>
          <span className={styles.hint}>Discover articles across index pages.</span>
        </span>
      </label>
    </>
  );
}

function BlueskyFields({ form }: AdapterProps) {
  const { values, setAdapter, newAppPassword, setNewAppPassword } = form;
  const mode = str(values.adapter.mode, "author");
  const author = (values.adapter.author_entity as { type?: string; id?: string } | null) || null;
  const authorType = (author?.type as AuthorEntityType) || "";
  const authorId = author?.id || "";

  const { data: actorsData } = useThreatActors(
    authorType === "threat_actor" ? { limit: 500 } : undefined
  );
  const { data: vendorsData } = useVendors(authorType === "vendor" ? { limit: 200 } : undefined);
  const { data: productsData } = useProducts(
    authorType === "product" ? { limit: 200 } : undefined
  );

  const options =
    authorType === "threat_actor"
      ? actorsData?.items
      : authorType === "vendor"
        ? vendorsData?.items
        : authorType === "product"
          ? productsData?.items
          : undefined;

  const setAuthor = (type: AuthorEntityType, id: string) =>
    setAdapter("author_entity", type && id ? { type, id } : null);

  return (
    <>
      <div className={styles.row}>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="bsky-mode">
            Mode
          </label>
          <select
            id="bsky-mode"
            className={styles.select}
            value={mode}
            onChange={(e) => setAdapter("mode", e.target.value)}
          >
            <option value="author">Author</option>
            <option value="feed">Custom feed</option>
            <option value="search">Search</option>
          </select>
        </div>

        {mode === "author" && (
          <div className={styles.field}>
            <label className={styles.label} htmlFor="bsky-handle">
              Handle
            </label>
            <input
              id="bsky-handle"
              type="text"
              className={styles.input}
              value={str(values.adapter.handle)}
              placeholder="alice.bsky.social"
              onChange={(e) => setAdapter("handle", e.target.value)}
            />
          </div>
        )}

        {mode === "feed" && (
          <div className={styles.field}>
            <label className={styles.label} htmlFor="bsky-uri">
              Feed URI
            </label>
            <input
              id="bsky-uri"
              type="text"
              className={styles.input}
              value={str(values.adapter.feed_uri)}
              placeholder="at://…"
              onChange={(e) => setAdapter("feed_uri", e.target.value)}
            />
          </div>
        )}

        {mode === "search" && (
          <div className={styles.field}>
            <label className={styles.label} htmlFor="bsky-query">
              Query
            </label>
            <input
              id="bsky-query"
              type="text"
              className={styles.input}
              value={str(values.adapter.query)}
              onChange={(e) => setAdapter("query", e.target.value)}
            />
          </div>
        )}
      </div>

      {mode === "search" && (
        <div className={styles.field}>
          <label className={styles.label} htmlFor="bsky-lang">
            Language
          </label>
          <input
            id="bsky-lang"
            type="text"
            className={styles.input}
            value={str(values.adapter.lang)}
            placeholder="en"
            onChange={(e) => setAdapter("lang", e.target.value)}
          />
        </div>
      )}

      {mode === "author" && (
        <label className={styles.checkRow}>
          <input
            type="checkbox"
            checked={bool(values.adapter.include_reposts)}
            onChange={(e) => setAdapter("include_reposts", e.target.checked)}
          />
          <span className={styles.checkText}>
            <span className={styles.checkLabel}>Include reposts</span>
          </span>
        </label>
      )}

      <div className={styles.row}>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="bsky-identifier">
            Auth identifier
          </label>
          <input
            id="bsky-identifier"
            type="text"
            className={styles.input}
            value={str(values.adapter.identifier)}
            placeholder="your.handle.bsky.social"
            onChange={(e) => setAdapter("identifier", e.target.value)}
          />
          <span className={styles.hint}>Optional.</span>
        </div>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="bsky-password">
            App password
          </label>
          <input
            id="bsky-password"
            type="password"
            className={styles.input}
            value={newAppPassword}
            placeholder="Leave blank to keep current"
            onChange={(e) => setNewAppPassword(e.target.value)}
          />
          <span className={styles.hint}>
            Stored encrypted. Blank keeps the existing value.
          </span>
        </div>
      </div>

      <div className={styles.row}>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="bsky-author-type">
            Attribute posts to
          </label>
          <select
            id="bsky-author-type"
            className={styles.select}
            value={authorType}
            onChange={(e) => setAuthor(e.target.value as AuthorEntityType, "")}
          >
            <option value="">Nobody</option>
            <option value="threat_actor">Threat actor</option>
            <option value="vendor">Vendor</option>
            <option value="product">Product</option>
          </select>
          <span className={styles.hint}>Optional.</span>
        </div>
        {authorType && (
          <div className={styles.field}>
            <label className={styles.label} htmlFor="bsky-author-id">
              Entity
            </label>
            <select
              id="bsky-author-id"
              className={styles.select}
              value={authorId}
              onChange={(e) => setAuthor(authorType, e.target.value)}
            >
              <option value="">Select…</option>
              {options?.map((o: { id: string; name: string }) => (
                <option key={o.id} value={o.id}>
                  {o.name}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>
    </>
  );
}

function TelegramFields({ feedId, form }: AdapterProps) {
  const { values, setAdapter } = form;
  const health = useTelegramFeedHealth(feedId);
  const listener = useTelegramListenerStatus(true);
  const { data: actorsData } = useThreatActors({ limit: 500 });
  const { data: campaignsData } = useCampaigns({ status: "active", limit: 200 });

  const h = health.data;

  return (
    <>
      {h && (
        <div className={styles.summaryBox}>
          <span className={styles.summaryLabel}>Channel health</span>
          <div className={styles.healthGrid}>
            <div>
              <span className={styles.healthKey}>Channel: </span>
              {h.channel.channel_username
                ? `@${h.channel.channel_username}`
                : h.channel.channel_id || "(unresolved)"}
            </div>
            <div>
              <span className={styles.healthKey}>Watermark: </span>
              msg #{h.watermark.last_seen_id ?? "—"}
            </div>
            <div>
              <span className={styles.healthKey}>Subscribers: </span>
              {h.live.subscribers?.toLocaleString() ?? "—"}
            </div>
            <div>
              <span className={styles.healthKey}>Session: </span>
              {h.session.name}
            </div>
            <div>
              <span className={styles.healthKey}>Recent (7d): </span>
              {h.recent_7d.total} in, {h.recent_7d.edited} edited, {h.recent_7d.deleted} deleted
            </div>
            <div>
              <span className={styles.healthKey}>Realtime: </span>
              {h.realtime_enabled ? (
                listener.data?.running ? (
                  <span className={styles.live}>live</span>
                ) : (
                  <span className={styles.down}>enabled, listener down</span>
                )
              ) : (
                "off"
              )}
            </div>
          </div>
          {h.flood_wait_seconds !== null && (
            <div className={`${styles.banner} ${styles.bannerWarn}`}>
              Flood wait: {h.flood_wait_seconds}s — Telegram is rate-limiting this
              account.
            </div>
          )}
          {(h.live.scam || h.live.fake) && (
            <div className={`${styles.banner} ${styles.bannerError}`}>
              Telegram has flagged this channel as {h.live.scam ? "scam" : "fake"}.
            </div>
          )}
        </div>
      )}

      <label className={styles.checkRow}>
        <input
          type="checkbox"
          checked={bool(values.adapter.include_media, true)}
          onChange={(e) => setAdapter("include_media", e.target.checked)}
        />
        <span className={styles.checkText}>
          <span className={styles.checkLabel}>Download media</span>
          <span className={styles.hint}>Photos, videos, voice notes and documents.</span>
        </span>
      </label>

      <label className={styles.checkRow}>
        <input
          type="checkbox"
          checked={bool(values.adapter.extract_forwards, true)}
          onChange={(e) => setAdapter("extract_forwards", e.target.checked)}
        />
        <span className={styles.checkText}>
          <span className={styles.checkLabel}>Show forward attribution</span>
        </span>
      </label>

      <label className={styles.checkRow}>
        <input
          type="checkbox"
          checked={bool(values.adapter.realtime)}
          onChange={(e) => setAdapter("realtime", e.target.checked)}
        />
        <span className={styles.checkText}>
          <span className={styles.checkLabel}>Realtime ingest</span>
          <span className={styles.hint}>
            Push updates from Telethon as they arrive. Needs the
            telegram-listener container; falls back to 30-minute polling if it is
            down.
          </span>
        </span>
      </label>

      <div className={styles.row}>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="tg-actor">
            Auto-attribute to threat actor
          </label>
          <select
            id="tg-actor"
            className={styles.select}
            value={str(values.adapter.threat_actor_id)}
            onChange={(e) => setAdapter("threat_actor_id", e.target.value || undefined)}
          >
            <option value="">Nobody</option>
            {actorsData?.items?.map((a: { id: string; name: string }) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
          <span className={styles.hint}>
            Applies to future entries only — existing ones are not backfilled.
          </span>
        </div>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="tg-campaign">
            Auto-link to campaign
          </label>
          <select
            id="tg-campaign"
            className={styles.select}
            value={str(values.adapter.campaign_id)}
            onChange={(e) => setAdapter("campaign_id", e.target.value || undefined)}
          >
            <option value="">None</option>
            {campaignsData?.items?.map((c: { id: string; name: string }) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </div>
      </div>
    </>
  );
}
