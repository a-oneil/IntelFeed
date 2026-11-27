import type { LinkPreview } from "@/api/types";

/** The body POST /feeds takes. */
export interface FeedCreate {
  url: string;
  feed_type?: string;
  custom_title?: string;
  adapter_config?: Record<string, unknown>;
  category_id?: string;
  fetch_interval_minutes?: number;
  intel_extraction_mode?: string;
  auto_extract_on_ingest?: boolean;
  exclude_shorts?: boolean;
}

export type GitHubPart = "releases" | "files" | "commits";

/** The few choices the dialog offers for a pasted link. */
export interface SourceChoices {
  /** kind=feed: which of the site's feeds. */
  feedUrl: string;
  skipShorts: boolean;
  github: Record<GitHubPart, boolean>;
  /** Newline- or comma-separated globs; empty means every file. */
  githubPaths: string;
  includeReposts: boolean;
}

/** What the dialog starts with for a link: the safest choice that still delivers something. */
export function defaultChoices(preview: LinkPreview, skipShortsDefault: boolean): SourceChoices {
  const rules = preview.github?.rules ?? null;
  return {
    feedUrl: preview.feeds[0]?.url ?? preview.url,
    skipShorts: skipShortsDefault,
    // A rule repo is followed for its rule files. Any other repo is followed
    // for its releases, or for its commits when it has never cut one.
    github: {
      files: rules !== null,
      releases: rules === null && preview.github?.has_releases !== false,
      commits: rules === null && preview.github?.has_releases === false,
    },
    githubPaths: rules ? rules.paths.join(", ") : "",
    includeReposts: false,
  };
}

export const GITHUB_PARTS: { id: GitHubPart; label: string; detail: string }[] = [
  { id: "releases", label: "Releases", detail: "new versions and their notes" },
  { id: "files", label: "File changes", detail: "new and changed files" },
  { id: "commits", label: "Commits", detail: "every push to the default branch" },
];

export function splitPatterns(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((p) => p.trim())
    .filter(Boolean);
}

/**
 * The feeds one press of Subscribe creates. Usually one; a GitHub repo makes
 * one per thing ticked. ``name`` replaces the title the server would pick,
 * and ``interval`` (minutes) the type's default; both are optional.
 */
export function feedsToCreate(
  preview: LinkPreview,
  choices: SourceChoices,
  common: { categoryId?: string; interval?: number; name?: string }
): FeedCreate[] {
  const base: Partial<FeedCreate> = {
    ...(common.categoryId ? { category_id: common.categoryId } : {}),
    ...(common.interval ? { fetch_interval_minutes: common.interval } : {}),
  };
  const name = common.name?.trim() || undefined;

  switch (preview.kind) {
    case "feed": {
      const feed = preview.feeds.find((f) => f.url === choices.feedUrl) ?? preview.feeds[0];
      const isYouTube = (feed?.feed_type ?? preview.feed_type) === "youtube";
      return [
        {
          ...base,
          url: feed?.url ?? preview.url,
          ...(name ? { custom_title: name } : {}),
          ...(isYouTube ? { exclude_shorts: choices.skipShorts } : {}),
        },
      ];
    }
    case "page":
      // No custom_title: the first fetch names the feed after the page's own title.
      return [
        {
          ...base,
          url: preview.url,
          feed_type: "web_scraper",
          adapter_config: { blog_url: preview.url, max_articles: 20, follow_pagination: false },
          ...(name ? { custom_title: name } : {}),
        },
      ];
    case "github":
      return githubFeeds(preview, choices, base, name);
    case "bluesky":
    case "bluesky_feed":
    case "bluesky_search":
      return [{ ...base, ...blueskyFeed(preview, choices), ...(name ? { custom_title: name } : {}) }];
    case "telegram": {
      const channel = preview.telegram?.channel ?? "";
      return [
        {
          ...base,
          url: `https://t.me/${channel}`,
          feed_type: "telegram",
          custom_title: name ?? preview.title,
          adapter_config: {
            channel: `@${channel}`,
            include_media: true,
            max_message_age_days: 30,
            max_messages_per_fetch: 200,
            extract_forwards: true,
          },
        },
      ];
    }
    case "mastodon_tag": {
      const m = preview.mastodon!;
      return [mastodonTagFeed(m.instance_url, m.hashtag, base, name ?? preview.title)];
    }
  }
}

function githubFeeds(
  preview: LinkPreview,
  choices: SourceChoices,
  base: Partial<FeedCreate>,
  name: string | undefined
): FeedCreate[] {
  const gh = preview.github!;
  const repoUrl = `https://github.com/${gh.owner}/${gh.repo}`;
  const label = name ?? `${gh.owner}/${gh.repo}`;
  const branch = gh.rules?.branch || gh.default_branch || "main";
  const out: FeedCreate[] = [];
  if (choices.github.files) {
    out.push({
      ...base,
      url: repoUrl,
      feed_type: "github_repo",
      custom_title: label,
      adapter_config: {
        owner: gh.owner,
        repo: gh.repo,
        branch,
        paths: splitPatterns(choices.githubPaths),
        include_content: true,
      },
      // Rule files are what a rule repo is for: extract from every one.
      ...(gh.rules ? { intel_extraction_mode: "full", auto_extract_on_ingest: true } : {}),
    });
  }
  if (choices.github.releases) {
    out.push({
      ...base,
      url: `${repoUrl}/releases`,
      feed_type: "github_releases",
      custom_title: `${label} releases`,
      adapter_config: { owner: gh.owner, repo: gh.repo },
    });
  }
  if (choices.github.commits) {
    out.push({
      ...base,
      url: `${repoUrl}/commits/${gh.default_branch || "main"}.atom`,
      custom_title: `${label} commits`,
    });
  }
  return out;
}

function blueskyFeed(preview: LinkPreview, choices: SourceChoices): FeedCreate {
  const b = preview.bluesky!;
  if (b.mode === "feed") {
    return {
      url: `bluesky://feed/${encodeURIComponent(b.feed_uri ?? "")}`,
      feed_type: "bluesky",
      custom_title: `Bluesky feed: ${preview.title}`,
      adapter_config: { mode: "feed", feed_uri: b.feed_uri },
    };
  }
  if (b.mode === "search") return blueskySearchFeed(b.query ?? "");
  const handle = b.handle ?? "";
  return {
    url: `bluesky://author/${handle}`,
    feed_type: "bluesky",
    custom_title: b.display_name ? `${b.display_name} (Bluesky)` : `Bluesky @${handle}`,
    adapter_config: { mode: "author", handle, include_reposts: choices.includeReposts },
  };
}

export function blueskySearchFeed(query: string): FeedCreate {
  const q = query.trim();
  return {
    url: `bluesky://search/${encodeURIComponent(q)}`,
    feed_type: "bluesky",
    custom_title: `Bluesky: "${q}"`,
    adapter_config: { mode: "search", query: q },
  };
}

export function mastodonTagFeed(
  instanceUrl: string,
  hashtag: string,
  base: Partial<FeedCreate> = {},
  title?: string
): FeedCreate {
  const instance = instanceUrl.replace(/\/+$/, "");
  const tag = hashtag.replace(/^#/, "");
  return {
    ...base,
    url: `${instance}/tags/${tag}`,
    feed_type: "mastodon",
    custom_title: title ?? `#${tag} on ${instance.replace(/^https?:\/\//, "")}`,
    adapter_config: { instance_url: instance, hashtags: [tag] },
  };
}

/** "#threatintel on infosec.exchange" (or "threatintel infosec.exchange"). */
export function parseMastodonTag(value: string): { instanceUrl: string; hashtag: string } | null {
  const m = value.trim().match(/^#?([\p{L}\p{N}_]+)\s+(?:on\s+|@)?((?:https?:\/\/)?[\w.-]+\.[a-z]{2,})\/?$/iu);
  if (!m) return null;
  const host = m[2].replace(/^https?:\/\//, "");
  return { instanceUrl: `https://${host}`, hashtag: m[1] };
}

export function nvdFeed(keywords: string): FeedCreate {
  const words = keywords
    .split(",")
    .map((w) => w.trim())
    .filter(Boolean);
  return {
    url: `nvd://cves?keywords=${encodeURIComponent(words.join(",").toLowerCase())}`,
    feed_type: "nvd",
    custom_title: `NVD: ${words.join(", ")}`,
    adapter_config: { keywords: words },
  };
}

/** The badge letters and the line under the title for a preview. */
export function describePreview(p: LinkPreview): { mono: string; kind: string } {
  switch (p.kind) {
    case "feed": {
      const type = p.feeds[0]?.feed_type ?? p.feed_type;
      if (type === "youtube") return { mono: "YT", kind: "YouTube channel" };
      if (type === "podcast") return { mono: "POD", kind: "Podcast" };
      if (p.feeds.length > 1) return { mono: "RSS", kind: `Website · ${p.feeds.length} feeds` };
      return { mono: "RSS", kind: "Feed" };
    }
    case "github":
      return { mono: "GH", kind: "GitHub repository" };
    case "bluesky":
      return { mono: "BS", kind: "Bluesky account" };
    case "bluesky_feed":
      return { mono: "BS", kind: "Bluesky feed" };
    case "bluesky_search":
      return { mono: "BS", kind: "Bluesky search" };
    case "telegram":
      return { mono: "TG", kind: "Telegram channel" };
    case "mastodon_tag":
      return { mono: "MA", kind: "Mastodon hashtag" };
    case "page":
      return { mono: "WEB", kind: "Web page" };
  }
}

/**
 * A short name for each of a site's feeds. WordPress calls its second feed
 * "<Site> » Comments Feed"; that reads as "Comments", and the site's own feed
 * as "Posts" beside it.
 */
export function feedOptionLabels(p: LinkPreview): string[] {
  const hasComments = p.feeds.some((f) => /comment/i.test(f.title ?? ""));
  const site = p.feeds[0]?.title ?? "";
  return p.feeds.map((f, i) => {
    const title = f.title ?? f.url;
    if (/comment/i.test(title)) return "Comments";
    if (hasComments && (i === 0 || title === site)) return "Posts";
    if (site && title.startsWith(site) && title.length > site.length) {
      return title.slice(site.length).replace(/^[\s»:|·–—-]+/, "") || title;
    }
    return title;
  });
}

/** True when a typed value is worth asking the server about. */
export function looksLikeLink(value: string): boolean {
  const v = value.trim();
  return v.length > 3 && !/\s/.test(v) && /[a-z0-9-]\.[a-z]{2,}/i.test(v);
}

export const INTERVALS: { minutes: number; label: string }[] = [
  { minutes: 15, label: "Every 15 min" },
  { minutes: 30, label: "Every 30 min" },
  { minutes: 60, label: "Every hour" },
  { minutes: 360, label: "Every 6 hours" },
  { minutes: 1440, label: "Once a day" },
];

export function intervalLabel(minutes: number): string {
  return INTERVALS.find((i) => i.minutes === minutes)?.label ?? `Every ${minutes} min`;
}
