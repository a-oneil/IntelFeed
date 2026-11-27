// Pure helpers over what capture.js read from a page. No browser APIs, so the tests run them under plain node.

const DATE_KEYS = [
  "article:published_time",
  "og:published_time",
  "datepublished",
  "parsely-pub-date",
  "sailthru.date",
  "citation_publication_date",
  "dc.date.issued",
  "dc.date",
  "dcterms.created",
  "date",
  "pubdate",
  "publishdate",
];

const AUTHOR_KEYS = ["author", "article:author", "parsely-author", "sailthru.author", "dc.creator"];

const FEED_TYPES = new Set([
  "application/rss+xml",
  "application/atom+xml",
  "application/feed+json",
  "application/json",
  "application/rdf+xml",
]);

/** Every JSON-LD object in the page's scripts, @graph flattened. Bad JSON is skipped. */
function ldObjects(ldjson) {
  const out = [];
  const walk = (node) => {
    if (Array.isArray(node)) node.forEach(walk);
    else if (node && typeof node === "object") {
      out.push(node);
      if (node["@graph"]) walk(node["@graph"]);
    }
  };
  for (const text of ldjson || []) {
    try {
      walk(JSON.parse(text));
    } catch {
      // ignore
    }
  }
  return out;
}

function toIso(value) {
  if (!value) return null;
  const date = new Date(String(value).trim());
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/** The page's own published date, ISO 8601, or null. The server rejects implausible ones. */
export function publishedAt(page) {
  for (const obj of ldObjects(page.ldjson)) {
    const iso = toIso(obj.datePublished || obj.dateCreated);
    if (iso) return iso;
  }
  const metas = new Map((page.metas || []).filter(([k]) => DATE_KEYS.includes(k)));
  for (const key of DATE_KEYS) {
    const iso = toIso(metas.get(key));
    if (iso) return iso;
  }
  return toIso(page.time);
}

export function author(page) {
  for (const obj of ldObjects(page.ldjson)) {
    const a = Array.isArray(obj.author) ? obj.author[0] : obj.author;
    const name = typeof a === "string" ? a : a?.name;
    if (name && typeof name === "string" && !/^https?:/i.test(name)) return name.trim().slice(0, 500);
  }
  const metas = new Map(page.metas || []);
  for (const key of AUTHOR_KEYS) {
    const v = metas.get(key);
    if (v && !/^https?:/i.test(v)) return v.trim().slice(0, 500);
  }
  return null;
}

/** The page's advertised feeds (RSS/Atom/JSON Feed), deduplicated, http(s) only. */
export function feedLinks(page) {
  const seen = new Set();
  const out = [];
  for (const f of page.feeds || []) {
    if (!FEED_TYPES.has(f.type)) continue;
    if (f.type === "application/json" && !/feed/i.test(f.href)) continue; // oEmbed etc.
    if (!/^https?:\/\//i.test(f.href) || seen.has(f.href)) continue;
    seen.add(f.href);
    out.push({ url: f.href, title: f.title || "" });
  }
  return out;
}

/** The subreddit a reddit.com page is in (/r/<name>/…), or null. */
export function subreddit(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (!/(^|\.)reddit\.com$/i.test(u.hostname)) return null;
  const m = /^\/r\/([A-Za-z0-9_]{2,21})(\/|$)/.exec(u.pathname);
  return m ? m[1] : null;
}

/** The body for POST /api/feeds that follows a subreddit — the same feed as the Reddit starter pack's. */
export function redditFeedBody(name) {
  return {
    url: `https://www.reddit.com/r/${name}/`,
    feed_type: "reddit",
    custom_title: `r/${name}`,
    adapter_config: { subreddit: name },
    fetch_interval_minutes: 60,
  };
}

/** The feeds the popup offers for a page: a subreddit through IntelFeed's Reddit adapter (reddit.com advertises no feed, and old.reddit's .rss links would make a plain RSS feed of it), else what the page advertises. */
export function siteFeeds(page) {
  const name = subreddit(page.url);
  if (name) return [{ url: redditFeedBody(name).url, title: `r/${name}`, kind: "Subreddit", subreddit: name }];
  return feedLinks(page);
}

// github.com/<these>/… is GitHub itself, not a user or org.
const GITHUB_RESERVED = new Set(
  "about account apps codespaces collections contact customer-stories dashboard enterprise events explore features issues login marketplace new notifications organizations orgs pricing pulls readme search security settings site sponsors team topics trending users".split(
    " ",
  ),
);

// What the app's Add feed → GitHub Repo form starts with.
export const DEFAULT_REPO_PATTERNS = ["**/*.yml", "**/*.yaml"];

/** The repository a github.com page belongs to, ready for a github_repo feed: {owner, repo, branch, paths}. On a /tree/<branch>/<dir> page the branch and directory come from the URL (a branch name with a slash can't be told apart from a directory, so the first segment is taken); otherwise the default branch the page reports. Null off GitHub. */
export function githubRepo(page) {
  let url;
  try {
    url = new URL(page.url);
  } catch {
    return null;
  }
  if (url.hostname !== "github.com") return null;
  const [owner, rawRepo, view, ref, ...rest] = url.pathname.split("/").filter(Boolean);
  if (!owner || !rawRepo || GITHUB_RESERVED.has(owner.toLowerCase())) return null;
  const repo = rawRepo.replace(/\.git$/, "");
  if (!/^[\w.-]+$/.test(owner) || !/^[\w.-]+$/.test(repo)) return null;

  let branch = page.githubDefaultBranch || "main";
  let paths = DEFAULT_REPO_PATTERNS;
  if ((view === "tree" || view === "blob") && ref) {
    branch = decodeURIComponent(ref);
    const dir = (view === "blob" ? rest.slice(0, -1) : rest).map(decodeURIComponent).join("/");
    if (dir) paths = [`${dir}/**`];
  }
  return { owner, repo, branch, paths };
}

/** The body for POST /api/feeds that tracks a repository — the same feed the app's form makes. */
export function repoFeedBody({ owner, repo, branch, paths }) {
  return {
    url: `https://github.com/${owner}/${repo}`,
    feed_type: "github_repo",
    custom_title: `${owner}/${repo}`,
    adapter_config: { owner, repo, branch, paths, include_content: true },
    fetch_interval_minutes: 120,
    intel_extraction_mode: "full",
    auto_extract_on_ingest: true,
  };
}

/** The body for POST /api/entries/ingest/page. */
export function ingestBody(page, { note, tagIds, client } = {}) {
  const body = { url: page.url, title: page.title || null, client };
  if (page.html) body.html = page.html;
  if (page.selection) body.selection = page.selection.slice(0, 20000);
  const date = publishedAt(page);
  if (date) body.published_at = date;
  const by = author(page);
  if (by) body.author = by;
  if (note && note.trim()) body.note = note.trim();
  if (tagIds?.length) body.tag_ids = tagIds;
  return body;
}
