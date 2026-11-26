import assert from "node:assert/strict";
import { test } from "node:test";

import { author, feedLinks, ingestBody, publishedAt } from "../src/lib/page-meta.js";

const page = (over = {}) => ({ url: "https://example.com/a", title: "A", metas: [], ldjson: [], feeds: [], ...over });

test("published date prefers JSON-LD, then meta tags, then <time>", () => {
  const ld = JSON.stringify({ "@graph": [{ "@type": "WebPage" }, { "@type": "NewsArticle", datePublished: "2024-09-10T12:00:00Z" }] });
  assert.equal(publishedAt(page({ ldjson: [ld], metas: [["article:published_time", "2020-01-01"]] })), "2024-09-10T12:00:00.000Z");
  assert.equal(publishedAt(page({ metas: [["article:published_time", "2023-03-04T05:06:07+00:00"]] })), "2023-03-04T05:06:07.000Z");
  assert.equal(publishedAt(page({ time: "2022-02-02" })), "2022-02-02T00:00:00.000Z");
  assert.equal(publishedAt(page({ ldjson: ["{not json"], metas: [["date", "garbage"]] })), null);
});

test("author skips profile URLs", () => {
  assert.equal(author(page({ ldjson: [JSON.stringify({ author: [{ name: "Jane Doe" }] })] })), "Jane Doe");
  assert.equal(author(page({ metas: [["article:author", "https://facebook.com/x"], ["author", "Sam"]] })), "Sam");
  assert.equal(author(page()), null);
});

test("feed links keep real feeds only, once each", () => {
  const feeds = feedLinks(
    page({
      feeds: [
        { href: "https://example.com/feed/", type: "application/rss+xml", title: "Blog" },
        { href: "https://example.com/feed/", type: "application/rss+xml", title: "Blog" },
        { href: "https://example.com/oembed?url=x", type: "application/json", title: "" },
        { href: "https://example.com/feed.json", type: "application/json", title: "" },
        { href: "https://example.com/fr/", type: "text/html", title: "French" },
        { href: "javascript:alert(1)", type: "application/atom+xml", title: "" },
      ],
    }),
  );
  assert.deepEqual(
    feeds.map((f) => f.url),
    ["https://example.com/feed/", "https://example.com/feed.json"],
  );
});

test("ingest body carries what the page has and nothing empty", () => {
  const body = ingestBody(page({ html: "<html></html>", selection: "key part" }), {
    note: "  why  ",
    tagIds: ["t1"],
    client: "intelfeed-extension/1.0.0",
  });
  assert.deepEqual(body, {
    url: "https://example.com/a",
    title: "A",
    client: "intelfeed-extension/1.0.0",
    html: "<html></html>",
    selection: "key part",
    note: "why",
    tag_ids: ["t1"],
  });
  assert.deepEqual(Object.keys(ingestBody(page(), {})), ["url", "title", "client"]);
});

test("a GitHub repo page names the repository to track", async () => {
  const { githubRepo, repoFeedBody, DEFAULT_REPO_PATTERNS } = await import("../src/lib/page-meta.js");
  const gh = (url, extra = {}) => githubRepo(page({ url, ...extra }));

  assert.deepEqual(gh("https://github.com/SigmaHQ/sigma", { githubDefaultBranch: "master" }), {
    owner: "SigmaHQ",
    repo: "sigma",
    branch: "master",
    paths: DEFAULT_REPO_PATTERNS,
  });
  assert.deepEqual(gh("https://github.com/SigmaHQ/sigma/tree/master/rules/windows"), {
    owner: "SigmaHQ",
    repo: "sigma",
    branch: "master",
    paths: ["rules/windows/**"],
  });
  assert.deepEqual(gh("https://github.com/x/y/blob/dev/a/b.yml").paths, ["a/**"]);
  assert.equal(gh("https://github.com/x/y.git").repo, "y");
  assert.equal(gh("https://github.com/x/y").branch, "main");
  assert.equal(gh("https://github.com/settings/profile"), null);
  assert.equal(gh("https://github.com/orgs/x"), null);
  assert.equal(gh("https://github.com/SigmaHQ"), null);
  assert.equal(gh("https://gitlab.com/x/y"), null);

  assert.deepEqual(repoFeedBody({ owner: "x", repo: "y", branch: "main", paths: ["**/*.yml"] }), {
    url: "https://github.com/x/y",
    feed_type: "github_repo",
    custom_title: "x/y",
    adapter_config: { owner: "x", repo: "y", branch: "main", paths: ["**/*.yml"], include_content: true },
    fetch_interval_minutes: 120,
    intel_extraction_mode: "full",
    auto_extract_on_ingest: true,
  });
});

test("a subreddit page offers the subreddit through the Reddit adapter", async () => {
  const { siteFeeds, subreddit, redditFeedBody } = await import("../src/lib/page-meta.js");
  assert.equal(subreddit("https://www.reddit.com/r/wallstreetbets/"), "wallstreetbets");
  assert.equal(subreddit("https://old.reddit.com/r/blueteamsec/comments/abc/x/"), "blueteamsec");
  assert.equal(subreddit("https://www.reddit.com/user/someone/"), null);
  assert.equal(subreddit("https://notreddit.com/r/malware/"), null);
  // old.reddit advertises .rss links; the adapter feed wins
  const feeds = siteFeeds({
    url: "https://old.reddit.com/r/malware/",
    feeds: [{ type: "application/rss+xml", href: "https://old.reddit.com/r/malware/.rss", title: "RSS" }],
  });
  assert.deepEqual(feeds, [
    { url: "https://www.reddit.com/r/malware/", title: "r/malware", kind: "Subreddit", subreddit: "malware" },
  ]);
  assert.deepEqual(redditFeedBody("malware").adapter_config, { subreddit: "malware" });
  assert.equal(redditFeedBody("malware").feed_type, "reddit");
});
