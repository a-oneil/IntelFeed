import { describe, expect, it } from "vitest";
import type { LinkPreview } from "@/api/types";
import {
  defaultChoices,
  feedOptionLabels,
  feedsToCreate,
  looksLikeLink,
  nvdFeed,
  parseMastodonTag,
  splitPatterns,
} from "../sourcePlan";

const base: LinkPreview = {
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
};

describe("looksLikeLink", () => {
  it.each(["thedfirreport.com", "https://t.me/x", "github.com/a/b"])("accepts %s", (v) => {
    expect(looksLikeLink(v)).toBe(true);
  });
  it.each(["", "ransomware", "two words.com", "a.b"])("rejects %s", (v) => {
    expect(looksLikeLink(v)).toBe(false);
  });
});

describe("parseMastodonTag", () => {
  it("reads '#tag on server'", () => {
    expect(parseMastodonTag("#threatintel on infosec.exchange")).toEqual({
      instanceUrl: "https://infosec.exchange",
      hashtag: "threatintel",
    });
  });
  it("reads a bare tag and server", () => {
    expect(parseMastodonTag("dfir https://ioc.exchange")?.instanceUrl).toBe("https://ioc.exchange");
  });
  it("needs a server", () => {
    expect(parseMastodonTag("#threatintel")).toBeNull();
  });
});

describe("feedOptionLabels", () => {
  it("names a WordPress pair Posts and Comments", () => {
    const p = {
      ...base,
      feeds: [
        { url: "a", title: "Site", feed_type: "rss", description: null },
        { url: "b", title: "Site » Comments Feed", feed_type: "rss", description: null },
      ],
    };
    expect(feedOptionLabels(p)).toEqual(["Posts", "Comments"]);
  });
  it("names section feeds by what follows the site name", () => {
    const p = {
      ...base,
      feeds: [
        { url: "a", title: "News", feed_type: "rss", description: null },
        { url: "b", title: "News - Security", feed_type: "rss", description: null },
      ],
    };
    expect(feedOptionLabels(p)).toEqual(["News", "Security"]);
  });
});

describe("GitHub", () => {
  const repo: LinkPreview = {
    ...base,
    kind: "github",
    feed_type: "github_repo",
    url: "https://github.com/o/r",
    github: { owner: "o", repo: "r", default_branch: "dev", has_releases: false, rules: null },
  };

  it("follows commits when a repo without rules has never released", () => {
    expect(defaultChoices(repo, true).github).toEqual({ files: false, releases: false, commits: true });
  });

  it("splits typed paths on commas and newlines", () => {
    expect(splitPatterns("rules/**/*.yml, docs/**\n*.md")).toEqual(["rules/**/*.yml", "docs/**", "*.md"]);
  });

  it("names every feed after the custom name", () => {
    const choices = { ...defaultChoices(repo, true), github: { files: true, releases: true, commits: true } };
    const bodies = feedsToCreate(repo, choices, { name: "Proj", categoryId: "c", interval: 60 });
    expect(bodies.map((b) => b.custom_title)).toEqual(["Proj", "Proj releases", "Proj commits"]);
    expect(bodies.every((b) => b.category_id === "c" && b.fetch_interval_minutes === 60)).toBe(true);
    expect(bodies[0].adapter_config).toMatchObject({ branch: "dev", paths: [] });
    expect(bodies[2].url).toBe("https://github.com/o/r/commits/dev.atom");
  });
});

describe("nvdFeed", () => {
  it("keeps each keyword and a stable URL", () => {
    expect(nvdFeed(" Fortinet , ivanti ")).toMatchObject({
      url: "nvd://cves?keywords=fortinet%2Civanti",
      adapter_config: { keywords: ["Fortinet", "ivanti"] },
    });
  });
});
