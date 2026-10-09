import { act } from "@testing-library/react";
import { renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Feed } from "@/api/types";
import { useFeedForm } from "../useFeedForm";

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
    last_fetched_at: null,
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

describe("useFeedForm", () => {
  it("starts clean and sends nothing", () => {
    const { result } = renderHook(() => useFeedForm(makeFeed()));
    expect(result.current.isDirty).toBe(false);
    expect(result.current.dirtyFields).toEqual([]);
    expect(result.current.buildPayload(true, false)).toEqual({});
  });

  it("sends only the keys that changed", () => {
    const { result } = renderHook(() => useFeedForm(makeFeed()));

    act(() => result.current.set("custom_title", "Bleeping"));

    expect(result.current.isDirty).toBe(true);
    expect(result.current.buildPayload(true, false)).toEqual({ custom_title: "Bleeping" });
  });

  it("attributes a changed field to its pane so the rail can mark it", () => {
    const { result } = renderHook(() => useFeedForm(makeFeed()));

    act(() => result.current.set("analyst_notes", "Fast on ransomware"));
    expect([...result.current.dirtyPanes]).toEqual(["assessment"]);

    act(() => result.current.set("url", "https://example.com/rss"));
    expect([...result.current.dirtyPanes].sort()).toEqual(["assessment", "source"]);
  });

  it("goes back to clean when a field is set back to its original value", () => {
    const { result } = renderHook(() => useFeedForm(makeFeed()));

    act(() => result.current.set("fetch_interval_minutes", 60));
    expect(result.current.isDirty).toBe(true);

    act(() => result.current.set("fetch_interval_minutes", 30));
    expect(result.current.isDirty).toBe(false);
  });

  it("sends an explicit null to clear the category", () => {
    const { result } = renderHook(() => useFeedForm(makeFeed()));

    act(() => result.current.set("category_id", ""));

    // Not `undefined` and not omitted: the API reads model_fields_set, so null
    // is how "Uncategorized" travels.
    const payload = result.current.buildPayload(true, false);
    expect(payload).toHaveProperty("category_id", null);
  });

  it("sends an explicit null to clear retention", () => {
    const { result } = renderHook(() => useFeedForm(makeFeed()));

    act(() => result.current.set("retention_days", ""));

    const payload = result.current.buildPayload(true, false);
    expect(payload).toHaveProperty("retention_days", null);
  });

  it("drops every infrastructure key for a non-admin", () => {
    const { result } = renderHook(() => useFeedForm(makeFeed()));

    act(() => {
      result.current.set("custom_title", "Mine");
      result.current.set("reliability_rating", "A");
      result.current.set("url", "https://evil.example.com/rss");
      result.current.set("fetch_interval_minutes", 15);
      result.current.set("intel_extraction_mode", "none");
      result.current.set("is_active", false);
    });

    // The endpoint 403s on the mere presence of an admin key, so the payload
    // must carry none of them — not even unchanged ones.
    expect(result.current.buildPayload(false, false)).toEqual({
      custom_title: "Mine",
      reliability_rating: "A",
    });
  });

  it("lets anyone pause their own copy once subscriptions are per-user", () => {
    const { result } = renderHook(() => useFeedForm(makeFeed({ per_user: true })));

    act(() => result.current.set("is_active", false));

    expect(result.current.buildPayload(false, true)).toEqual({ is_active: false });
  });

  it("withholds the pause from a non-admin while the feed is shared", () => {
    const { result } = renderHook(() => useFeedForm(makeFeed()));

    act(() => result.current.set("is_active", false));

    // One shared switch: throwing it would stop the fetch for the instance.
    expect(result.current.buildPayload(false, false)).toEqual({});
  });

  it("keeps curation keys for an admin alongside the rest", () => {
    const { result } = renderHook(() => useFeedForm(makeFeed()));

    act(() => {
      result.current.set("custom_title", "Mine");
      result.current.set("is_active", false);
    });

    expect(result.current.buildPayload(true, false)).toEqual({
      custom_title: "Mine",
      is_active: false,
    });
  });

  it("merges adapter config rather than replacing it", () => {
    const feed = makeFeed({
      feed_type: "github_repo",
      adapter_config: { branch: "main", last_commit_sha: "abc123" },
    });
    const { result } = renderHook(() => useFeedForm(feed));

    act(() => result.current.setAdapter("branch", "develop"));

    // last_commit_sha is fetch state — dropping it would re-import the repo.
    expect(result.current.buildPayload(true, false).adapter_config).toEqual({
      branch: "develop",
      last_commit_sha: "abc123",
    });
  });

  it("rebuilds bluesky config so a mode switch drops the old mode's keys", () => {
    const feed = makeFeed({
      feed_type: "bluesky",
      adapter_config: { mode: "author", handle: "alice.bsky.social", include_reposts: true },
    });
    const { result } = renderHook(() => useFeedForm(feed));

    act(() => {
      result.current.setAdapter("mode", "search");
      result.current.setAdapter("query", "ransomware");
    });

    const config = result.current.buildPayload(true, false).adapter_config as Record<string, unknown>;
    expect(config.mode).toBe("search");
    expect(config.query).toBe("ransomware");
    expect(config).not.toHaveProperty("handle");
  });

  it("never echoes a masked app password back to the server", () => {
    const feed = makeFeed({
      feed_type: "bluesky",
      adapter_config: { mode: "author", handle: "a.bsky.social", app_password: "••••••••" },
    });
    const { result } = renderHook(() => useFeedForm(feed));

    act(() => result.current.setAdapter("handle", "b.bsky.social"));

    const config = result.current.buildPayload(true, false).adapter_config as Record<string, unknown>;
    expect(config).not.toHaveProperty("app_password");
  });

  it("sends a new app password even when nothing else changed", () => {
    const feed = makeFeed({ feed_type: "bluesky", adapter_config: { mode: "author" } });
    const { result } = renderHook(() => useFeedForm(feed));

    act(() => result.current.setNewAppPassword("hunter2"));

    expect(result.current.isDirty).toBe(true);
    const config = result.current.buildPayload(true, false).adapter_config as Record<string, unknown>;
    expect(config.app_password).toBe("hunter2");
  });

  it("withholds a new app password from a non-admin", () => {
    const feed = makeFeed({ feed_type: "bluesky", adapter_config: { mode: "author" } });
    const { result } = renderHook(() => useFeedForm(feed));

    act(() => result.current.setNewAppPassword("hunter2"));

    expect(result.current.buildPayload(false, false)).toEqual({});
  });

  it("trims the text fields it sends", () => {
    const { result } = renderHook(() => useFeedForm(makeFeed()));

    act(() => {
      result.current.set("custom_title", "  Spaced  ");
      result.current.set("url", "  https://example.com/rss  ");
    });

    const payload = result.current.buildPayload(true, false);
    expect(payload.custom_title).toBe("Spaced");
    expect(payload.url).toBe("https://example.com/rss");
  });

  it("reset returns every field to the feed's stored values", () => {
    const { result } = renderHook(() => useFeedForm(makeFeed()));

    act(() => {
      result.current.set("custom_title", "Changed");
      result.current.setNewAppPassword("secret");
    });
    expect(result.current.isDirty).toBe(true);

    act(() => result.current.reset());
    expect(result.current.isDirty).toBe(false);
    expect(result.current.values.custom_title).toBe("");
  });
});
