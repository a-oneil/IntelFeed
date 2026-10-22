import { describe, expect, it, beforeEach } from "vitest";
import {
  READING_DEFAULTS,
  applyReadingPrefsToUI,
  readingPrefs,
  readingPrefsStamp,
} from "@/hooks/useReadingPrefs";
import { useUIStore } from "@/stores/uiStore";

describe("readingPrefs", () => {
  it("returns the shipped defaults for an empty profile", () => {
    expect(readingPrefs(undefined)).toEqual(READING_DEFAULTS);
    expect(readingPrefs({})).toEqual(READING_DEFAULTS);
  });

  it("ships the production-tuned defaults", () => {
    expect(READING_DEFAULTS.date_format).toBe("both");
    expect(READING_DEFAULTS.default_view).toBe("unread");
    expect(READING_DEFAULTS.mark_read_on_scroll).toBe(true);
    expect(READING_DEFAULTS.open_links_new_tab).toBe(true);
  });

  it("the defaults for the list toggles match what a fresh UI store starts with", () => {
    const s = useUIStore.getState();
    expect(s.showUnreadOnly).toBe(READING_DEFAULTS.default_view === "unread");
    expect(s.sortOrder).toBe(READING_DEFAULTS.default_sort);
    expect(s.markReadOnScroll).toBe(READING_DEFAULTS.mark_read_on_scroll);
    expect(s.viewMode === "compact").toBe(READING_DEFAULTS.compact_view);
  });

  it("takes the account's values and ignores junk", () => {
    const prefs = readingPrefs({
      date_format: "absolute",
      entries_per_page: 100,
      default_view: "everything", // not a real option
      default_sort: "oldest",
      open_links_new_tab: "yes", // not a boolean
      compact_view: true,
    });
    expect(prefs.date_format).toBe("absolute");
    expect(prefs.entries_per_page).toBe(100);
    expect(prefs.default_view).toBe(READING_DEFAULTS.default_view);
    expect(prefs.default_sort).toBe("oldest");
    expect(prefs.open_links_new_tab).toBe(READING_DEFAULTS.open_links_new_tab);
    expect(prefs.compact_view).toBe(true);
  });
});

describe("applyReadingPrefsToUI", () => {
  beforeEach(() => {
    useUIStore.setState({
      showUnreadOnly: true,
      unreadFallbackActive: true,
      sortOrder: "newest",
      markReadOnScroll: true,
      viewMode: "magazine",
    });
  });

  it("pushes the four list defaults into the store", () => {
    applyReadingPrefsToUI({
      ...READING_DEFAULTS,
      default_view: "all",
      default_sort: "oldest",
      mark_read_on_scroll: false,
      compact_view: true,
    });
    const s = useUIStore.getState();
    expect(s.showUnreadOnly).toBe(false);
    expect(s.unreadFallbackActive).toBe(false);
    expect(s.sortOrder).toBe("oldest");
    expect(s.markReadOnScroll).toBe(false);
    expect(s.viewMode).toBe("compact");
  });

  it("compact off only leaves compact, it does not reset table or expanded views", () => {
    useUIStore.setState({ viewMode: "table" });
    applyReadingPrefsToUI({ ...READING_DEFAULTS, compact_view: false });
    expect(useUIStore.getState().viewMode).toBe("table");

    useUIStore.setState({ viewMode: "compact" });
    applyReadingPrefsToUI({ ...READING_DEFAULTS, compact_view: false });
    expect(useUIStore.getState().viewMode).toBe("magazine");
  });
});

describe("readingPrefsStamp", () => {
  it("changes when a seeded preference changes, and per user", () => {
    const a = readingPrefsStamp("u1", READING_DEFAULTS);
    expect(readingPrefsStamp("u1", READING_DEFAULTS)).toBe(a);
    expect(readingPrefsStamp("u2", READING_DEFAULTS)).not.toBe(a);
    expect(readingPrefsStamp("u1", { ...READING_DEFAULTS, default_sort: "oldest" })).not.toBe(a);
    // Preferences that are not toggles do not force a re-seed.
    expect(readingPrefsStamp("u1", { ...READING_DEFAULTS, date_format: "absolute" })).toBe(a);
  });
});
