import { useEffect } from "react";
import { useAuthStore } from "@/stores/authStore";
import { useUIStore } from "@/stores/uiStore";

/**
 * The Settings → Reading preferences, with the shipped defaults.
 *
 * These live on the account (`users.settings`), so they follow the analyst
 * between devices, while the toolbar toggles they seed (`uiStore`) stay per
 * browser. The defaults are what a fresh account gets; they match what the
 * UI store starts with on a fresh browser, so changing a default here is the
 * one place to change first-run behaviour.
 */
export interface ReadingPrefs {
  /** Which entries a feed opens on: everything, or unread only. */
  default_view: "all" | "unread";
  /** Entries fetched per page of the list. */
  entries_per_page: 25 | 50 | 100;
  /** Order of the feed list on load. */
  default_sort: "newest" | "oldest";
  /** How timestamps render app-wide (see utils/formatDate). */
  date_format: "relative" | "absolute" | "both";
  /** Article links open in a new tab instead of leaving the app. */
  open_links_new_tab: boolean;
  /** Entries scrolled past are marked read. */
  mark_read_on_scroll: boolean;
  /** Start the list in compact rows. */
  compact_view: boolean;
  /** Show the summary line under each entry title. */
  show_entry_preview: boolean;
}

export const READING_DEFAULTS: ReadingPrefs = {
  default_view: "unread",
  entries_per_page: 50,
  default_sort: "newest",
  date_format: "both",
  open_links_new_tab: true,
  mark_read_on_scroll: true,
  compact_view: false,
  show_entry_preview: true,
};

const PAGE_SIZES = new Set([25, 50, 100]);

/** The account's reading preferences over the defaults. Tolerates junk values. */
export function readingPrefs(settings: Record<string, unknown> | null | undefined): ReadingPrefs {
  const s = settings ?? {};
  const pick = <K extends keyof ReadingPrefs>(key: K, ok: (v: unknown) => boolean): ReadingPrefs[K] =>
    (ok(s[key]) ? (s[key] as ReadingPrefs[K]) : READING_DEFAULTS[key]);
  return {
    default_view: pick("default_view", (v) => v === "all" || v === "unread"),
    entries_per_page: pick("entries_per_page", (v) => typeof v === "number" && PAGE_SIZES.has(v)),
    default_sort: pick("default_sort", (v) => v === "newest" || v === "oldest"),
    date_format: pick("date_format", (v) => v === "relative" || v === "absolute" || v === "both"),
    open_links_new_tab: pick("open_links_new_tab", (v) => typeof v === "boolean"),
    mark_read_on_scroll: pick("mark_read_on_scroll", (v) => typeof v === "boolean"),
    compact_view: pick("compact_view", (v) => typeof v === "boolean"),
    show_entry_preview: pick("show_entry_preview", (v) => typeof v === "boolean"),
  };
}

/** Reading preferences of the signed-in user, re-rendering when they change. */
export function useReadingPrefs(): ReadingPrefs {
  const settings = useAuthStore((s) => s.user?.settings as Record<string, unknown> | undefined);
  return readingPrefs(settings);
}

/** Non-hook read for code outside React (formatters, query functions). */
export function currentReadingPrefs(): ReadingPrefs {
  return readingPrefs(useAuthStore.getState().user?.settings as Record<string, unknown> | undefined);
}

/**
 * The four preferences that are really defaults for toolbar toggles: push
 * them into the UI store. Compact view only moves the list between compact
 * and magazine rows — an analyst on table or expanded view keeps it.
 */
export function applyReadingPrefsToUI(prefs: ReadingPrefs): void {
  useUIStore.setState((state) => ({
    showUnreadOnly: prefs.default_view === "unread",
    unreadFallbackActive: false,
    sortOrder: prefs.default_sort,
    markReadOnScroll: prefs.mark_read_on_scroll,
    viewMode: prefs.compact_view ? "compact" : state.viewMode === "compact" ? "magazine" : state.viewMode,
  }));
}

/** What `useReadingPrefsSync` compares, so a change on any device re-applies. */
export function readingPrefsStamp(userId: string, prefs: ReadingPrefs): string {
  return `${userId}:${prefs.default_view}:${prefs.default_sort}:${prefs.mark_read_on_scroll}:${prefs.compact_view}`;
}

/**
 * Seed this browser's toolbar toggles from the account's Reading preferences.
 *
 * Mount once, app-wide. It applies when the account's preferences differ from
 * the ones this browser last applied — first sign-in here, a different user
 * signing in, or a preference changed in Settings on any device. Between
 * those moments the toolbar toggles are the analyst's own, per browser.
 */
export function useReadingPrefsSync(): void {
  const userId = useAuthStore((s) => s.user?.id);
  const prefs = useReadingPrefs();
  const applied = useUIStore((s) => s.readingPrefsApplied);
  const stamp = userId ? readingPrefsStamp(userId, prefs) : null;

  useEffect(() => {
    if (!stamp || stamp === applied) return;
    applyReadingPrefsToUI(prefs);
    useUIStore.setState({ readingPrefsApplied: stamp });
    // `prefs` is derived from the same settings the stamp summarises.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stamp, applied]);
}
