import { useCallback } from "react";
import { useLocation, useNavigate, type NavigateFunction } from "react-router-dom";
import { useIntelStore } from "@/stores/intelStore";
import { useUIStore } from "@/stores/uiStore";

/**
 * The one answer to "where does clicking an entry open it?".
 *
 * Under `/workbench` — entity profiles included — the docked reader on the
 * right IS the reader: the surface you clicked from stays put and acts as the
 * list. Writing `uiStore.setSelectedEntry` there is a dead click, because the
 * dock reads `intelStore.workbenchReaderEntryId` and nothing on screen is
 * bound to the feed's selection.
 *
 * Everywhere else the feed reader owns the entry, so the selection goes to
 * `uiStore` and the caller lands on a route that renders it.
 */

/**
 * Routes that render `uiStore.selectedEntryId` themselves — the feed shell
 * (`MainLayout`, including its priority-queue and feeds mounts) and the search
 * page. Clicking an entry there moves that surface's own selection; it must
 * not bounce the analyst to the feed root.
 */
const SELECTION_READER_PATHS = new Set(["/", "/feeds", "/priority-queue", "/search"]);

export function openEntryAt(pathname: string, entryId: string, navigate?: NavigateFunction) {
  if (pathname.startsWith("/workbench")) {
    useIntelStore.getState().openWorkbenchReader(entryId);
    return;
  }
  useUIStore.getState().setSelectedEntry(entryId);
  if (!SELECTION_READER_PATHS.has(pathname)) navigate?.("/");
}

/** Hook form: `const openEntry = useOpenEntry()` then `openEntry(id)`. */
export function useOpenEntry() {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  return useCallback((entryId: string) => openEntryAt(pathname, entryId, navigate), [pathname, navigate]);
}

/**
 * Same rule for the story a set of articles belongs to: `ThreadReader` takes
 * the workbench dock rather than sending the analyst to the feed.
 */
export function useOpenThread() {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  return useCallback(
    (slug: string) => {
      if (pathname.startsWith("/workbench")) {
        useIntelStore.getState().openWorkbenchThread(slug);
        return;
      }
      useUIStore.getState().setSelectedThread(slug);
      if (pathname !== "/") navigate("/");
    },
    [pathname, navigate],
  );
}
