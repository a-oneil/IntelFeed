import { useInfiniteQuery, useMutation, useQueryClient, keepPreviousData } from "@tanstack/react-query";
import { currentReadingPrefs } from "@/hooks/useReadingPrefs";
import { useCallback, useMemo } from "react";
import api from "@/api/client";
import { isVisitorNow } from "@/stores/authStore";
import type {
  CursorPaginatedResponse,
  Entry,
  EntryDetail,
  PriorityQueueResponse,
  TranslateEntryResponse,
} from "@/api/types";
import { useQuery } from "@tanstack/react-query";

/**
 * Debounced read-state reconcile. Mark-read/unread fires on every article
 * opened (and on scroll with markReadOnScroll), and the optimistic update has
 * already put the new state on screen, so the refetch that reconciles with
 * the server waits until the clicking stops. Otherwise each click refetches
 * every loaded list page, the sidebar's six counts and the feeds, and a quick
 * run through a dozen articles queues hundreds of requests on the API.
 *
 * The timer is module-level: every component that marks entries read shares
 * one reconcile.
 */
let reconcileTimer: ReturnType<typeof setTimeout> | undefined;

function useDebouncedReadReconcile(delayMs = 1500) {
  const queryClient = useQueryClient();
  return useCallback(() => {
    clearTimeout(reconcileTimer);
    reconcileTimer = setTimeout(() => {
      queryClient.invalidateQueries({ queryKey: ["entries"] });
      queryClient.invalidateQueries({ queryKey: ["entries-count"] });
      queryClient.invalidateQueries({ queryKey: ["entry"] });
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
    }, delayMs);
  }, [queryClient, delayMs]);
}

interface EntryFilters {
  feed_id?: string;
  category_id?: string;
  is_read?: boolean;
  is_starred?: boolean;
  is_bookmarked?: boolean;
  watched?: boolean;
  content_type?: string;
  change_type?: string;
  since?: string;
  before?: string;
  country_id?: string;
  country_role?: string;
  saved_search_id?: string;
  campaign_id?: string;
  /** Only entries mentioning a CVE in CISA KEV or under active exploitation. */
  exploited_cves?: boolean;
  /** With entity_id: keep only entries linked to that entity. */
  entity_type?: string;
  entity_id?: string;
  /** Only entries whose targeted sector matches this slug. */
  sector?: string;
  sort?: string;
  dedup?: boolean;
}

export function useEntries(filters: EntryFilters, { enabled = true }: { enabled?: boolean } = {}) {
  return useInfiniteQuery({
    enabled,
    queryKey: ["entries", filters],
    queryFn: async ({ pageParam }) => {
      const params: Record<string, string | boolean | undefined> = {
        ...filters,
        limit: String(currentReadingPrefs().entries_per_page),
      };
      if (pageParam) {
        params.cursor = pageParam;
      }
      const res = await api.get<CursorPaginatedResponse<Entry>>("/entries", { params });
      return res.data;
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
  });
}

/**
 * The Priority Queue: radar-ranked entries with story threads folded in as
 * single rows. One request rather than the list plus a threads call merged in
 * the client — the server owns the order, so what an analyst reads here is what
 * an agent asking "what should I read next" gets back.
 *
 * `excludeThreadIds` are threads this reader cleared: the row goes, and its
 * members come back as standalone entries rather than vanishing with it.
 */
export function usePriorityQueue(
  {
    enabled = true,
    unreadOnly = true,
    excludeThreadIds = [],
    withThreads = true,
  }: { enabled?: boolean; unreadOnly?: boolean; excludeThreadIds?: string[]; withThreads?: boolean } = {},
) {
  const excluded = [...excludeThreadIds].sort();
  return useInfiniteQuery({
    queryKey: ["priority-queue", { unreadOnly, withThreads, excluded }],
    queryFn: async ({ pageParam }) => {
      const params = new URLSearchParams({
        limit: "50",
        unread_only: String(unreadOnly),
        with_threads: String(withThreads),
      });
      for (const id of excluded) params.append("exclude_thread_ids", id);
      if (pageParam) params.set("cursor", pageParam);
      const res = await api.get<PriorityQueueResponse>(`/entries/priority-queue?${params}`);
      return res.data;
    },
    enabled,
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
  });
}

export function useEntriesCount(filters: EntryFilters) {
  return useQuery({
    queryKey: ["entries-count", filters],
    queryFn: async () => {
      const { sort: _sort, ...rest } = filters;
      const res = await api.get<{ total: number }>("/entries/count", { params: rest });
      return res.data.total;
    },
    staleTime: 30_000,
    // Keep the last count on screen while a refetch runs (e.g. filter/window
    // change) instead of flashing to undefined.
    placeholderData: keepPreviousData,
  });
}

/**
 * Unread counts for the sidebar's Articles quick-view chips (last 24h, this
 * week, watched, bookmarked, starred). Each is a small /entries/count query;
 * the time anchors are frozen per mount so the query keys stay cache-stable.
 * Returns a folder → count map (undefined while a count is still loading).
 */
export function useVirtualFolderCounts() {
  // Bucket the window anchors to the top of the current hour so the query keys
  // stay identical across sidebar remounts — a fresh Date.now() each mount would
  // mint a new key every time, defeat the cache, and make the chip counts flicker.
  const hourStart = Math.floor(Date.now() / 3_600_000) * 3_600_000;
  const since24h = useMemo(() => new Date(hourStart - 24 * 60 * 60 * 1000).toISOString(), [hourStart]);
  const sinceWeek = useMemo(() => new Date(hourStart - 7 * 24 * 60 * 60 * 1000).toISOString(), [hourStart]);
  const last24h = useEntriesCount({ is_read: false, since: since24h, dedup: true });
  const thisWeek = useEntriesCount({ is_read: false, since: sinceWeek, dedup: true });
  const watched = useEntriesCount({ is_read: false, watched: true, dedup: true });
  const bookmarked = useEntriesCount({ is_read: false, is_bookmarked: true, dedup: true });
  const starred = useEntriesCount({ is_read: false, is_starred: true, dedup: true });
  return useMemo<Record<string, number | undefined>>(
    () => ({
      last_24h: last24h.data,
      this_week: thisWeek.data,
      watched: watched.data,
      bookmarked: bookmarked.data,
      starred: starred.data,
    }),
    [last24h.data, thisWeek.data, watched.data, bookmarked.data, starred.data],
  );
}

/**
 * Unread, radar-surfaced entry count for the sidebar's Priority Queue badge.
 * Returns 0 when signal surfacing is disabled (backend short-circuits).
 */
export function usePriorityUnreadCount() {
  return useQuery({
    queryKey: ["priority-unread-count"],
    queryFn: async () => {
      const res = await api.get<{ unread_count: number }>("/entries/priority-unread-count");
      return res.data.unread_count;
    },
    staleTime: 30_000,
    placeholderData: keepPreviousData,
  });
}

/**
 * Total count for the sidebar's Priority Queue badge, matching the rows the
 * queue actually renders: unread radar-surfaced entries with live story threads
 * folded in (computed directly by GET /api/entries/priority-unread-count).
 */
export function usePriorityQueueCount() {
  const { data: radarUnread } = usePriorityUnreadCount();
  return radarUnread ?? 0;
}

export function useEntry(entryId: string | null) {
  return useQuery({
    queryKey: ["entry", entryId],
    queryFn: async () => {
      const res = await api.get<EntryDetail>(`/entries/${entryId}`);
      return res.data;
    },
    enabled: !!entryId,
  });
}

/**
 * Shared read/unread mutation with optimistic cache updates.
 *
 * The list (`["entries"]` infinite queries) and the open reader (`["entry", id]`)
 * both derive their read state from separate caches. Relying on
 * invalidate → refetch alone leaves a visible window — as long as the server
 * round-trip — where one cache has flipped and the other hasn't, so a just-read
 * article lingers in the list (dimmed) while the reader shows it unread, or vice
 * versa. Under rapid auto-read navigation the windows stack and the mismatch
 * looks permanent. We update both caches synchronously in `onMutate` (rolling
 * back on error) so they can never disagree — flipping the flag in place, or
 * dropping the entry from any list whose read-state filter it no longer matches
 * (the Hide-Read list) — then reconcile with the server in `onSettled`.
 */
function useReadStateMutation(read: boolean) {
  const queryClient = useQueryClient();
  const reconcile = useDebouncedReadReconcile();
  return useMutation({
    mutationFn: async (entryId: string) => {
      // A visitor has no read state: opening and scrolling articles must not
      // try to record one (the server would refuse it anyway).
      if (isVisitorNow()) return;
      await api.put(`/entries/${entryId}/${read ? "read" : "unread"}`);
    },
    onMutate: async (entryId: string) => {
      if (isVisitorNow()) return undefined;
      // Stop in-flight refetches from clobbering the optimistic write.
      await queryClient.cancelQueries({ queryKey: ["entries"] });
      await queryClient.cancelQueries({ queryKey: ["entry", entryId] });

      const prevEntries = queryClient.getQueriesData<{
        pages?: CursorPaginatedResponse<Entry>[];
      }>({ queryKey: ["entries"] });
      const prevDetail = queryClient.getQueryData<EntryDetail>(["entry", entryId]);

      // Update every cached entries list, reading each query's own filter so we
      // do the right thing per list. A list scoped to a single read-state (the
      // Hide-Read list keys on `is_read: false`) must DROP the entry once its new
      // state no longer matches the filter — otherwise a just-read article
      // lingers as a dimmed row instead of disappearing. Lists with no read
      // filter just flip the flag in place. Removing optimistically (rather than
      // leaning on the onSettled refetch) is essential under rapid auto-read
      // navigation, where each onMutate's cancelQueries would otherwise cancel
      // the prior mutation's reconciling refetch and let read rows pile up.
      for (const [key] of prevEntries) {
        const filterIsRead = (key[1] as EntryFilters | undefined)?.is_read;
        const drops = filterIsRead !== undefined && filterIsRead !== read;
        queryClient.setQueryData<{ pages?: CursorPaginatedResponse<Entry>[] } | undefined>(
          key,
          (old) => {
            if (!old?.pages) return old;
            return {
              ...old,
              pages: old.pages.map((p) => ({
                ...p,
                items: drops
                  ? p.items.filter((it) => it.id !== entryId)
                  : p.items.map((it) =>
                      it.id === entryId ? { ...it, is_read: read } : it,
                    ),
              })),
            };
          },
        );
      }
      queryClient.setQueryData<EntryDetail>(["entry", entryId], (old) =>
        old ? { ...old, is_read: read } : old,
      );

      return { prevEntries, prevDetail, entryId };
    },
    onError: (_err, _entryId, ctx) => {
      if (!ctx) return;
      for (const [key, data] of ctx.prevEntries) {
        queryClient.setQueryData(key, data);
      }
      queryClient.setQueryData(["entry", ctx.entryId], ctx.prevDetail);
    },
    onSettled: () => {
      // Nothing changed for a visitor, and refetching would only spend their
      // rate-limit budget.
      if (isVisitorNow()) return;
      reconcile();
    },
  });
}

export function useMarkRead() {
  return useReadStateMutation(true);
}

export function useMarkUnread() {
  return useReadStateMutation(false);
}

export function useToggleStar() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (entryId: string) => {
      if (isVisitorNow()) return null;
      const res = await api.put(`/entries/${entryId}/star`);
      return res.data;
    },
    onSuccess: (_data, entryId) => {
      if (isVisitorNow()) return;
      queryClient.invalidateQueries({ queryKey: ["entries"] });
      queryClient.invalidateQueries({ queryKey: ["entries-count"] });
      queryClient.invalidateQueries({ queryKey: ["entry", entryId] });
    },
  });
}

export function useToggleBookmark() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (entryId: string) => {
      if (isVisitorNow()) return null;
      const res = await api.put(`/entries/${entryId}/bookmark`);
      return res.data;
    },
    onSuccess: (_data, entryId) => {
      if (isVisitorNow()) return;
      queryClient.invalidateQueries({ queryKey: ["entries"] });
      queryClient.invalidateQueries({ queryKey: ["entries-count"] });
      queryClient.invalidateQueries({ queryKey: ["entry", entryId] });
    },
  });
}

export function useMarkAllRead() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: {
      feed_id?: string;
      category_id?: string;
      since?: string;
      before?: string;
      radar_only?: boolean;
    }) => {
      const res = await api.post("/entries/mark-all-read", data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["entries"] });
      queryClient.invalidateQueries({ queryKey: ["entries-count"] });
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
    },
  });
}

export function useBulkAction() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: { entry_ids: string[]; action: string }) => {
      const res = await api.post("/entries/bulk-action", data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["entries"] });
      queryClient.invalidateQueries({ queryKey: ["entries-count"] });
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
    },
  });
}

export interface SimilarEntry {
  id: string;
  title: string;
  feed_title: string;
  feed_id?: string;
  feed_type?: string;
  published_at: number | null;
  summary?: string;
  author?: string;
  url?: string;
  image_url?: string | null;
  word_count?: number | null;
  /** Cosine similarity 0-1. Only present on embedding-backed results. */
  similarity?: number;
  /** Set when the neighbour already belongs to a story thread. */
  thread_slug?: string | null;
  thread_title?: string | null;
}

export interface SimilarEntriesResponse {
  items: SimilarEntry[];
  total: number;
  query_keywords: string[];
  /** "embedding" when vectors answered, "keyword" on the Meilisearch fallback. */
  method?: "embedding" | "keyword";
}

export function useSimilarEntries(entryId: string | null, enabled = true) {
  return useQuery({
    queryKey: ["similar-entries", entryId],
    queryFn: async () => {
      const res = await api.get<SimilarEntriesResponse>(
        `/entries/${entryId}/similar`,
        { params: { limit: 8 } }
      );
      return res.data;
    },
    enabled: !!entryId && enabled,
    staleTime: 5 * 60_000,
  });
}

export function useTranslateEntry() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ entryId, target }: { entryId: string; target?: string }) => {
      const res = await api.post<TranslateEntryResponse>(
        `/entries/${entryId}/translate`,
        null,
        { params: target ? { target } : {} },
      );
      return res.data;
    },
    onSuccess: (data, { entryId }) => {
      queryClient.setQueryData<EntryDetail>(["entry", entryId], (prev) =>
        prev
          ? {
              ...prev,
              translated_html: data.translated_html,
              translated_title: data.translated_title ?? prev.translated_title,
              translation_source_language: data.source_language,
              translation_target_language: data.target_language,
              translated_at: data.translated_at,
            }
          : prev,
      );
    },
  });
}

export function useEntryNames(ids: string[]) {
  return useQuery({
    queryKey: ["entry-names", ids],
    queryFn: async () => {
      const { data } = await api.post<Array<{ id: string; title: string; feed_title: string }>>(
        "/entries/resolve-names",
        { ids }
      );
      return data;
    },
    enabled: ids.length > 0,
    staleTime: 60_000,
  });
}
