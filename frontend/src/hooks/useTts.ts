import { useCallback, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import axios from "axios";
import { toast } from "sonner";
import api from "@/api/client";
import { selectIsVisitor, useAuthStore } from "@/stores/authStore";
import { usePlayerStore, type QueueItem } from "@/stores/playerStore";

/**
 * Server-side read-aloud (Piper). Enqueues synthesis, polls until the MP3 is ready, then plays it through the shared audio player. Returns false on any failure so callers can fall back to the browser Web Speech voice. Cancellation returns null: callers must not start fallback speech in that case.
 *
 * Works both authenticated (default) and on the public share page: pass the share token to route through the token-gated public endpoints (no JWT).
 */

interface TrackMeta {
  entryId: string;
  title: string;
  feedTitle: string;
  thumbnailUrl?: string | null;
}

interface StartArgs {
  source: "entry" | "summary" | "entity";
  id: string;
  // For source="summary": filter context so the server resolves the same cached summary (and thus the same pre-generated audio). Ignored for entries.
  filters?: Record<string, unknown>;
  // For source="entity": which workbench entity type the id refers to.
  entityType?: string;
  track: TrackMeta;
}

interface PrepareResponse {
  cache_key: string | null;
  status: "pending" | "ready" | "error";
  duration?: number | null;
  error?: string | null;
}

const POLL_INTERVAL_MS = 1500;
const POLL_TIMEOUT_MS = 180_000;

// Unauthenticated axios for the public share page (mirrors SharedEntryPage).
const publicApi = axios.create({ baseURL: "/api", timeout: 20_000 });

function buildFileUrl(cacheKey: string, shareToken?: string): string {
  if (shareToken) {
    return `/api/shared/${shareToken}/tts/file/${cacheKey}.mp3`;
  }
  // A plain <audio> element can't send a bearer header, so put the token in the URL as Telegram media does.
  const token = useAuthStore.getState().accessToken;
  const base = `/api/tts/file/${cacheKey}.mp3`;
  return token ? `${base}?token=${encodeURIComponent(token)}` : base;
}

export function useTts(opts?: { shareToken?: string }) {
  const shareToken = opts?.shareToken;
  const play = usePlayerStore((s) => s.play);
  const [isPreparing, setIsPreparing] = useState(false);
  // The in-flight request; cancel() or a newer start() replaces it. Unmounting deliberately does not cancel: the player is global, so audio requested from a day divider or the reader still plays after that view scrolls away or closes.
  const requestRef = useRef<symbol | null>(null);

  const start = useCallback(
    async (args: StartArgs): Promise<boolean | null> => {
      const request = Symbol();
      requestRef.current = request;
      const canceled = () => requestRef.current !== request;
      setIsPreparing(true);
      let toastId: string | number | undefined;
      try {
        const url = shareToken ? `/shared/${shareToken}/tts/prepare` : `/tts/prepare`;
        // The public route resolves the text from the share; the authenticated route sends source/id/filters/entity_type.
        const body = shareToken
          ? {}
          : { source: args.source, id: args.id, filters: args.filters, entity_type: args.entityType };
        // Generous per-request timeout: the summary prepare renders markdown server-side and the server can be briefly loaded, so the 15s client default is too tight and shows up as a spurious "timeout exceeded".
        const cfg = { timeout: 45_000 };
        // A visitor (public read-only mode) only plays audio that already exists: GET /tts/existing never synthesizes, and returns 404 on a miss.
        const visitor = !shareToken && selectIsVisitor(useAuthStore.getState());
        const post = () =>
          (visitor
            ? api.get<PrepareResponse>("/tts/existing", {
                params: { source: args.source, id: args.id, entity_type: args.entityType },
              })
            : shareToken
              ? publicApi.post<PrepareResponse>(url, body, cfg)
              : api.post<PrepareResponse>(url, body, cfg)
          ).then((r) => r.data);

        let resp = await post();
        if (canceled()) return null;
        // Only toast when there is a wait; a cache hit plays instantly.
        if (resp.status === "pending") {
          toastId = toast.loading("Generating audio…", {
            description: "Audio for this article is being generated.",
          });
        }
        const startedAt = Date.now();
        while (resp.status === "pending" && Date.now() - startedAt < POLL_TIMEOUT_MS) {
          if (canceled()) return null;
          await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
          if (canceled()) return null;
          resp = await post(); // prepare is idempotent — re-POST returns current status
        }

        if (canceled()) return null;
        if (resp.status !== "ready" || !resp.cache_key) return false;

        const item: QueueItem = {
          mediaId: `tts:${resp.cache_key}`,
          entryId: args.track.entryId,
          title: args.track.title,
          feedTitle: args.track.feedTitle,
          audioUrl: buildFileUrl(resp.cache_key, shareToken),
          thumbnailUrl: args.track.thumbnailUrl ?? null,
          durationSeconds: resp.duration ?? null,
          kind: "tts",
        };
        play(item);
        if (toastId !== undefined) {
          toast.success("Playing audio", { id: toastId, duration: 2000 });
          toastId = undefined;
        }
        return true;
      } catch {
        return canceled() ? null : false;
      } finally {
        if (toastId !== undefined) toast.dismiss(toastId);
        if (!canceled()) {
          requestRef.current = null;
          setIsPreparing(false);
        }
      }
    },
    [shareToken, play],
  );

  const cancel = useCallback(() => {
    requestRef.current = null;
    setIsPreparing(false);
  }, []);

  return { start, cancel, isPreparing };
}

/** Whether read-aloud audio already exists for an entry. For visitors only, who can play existing audio but never generate new audio; signed-in readers don't call it. */
export function useExistingTts(entryId: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: ["tts-existing", "entry", entryId],
    queryFn: async () =>
      (await api.get<PrepareResponse>("/tts/existing", { params: { source: "entry", id: entryId } })).data,
    enabled: enabled && !!entryId,
    retry: false,
    staleTime: 5 * 60_000,
    meta: { silenceToast: true },
  });
}
