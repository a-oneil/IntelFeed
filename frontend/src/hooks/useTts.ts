import { useCallback, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import axios from "axios";
import { toast } from "sonner";
import api from "@/api/client";
import { selectIsVisitor, useAuthStore } from "@/stores/authStore";
import { usePlayerStore, type QueueItem } from "@/stores/playerStore";

/**
 * Server-side read-aloud (Piper). Enqueues synthesis, polls until the MP3 is
 * ready, then plays it through the shared audio player. Returns false on any
 * failure so callers can fall back to the browser Web Speech voice.
 *
 * Works both authenticated (default) and on the public share page — pass the
 * share token to route through the token-gated public endpoints (no JWT).
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
  // For source="summary": filter context so the server resolves the same cached
  // summary (and thus the same pre-generated audio). Ignored for entries.
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
  // Bare <audio> can't send a bearer header — sign the URL like telegram media.
  const token = useAuthStore.getState().accessToken;
  const base = `/api/tts/file/${cacheKey}.mp3`;
  return token ? `${base}?token=${encodeURIComponent(token)}` : base;
}

export function useTts(opts?: { shareToken?: string }) {
  const shareToken = opts?.shareToken;
  const play = usePlayerStore((s) => s.play);
  const [isPreparing, setIsPreparing] = useState(false);
  const abortRef = useRef(false);

  const start = useCallback(
    async (args: StartArgs): Promise<boolean> => {
      abortRef.current = false;
      setIsPreparing(true);
      let toastId: string | number | undefined;
      try {
        const url = shareToken ? `/shared/${shareToken}/tts/prepare` : `/tts/prepare`;
        // The public route resolves text from the share; authed sends source/id/text.
        const body = shareToken
          ? {}
          : { source: args.source, id: args.id, filters: args.filters, entity_type: args.entityType };
        // Generous per-request timeout: the summary prepare renders markdown
        // server-side and the box can be briefly loaded — 15s (client default)
        // is too tight and surfaces as a spurious "timeout exceeded".
        const cfg = { timeout: 45_000 };
        // A visitor (public read-only mode) only plays audio that already
        // exists: GET /tts/existing never synthesizes, and 404s on a miss.
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
        // Only toast when we actually have to wait — a cache hit plays instantly.
        if (resp.status === "pending") {
          toastId = toast.loading("Generating audio…", {
            description: "Synthesizing a natural voice for this article.",
          });
        }
        const startedAt = Date.now();
        while (resp.status === "pending" && Date.now() - startedAt < POLL_TIMEOUT_MS) {
          if (abortRef.current) {
            if (toastId !== undefined) toast.dismiss(toastId);
            return false;
          }
          await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
          resp = await post(); // prepare is idempotent — re-POST returns current status
        }

        if (abortRef.current || resp.status !== "ready" || !resp.cache_key) {
          if (toastId !== undefined) toast.dismiss(toastId);
          return false;
        }

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
        if (toastId !== undefined) toast.success("Playing audio", { id: toastId, duration: 2000 });
        return true;
      } catch {
        if (toastId !== undefined) toast.dismiss(toastId);
        return false;
      } finally {
        setIsPreparing(false);
      }
    },
    [shareToken, play],
  );

  const cancel = useCallback(() => {
    abortRef.current = true;
  }, []);

  return { start, cancel, isPreparing };
}

/**
 * Whether read-aloud audio already exists for an entry (visitors only: they
 * can play what was made, never make new). Signed-in readers don't ask.
 */
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
