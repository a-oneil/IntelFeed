import { QueryClient, QueryCache, MutationCache } from "@tanstack/react-query";
import { toast } from "sonner";
import { apiErrorInfo, hasErrorEnvelope, isTimeout } from "@/api/errors";
import { selectIsAdmin, useAuthStore } from "@/stores/authStore";

/** The toast text: the same reading of the error envelope the inline errors use. */
function extractErrorMessage(error: unknown): string {
  if (hasErrorEnvelope(error)) return apiErrorInfo(error).message;
  if (error instanceof Error) return error.message;
  return "An unexpected error occurred";
}

function isRateLimited(error: unknown): boolean {
  return (
    !!error &&
    typeof error === "object" &&
    "response" in error &&
    (error as { response?: { status?: number } }).response?.status === 429
  );
}

/** The toast id every timeout shares, so a stalled page shows one message, not one per panel. */
export const SLOW_SERVER_TOAST_ID = "slow-server";

/** What an admin sees under the timeout message: which call, and how long the browser waited. */
export function timeoutDetail(error: unknown): string | undefined {
  const config = (error as { config?: { method?: string; url?: string; timeout?: number } })?.config;
  if (!config?.url) return undefined;
  const method = (config.method ?? "get").toUpperCase();
  const waited = config.timeout ? ` after ${Math.round(config.timeout / 1000)}s` : "";
  return `${method} ${config.url} gave up${waited}.`;
}

/**
 * A timeout is the server being slow, not the app being broken, and the page
 * usually fills in on its own once the server catches up. Say that once, in
 * plain words, for everyone; an admin also gets the route and the wait, which
 * is what they need to go and look at the server.
 */
export function toastTimeout(error: unknown, kind: "query" | "mutation"): void {
  const message =
    kind === "mutation"
      ? "The server is busy and did not finish that action in time. Try again in a moment."
      : "The server is busy, so some panels are loading slowly. They will fill in when it catches up.";
  const description = selectIsAdmin(useAuthStore.getState()) ? timeoutDetail(error) : undefined;
  toast.error(message, { id: SLOW_SERVER_TOAST_ID, description, duration: 8000 });
}

/** One page fans out into many requests, so a 429 is one toast, not one per query. */
function toastError(error: unknown, kind: "query" | "mutation" = "query"): void {
  if (isRateLimited(error)) {
    toast.error("Too many requests. Wait a minute and try again.", { id: "rate-limited" });
    return;
  }
  if (isTimeout(error)) {
    toastTimeout(error, kind);
    return;
  }
  toast.error(extractErrorMessage(error));
}

/** Queries that report state on a timer opt out of the global toast via `meta`. */
function silenced(meta: Record<string, unknown> | undefined): boolean {
  return meta?.silenceToast === true;
}

function shouldShowToast(error: unknown): boolean {
  // A visitor's refused write (api/client.ts) has already said so once.
  if (error instanceof Error && error.name === "ReadOnlyViewError") return false;
  if (error && typeof error === "object" && "response" in error) {
    const axiosErr = error as { response?: { data?: { error?: { code?: string } }; status?: number } };
    const code = axiosErr.response?.data?.error?.code;
    if (code === "validation_error") return false;
    if (axiosErr.response?.status === 401) return false;
  }
  return true;
}

export const queryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (error, query) => {
      if (!silenced(query.meta) && shouldShowToast(error)) {
        toastError(error);
      }
    },
  }),
  mutationCache: new MutationCache({
    onError: (error) => {
      if (shouldShowToast(error)) {
        toastError(error, "mutation");
      }
    },
  }),
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        if (error && typeof error === "object" && "response" in error) {
          const status = (error as { response?: { status?: number } }).response?.status;
          if (status === 429 || status === 401 || status === 403) return false;
        }
        return failureCount < 1;
      },
      // A timed-out request usually means a stalled server, not a lost one; a
      // few seconds' pause before the one retry lets it clear, where the
      // default one-second wait mostly re-queued into the same stall.
      retryDelay: (attempt, error) => (isTimeout(error) ? 3000 : Math.min(1000 * 2 ** attempt, 30000)),
      staleTime: 30_000,
      refetchOnWindowFocus: false,
    },
  },
});
