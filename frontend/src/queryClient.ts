import { QueryClient, QueryCache, MutationCache } from "@tanstack/react-query";
import { toast } from "sonner";

function extractErrorMessage(error: unknown): string {
  if (error && typeof error === "object" && "response" in error) {
    const axiosErr = error as { response?: { data?: { error?: { message?: string } }; status?: number } };
    const apiError = axiosErr.response?.data?.error;
    if (apiError?.message) return apiError.message;
    if (axiosErr.response?.status === 429) return "Rate limited. Please try again shortly.";
  }
  if (error instanceof Error) return error.message;
  return "An unexpected error occurred";
}

/** Queries that report state on a timer opt out of the global toast via `meta`. */
function silenced(meta: Record<string, unknown> | undefined): boolean {
  return meta?.silenceToast === true;
}

function shouldShowToast(error: unknown): boolean {
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
        toast.error(extractErrorMessage(error));
      }
    },
  }),
  mutationCache: new MutationCache({
    onError: (error) => {
      if (shouldShowToast(error)) {
        toast.error(extractErrorMessage(error));
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
      staleTime: 30_000,
      refetchOnWindowFocus: false,
    },
  },
});
