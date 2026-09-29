import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";

export interface BuildStamp {
  version: string;
  git_sha: string | null;
  built_at: string | null;
}

/**
 * The build the API is running, from `GET /api/version`.
 *
 * That endpoint touches no database, Redis or Meilisearch, which is what makes
 * polling it reasonable. Refetches on window focus — coming back to a tab you
 * left open across a deploy is the moment this matters — against the app-wide
 * default of `false`.
 */
export function useBuildVersion(enabled = true) {
  return useQuery({
    queryKey: ["build-version"],
    queryFn: async () => (await api.get<BuildStamp>("/version")).data,
    enabled,
    staleTime: 60_000,
    refetchInterval: 10 * 60_000,
    refetchOnWindowFocus: true,
    // A missing version endpoint must never surface as an error toast; the
    // footer simply has nothing to compare against.
    retry: false,
  });
}

/**
 * True when the browser is holding a bundle older than the one the server is
 * serving — i.e. a reload would change what you are looking at.
 *
 * Only ever true for a stamped image build. Under the dev server the stamp is
 * frozen at start-up while HMR keeps the code current, so every commit would
 * otherwise light this up while the bundle is in fact fine.
 */
export function useStaleBundle(): { stale: boolean; serverVersion?: string } {
  const meaningful = __STAMP_SOURCE__ === "env" && Boolean(__GIT_SHA__);
  const { data } = useBuildVersion(meaningful);

  if (!meaningful || !data?.git_sha) return { stale: false };
  return {
    stale: data.git_sha !== __GIT_SHA__,
    serverVersion: data.version,
  };
}
