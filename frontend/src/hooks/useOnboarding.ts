import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import type { OnboardingStatus, User } from "@/api/types";

/** Keys the wizard owns inside `user.settings`. */
export interface OnboardingProgress {
  /** The step the user was last on. Closing the modal saves this; it is where they resume. */
  onboarding_step?: string | null;
  /** Only ever set by finishing. Closing must never set it — that was the old bug. */
  onboarding_completed?: boolean;
  /** A new run id remounts the wizard when a deferred tour is replayed. */
  onboarding_run_id?: string;
}

/**
 * Instance readiness, for the setup track's first and last steps.
 *
 * `refetchInterval` is opt-in because only the verify step wants to watch a
 * poll land; everywhere else this is a one-shot read.
 */
export function useOnboardingStatus(options?: { enabled?: boolean; pollMs?: number }) {
  return useQuery({
    queryKey: ["onboarding", "status"],
    queryFn: async () => {
      const res = await api.get<OnboardingStatus>("/onboarding/status");
      return res.data;
    },
    enabled: options?.enabled ?? true,
    refetchInterval: options?.pollMs ?? false,
    // Readiness changes out-of-band (a seeder running in a shell, a feed
    // polling), so never serve a cached answer to a step whose whole job is to
    // report the current state.
    staleTime: 0,
    gcTime: 0,
  });
}

/**
 * Persist onboarding progress.
 *
 * Uses `PATCH /auth/me/settings`, which shallow-merges top-level keys, rather
 * than `PUT /auth/me`, which replaces the whole blob — the triage view, table
 * layouts and theme preference all auto-save into the same object, and a PUT
 * from a stale snapshot silently reverts whichever of them wrote last.
 */
export function useSaveOnboardingProgress() {
  const setUser = useAuthStore((s) => s.setUser);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (settings: OnboardingProgress) => {
      const res = await api.patch<User>("/auth/me/settings", { settings });
      return res.data;
    },
    onSuccess: (user) => {
      setUser(user);
      queryClient.invalidateQueries({ queryKey: ["onboarding"] });
    },
  });
}
