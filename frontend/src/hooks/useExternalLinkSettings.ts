import { useCallback } from "react";
import { useMutation } from "@tanstack/react-query";
import api from "@/api/client";
import type { User } from "@/api/types";
import { useAuthStore } from "@/stores/authStore";
import {
  EXTERNAL_LINK_MODE_KEY,
  EXTERNAL_LINK_TRUSTED_KEY,
  MAX_TRUSTED_HOSTS,
  normalizeHost,
  parseMode,
  parseTrustedHosts,
  type ExternalLinkMode,
} from "@/utils/externalLinks";

/** Read the interstitial preferences off a user's settings blob. */
export function readExternalLinkSettings(user: User | null | undefined): {
  mode: ExternalLinkMode;
  trustedHosts: string[];
} {
  const settings = (user?.settings ?? {}) as Record<string, unknown>;
  return {
    mode: parseMode(settings[EXTERNAL_LINK_MODE_KEY]),
    trustedHosts: parseTrustedHosts(settings[EXTERNAL_LINK_TRUSTED_KEY]),
  };
}

/**
 * Preferences for the external-link interstitial. They live on the account
 * (`user.settings`) rather than in localStorage so "don't ask again for X"
 * follows you between devices — and so a shared browser doesn't leak one
 * analyst's allowlist to the next.
 *
 * Writes use the shallow-merge PATCH, so saving one key can't overwrite
 * another autosaver's stale snapshot of the rest of the blob.
 */
export function useExternalLinkSettings() {
  const user = useAuthStore((s) => s.user);
  const setUser = useAuthStore((s) => s.setUser);
  const { mode, trustedHosts } = readExternalLinkSettings(user);

  const save = useMutation({
    mutationFn: async (patch: Record<string, unknown>) => {
      const res = await api.patch<User>("/auth/me/settings", { settings: patch });
      return res.data;
    },
    onSuccess: (data) => setUser(data),
  });

  const setMode = useCallback(
    (next: ExternalLinkMode) => save.mutateAsync({ [EXTERNAL_LINK_MODE_KEY]: next }),
    [save],
  );

  const trustHost = useCallback(
    (host: string) => {
      // Re-read at call time: the modal can outlive the render that built this callback.
      const current = readExternalLinkSettings(useAuthStore.getState().user).trustedHosts;
      const h = normalizeHost(host);
      if (!h || current.includes(h)) return Promise.resolve(undefined);
      const next = [...current, h].slice(-MAX_TRUSTED_HOSTS);
      return save.mutateAsync({ [EXTERNAL_LINK_TRUSTED_KEY]: next });
    },
    [save],
  );

  const untrustHost = useCallback(
    (host: string) => {
      const current = readExternalLinkSettings(useAuthStore.getState().user).trustedHosts;
      const h = normalizeHost(host);
      return save.mutateAsync({ [EXTERNAL_LINK_TRUSTED_KEY]: current.filter((t) => t !== h) });
    },
    [save],
  );

  return {
    mode,
    trustedHosts,
    canSave: user !== null,
    saving: save.isPending,
    setMode,
    trustHost,
    untrustHost,
  };
}
