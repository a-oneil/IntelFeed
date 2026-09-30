import { create } from "zustand";
import { useAuthStore } from "@/stores/authStore";
import { MAX_TRUSTED_HOSTS, normalizeHost, type ExternalLinkInfo } from "@/utils/externalLinks";
import { readSessionTrust, sessionTrustKey, writeSessionTrust } from "@/utils/sessionTrust";

const key = () => sessionTrustKey(useAuthStore.getState().user?.id);

/** Session trust survives same-tab navigation, without crossing accounts. */
export function readSessionTrustedHosts(): string[] {
  return readSessionTrust(key());
}

interface ExternalLinkState {
  /** The link currently held for confirmation, if any. Never persisted. */
  pending: ExternalLinkInfo | null;
  /** Hosts trusted for this tab, scoped to the current account or public pages. */
  sessionTrustedHosts: string[];
  hold: (info: ExternalLinkInfo) => void;
  release: () => void;
  trustForSession: (host: string) => void;
}

export const useExternalLinkStore = create<ExternalLinkState>((set) => ({
  pending: null,
  sessionTrustedHosts: [],
  hold: (info) => set({ pending: info }),
  release: () => set({ pending: null }),
  trustForSession: (host) => {
    const next = [...new Set([...readSessionTrustedHosts(), normalizeHost(host)])].slice(-MAX_TRUSTED_HOSTS);
    writeSessionTrust(key(), next);
    set({ sessionTrustedHosts: next });
  },
}));
