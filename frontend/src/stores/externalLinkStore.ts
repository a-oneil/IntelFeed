import { create } from "zustand";
import type { ExternalLinkInfo } from "@/utils/externalLinks";

interface ExternalLinkState {
  /** The link currently held for confirmation, if any. Never persisted. */
  pending: ExternalLinkInfo | null;
  /**
   * Hosts trusted for this page load only. Used when there is no account to
   * save to (shared pages), so "don't ask again" still works within a visit.
   */
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
  trustForSession: (host) =>
    set((s) =>
      s.sessionTrustedHosts.includes(host)
        ? s
        : { sessionTrustedHosts: [...s.sessionTrustedHosts, host] },
    ),
}));
