import { useTriageViewStore } from "@/stores/triageViewStore";
import { clearAllSessionTrust } from "@/utils/sessionTrust";

/**
 * Wipe per-account browser state on logout so the next person to sign in on
 * this browser doesn't inherit (or overwrite) the previous account's data.
 *
 * Deliberately NOT cleared: theme selection (documented as surviving logout in
 * useThemes), player volume/rate (device preference), and the auth store
 * itself (logout() owns that).
 */
const USER_SCOPED_STORAGE_KEYS = [
  "intelfeed-ui",
  "intelfeed-intel",
  "intelfeed-triage-view",
  // Legacy client-side watchlist fallback; no longer written, still purged.
  "intelfeed-watchlists",
  "intelfeed-recent-pages",
  "intelfeed-active-dashboard",
  "intelfeed:readAloud:progress",
  "intelfeed:pulse-expanded",
];

const USER_SCOPED_SESSION_KEYS = ["intelfeed-bench-seed", "intelfeed-bench-return"];

export function clearUserScopedState(): void {
  for (const key of USER_SCOPED_STORAGE_KEYS) {
    try {
      localStorage.removeItem(key);
    } catch {
      // localStorage unavailable (private mode) — nothing persisted anyway
    }
  }
  for (const key of USER_SCOPED_SESSION_KEYS) {
    try {
      sessionStorage.removeItem(key);
    } catch {
      // sessionStorage unavailable — nothing persisted anyway
    }
  }
  // Hosts trusted "for this tab" in the external-link dialog belong to the
  // session that granted them; don't hand them to the next person in this tab.
  clearAllSessionTrust();
  // In-memory reset for the store that mirrors server-side user data; the
  // others are refreshed by the full page load the logout buttons trigger.
  useTriageViewStore.setState({ view: null, viewOwnerId: null });
}
