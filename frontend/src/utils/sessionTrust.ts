import { EXTERNAL_LINK_SESSION_TRUST_PREFIX, parseTrustedHosts } from "@/utils/externalLinks";

/**
 * Per-tab storage for hosts trusted "for this tab" in the external-link dialog.
 *
 * A leaf module (no store imports) so the logout cleanup can clear it: the
 * cleanup is imported by authStore, and the link store imports authStore.
 *
 * sessionStorage is the source of truth. The in-memory copy exists only because
 * restrictive private modes can reject writes (setItem throws) while reads
 * return null; it is dropped together with the storage keys, so clearing one
 * never leaves the other to resurrect trust.
 */
const volatile = new Map<string, string[]>();

export function sessionTrustKey(accountId: string | undefined): string {
  return `${EXTERNAL_LINK_SESSION_TRUST_PREFIX}${accountId ?? "public"}`;
}

export function readSessionTrust(key: string): string[] {
  try {
    const raw = sessionStorage.getItem(key);
    if (raw) return parseTrustedHosts(JSON.parse(raw));
  } catch {
    // Storage unavailable or unparseable: fall through to the in-memory copy.
  }
  return volatile.get(key) ?? [];
}

export function writeSessionTrust(key: string, hosts: string[]): void {
  volatile.set(key, hosts);
  try {
    sessionStorage.setItem(key, JSON.stringify(hosts));
  } catch {
    // The in-memory copy still lasts for this page load.
  }
}

/** Forget every session-trusted host, in storage and in memory (logout). */
export function clearAllSessionTrust(): void {
  volatile.clear();
  try {
    for (let i = sessionStorage.length - 1; i >= 0; i--) {
      const key = sessionStorage.key(i);
      if (key?.startsWith(EXTERNAL_LINK_SESSION_TRUST_PREFIX)) sessionStorage.removeItem(key);
    }
  } catch {
    // sessionStorage unavailable — nothing persisted there anyway
  }
}
