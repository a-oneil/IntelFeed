// The hover card's Watch button. No browser APIs.

// The types the watchlist accepts (WATCHABLE_ENTITY_TYPES in backend/app/api/watchlist.py).
export const WATCHABLE = new Set([
  "threat_actor", "malware", "cve", "cwe", "tool", "vendor", "product", "country", "sector", "observable",
]);

/** {watchable, watched} for an entity whose watchlist row has `mode` (watch, mute, stack, or none). The watchlist keeps one mode per entity, so watching a muted entity or one in My Stack would replace that mode: those get no button. */
export function watchState(type, mode) {
  if (!WATCHABLE.has(type)) return { watchable: false, watched: false };
  return { watchable: !mode || mode === "watch", watched: mode === "watch" };
}
