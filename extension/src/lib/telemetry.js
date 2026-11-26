// Saving a page to a telemetry source's notes: remembering which source the
// user picked for which part of which site. No browser APIs.

export const MAX_PICKS = 200;

/** host + the first two path segments: the part of a docs site one product lives under. */
export function sitePrefix(url) {
  try {
    const u = new URL(url);
    return [u.hostname.toLowerCase(), ...u.pathname.split("/").filter(Boolean).slice(0, 2)].join("/");
  } catch {
    return "";
  }
}

/** Remember a pick, newest last, keeping MAX_PICKS. */
export function rememberPick(picks, url, name) {
  const key = sitePrefix(url);
  if (!key || !name) return picks;
  const next = { ...picks };
  delete next[key];
  next[key] = name;
  const keys = Object.keys(next);
  for (const k of keys.slice(0, Math.max(0, keys.length - MAX_PICKS))) delete next[k];
  return next;
}

/** The source to pre-fill: the user's own last pick here, else the server's best suggestion. */
export function preferredSource(picks, url, suggestions) {
  return (picks || {})[sitePrefix(url)] || suggestions?.[0]?.name || "";
}
