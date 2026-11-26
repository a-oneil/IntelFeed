// Right-click lookup: turn selected text into an IntelFeed search.

/** Undo the usual defanging: hxxp, [.] (.) {.}, [:], [at]. */
export function refang(text) {
  return String(text || "")
    .trim()
    .replace(/\bhxxp(s?)/gi, "http$1")
    .replace(/\bfxp\b/gi, "ftp")
    .replace(/\s*[[({]\s*(?:\.|dot)\s*[\])}]\s*/gi, ".")
    .replace(/\s*\[\s*:\s*\]\s*/g, ":")
    .replace(/\s*[[({]\s*(?:@|at)\s*[\])}]\s*/gi, "@");
}

/** The IntelFeed page to open for a selection, or null when there's nothing to look up. */
export function lookupUrl(server, selection) {
  const query = refang(selection).replace(/\s+/g, " ").slice(0, 500);
  if (!query) return null;
  return `${server}/search?q=${encodeURIComponent(query)}`;
}
