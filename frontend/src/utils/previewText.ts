/**
 * previewText — pure helpers for entry-list preview snippets. Bulletin-style
 * sources (e.g. AusCERT/ESB) wrap sections in ASCII banner lines ("======…",
 * "------…") that are meaningless in a short preview; these helpers strip that
 * noise from PREVIEW text only — the full article body renders untouched.
 */

/** A line that is just a repeated punctuation banner: 4+ repeats of the same
 * character (optionally space-separated), e.g. "========", "- - - -", "####". */
const BANNER_LINE = /^\s*([=\-#*_~+])(?:\s*\1){3,}\s*$/;

/** Inline banner runs that survive HTML flattening — line structure is often
 * lost when summaries pass through textContent (e.g. `<br>`-separated text). */
const BANNER_RUN = /(^|\s)([=\-#*_~+])\2{3,}(?=\s|$)/g;

/** Remove banner lines/runs from plain text, keeping remaining line structure. */
export function stripBannerLines(text: string): string {
  return text
    .split(/\r?\n/)
    .filter((line) => !BANNER_LINE.test(line))
    .join("\n")
    .replace(BANNER_RUN, "$1");
}

/** Derive a preview snippet: banner noise stripped, whitespace collapsed,
 * sliced to maxLen. */
export function previewSnippet(text: string, maxLen: number): string {
  return stripBannerLines(text).replace(/\s+/g, " ").trim().slice(0, maxLen);
}
