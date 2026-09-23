/**
 * Note content normalization.
 *
 * Notes are stored inconsistently: pure markdown, real rendered HTML, or (from
 * the AI copilot) markdown blocks wrapped in <p>…</p>. These helpers decide how
 * to render/edit a given blob and recover markdown source when it's just been
 * wrapped in block tags.
 */

// "Rich" HTML = genuinely rendered markup, detected by *block-level* tags only.
// Inline tags (<a>, <code>, <strong>, <em>, <span>, <mark>…) are deliberately
// excluded: the AI copilot emits otherwise-markdown text that mixes a few real
// inline tags into <p>-wrapped markdown blocks. Matching on those inline tags
// would misroute the whole note to the HTML renderer, showing its block markdown
// (#, **, |, ---) as raw text. toMarkdownSource() converts the inline tags back
// to markdown, so the markdown path renders them correctly.
const RICH_HTML_RE =
  /<(?:h[1-6]|ul|ol|li|table|thead|tbody|tr|td|th|pre|blockquote|img|hr)\b[^>]*>/i;

/** True when the content is real rendered HTML (not <p>-wrapped markdown). */
export function isRichHtml(content: string): boolean {
  return RICH_HTML_RE.test(content);
}

/** Turn <p>/<br>-wrapped text (with any inline HTML) back into markdown source. */
export function toMarkdownSource(content: string): string {
  return content
    // Inline HTML the copilot sometimes emits amid otherwise-markdown text →
    // markdown, so react-markdown (which doesn't parse raw HTML) renders it.
    .replace(/<a\b[^>]*\bhref=["']([^"']*)["'][^>]*>([\s\S]*?)<\/a>/gi, "[$2]($1)")
    .replace(/<code\b[^>]*>([\s\S]*?)<\/code>/gi, "`$1`")
    .replace(/<(?:strong|b)\b[^>]*>([\s\S]*?)<\/(?:strong|b)>/gi, "**$1**")
    .replace(/<(?:em|i)\b[^>]*>([\s\S]*?)<\/(?:em|i)>/gi, "*$1*")
    // <p>/<br> block wrappers → blank-line-separated markdown.
    .replace(/<\/p>\s*<p[^>]*>/gi, "\n\n")
    .replace(/<p[^>]*>/gi, "")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}
