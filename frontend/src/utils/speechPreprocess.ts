/**
 * Cleans article text for the Web Speech API. Without this, security articles
 * are read terribly: URLs are spelled character by character, CVE IDs are
 * mispronounced, IP addresses run together, and code blocks are read literally.
 */

const URL_REGEX = /\b(?:https?:\/\/|www\.)\S+/gi;
const EMAIL_REGEX = /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi;
const CVE_REGEX = /\bCVE[-\s_]?(\d{4})[-\s_]?(\d+)\b/gi;
const IPV4_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const HASH_REGEX = /\b[a-f0-9]{32,}\b/gi;
const TLD_LIST =
  "com|net|org|io|gov|edu|co|us|uk|ru|cn|de|fr|jp|info|biz|xyz|app|dev|tech|cloud|systems|security|tv|mil|me|ai|nl|au|ca|in|it|es|pl|br|kr|tw|hk|sg|nz|za";
const HOSTNAME_REGEX = new RegExp(
  `\\b(?:[a-z0-9][a-z0-9-]*\\.)+(?:${TLD_LIST})\\b`,
  "gi",
);
const FILE_PATH_REGEX = /\b[a-z]:\\[\w\\.\- ]+|\/(?:[\w.\- ]+\/)+[\w.\- ]+/gi;

/** Strip noise from a paragraph before sending to the synthesizer. */
export function cleanForSpeech(text: string): string {
  return text
    .replace(URL_REGEX, " link ")
    .replace(EMAIL_REGEX, " email address ")
    .replace(HASH_REGEX, " hash ")
    .replace(CVE_REGEX, "C V E $1 $2")
    .replace(IPV4_REGEX, (m) => m.split(".").join(" dot "))
    .replace(HOSTNAME_REGEX, (m) => m.split(".").join(" dot "))
    .replace(FILE_PATH_REGEX, " file path ")
    .replace(/\s+/g, " ")
    .trim();
}

const BLOCK_SELECTOR = "p, h1, h2, h3, h4, h5, h6, li, blockquote, td, pre";

/**
 * Pull readable paragraphs out of an article container for read-aloud.
 * Replaces &lt;pre&gt; blocks with a stub so the synthesizer doesn't enumerate
 * every character of source code.
 */
export function extractSpeechParagraphs(
  container: Element | null,
  title?: string | null,
): string[] {
  const paragraphs: string[] = [];
  const pushed = new Set<Element>();

  if (title?.trim()) paragraphs.push(cleanForSpeech(title));

  if (!container) return paragraphs;

  const blocks = container.querySelectorAll(BLOCK_SELECTOR);
  blocks.forEach((block) => {
    // Skip blocks that are nested inside an already-emitted block (e.g. a <p>
    // inside a <li>) so content isn't read twice.
    for (const ancestor of pushed) {
      if (ancestor.contains(block)) return;
    }

    const tag = block.tagName.toLowerCase();
    if (tag === "pre") {
      paragraphs.push("Code block.");
      pushed.add(block);
      return;
    }

    const raw = (block.textContent || "").trim();
    if (!raw) return;

    const cleaned = cleanForSpeech(raw);
    if (!cleaned) return;

    paragraphs.push(cleaned);
    pushed.add(block);
  });

  // Fallback for content without recognizable blocks.
  if (paragraphs.length === (title?.trim() ? 1 : 0)) {
    const text = (container.textContent || "").trim();
    if (text) {
      text.split(/\n\s*\n/).forEach((chunk) => {
        const cleaned = cleanForSpeech(chunk);
        if (cleaned) paragraphs.push(cleaned);
      });
    }
  }

  return paragraphs;
}
