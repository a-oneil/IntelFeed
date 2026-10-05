import { isValidElement, type ReactNode } from "react";

/**
 * GitHub-compatible heading anchors for the in-app docs reader.
 *
 * The docs are written to be read on GitHub as well as here, so a link such as
 * `[Logging & Audit](#logging--audit)` has to land in both places. GitHub's rule
 * is: lowercase, drop everything except letters, digits, underscores, hyphens
 * and spaces, then turn each space into one hyphen — so "Logging & Audit" is
 * `logging--audit`, not `logging-audit` — and a repeated heading gets `-1`, `-2`.
 */
export function slugify(text: string): string {
  return text
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}_\s-]/gu, "")
    .replace(/\s/g, "-");
}

/** The visible text of rendered markdown children: inline code, links and emphasis included. */
export function nodeText(node: ReactNode): string {
  if (node === null || node === undefined || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(nodeText).join("");
  if (isValidElement<{ children?: ReactNode }>(node)) return nodeText(node.props.children);
  return "";
}

/** What GitHub slugs for a heading written as markdown: the text, minus its inline markup. */
function plainHeadingText(source: string): string {
  return source
    .replace(/\s+#+\s*$/, "") // closing hashes of an ATX heading
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1") // a link or image keeps its text
    .replace(/[`*]/g, ""); // code spans and emphasis keep their text
}

/**
 * Anchor ids for every heading in a markdown document, keyed by the 1-based line
 * the heading starts on.
 *
 * Done from the source rather than per heading as it renders because a repeat
 * needs to know what came before it, and a renderer called one heading at a time
 * (twice, under StrictMode) cannot count. Fenced code is skipped so a `# comment`
 * inside a bash block is not mistaken for a heading.
 */
export function headingIdsByLine(markdown: string): Map<number, string> {
  const ids = new Map<number, string>();
  const seen = new Map<string, number>();
  let fence: string | null = null;

  markdown.split("\n").forEach((line, index) => {
    const marker = /^\s*(```|~~~)/.exec(line)?.[1];
    if (marker) {
      if (fence === null) fence = marker;
      else if (fence === marker) fence = null;
      return;
    }
    if (fence !== null) return;

    const heading = /^#{1,6}\s+(.+?)\s*$/.exec(line);
    if (!heading) return;

    const base = slugify(plainHeadingText(heading[1]));
    const count = seen.get(base) ?? 0;
    seen.set(base, count + 1);
    ids.set(index + 1, count === 0 ? base : `${base}-${count}`);
  });

  return ids;
}
