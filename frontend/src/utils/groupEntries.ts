import type { Entry } from "@/api/types";

const CVE_PATTERN = /CVE-\d{4}-\d{4,}/i;

export interface SingleItem {
  type: "single";
  entry: Entry;
  /** Original index in the flat entries array */
  flatIndex: number;
}

export interface GroupItem {
  type: "group";
  entries: Entry[];
  /** Product/vendor label extracted from titles */
  label: string;
  /** Feed title shared by all entries in the group */
  feedTitle: string;
  feedId: string;
  feedType: string | null;
  /** Original index of the first entry in the flat array */
  flatIndex: number;
  /** CVE IDs found in the group */
  cveIds: string[];
}

export type DisplayItem = SingleItem | GroupItem;

/**
 * Strip the CVE ID and leading punctuation from a title.
 */
function stripCveId(title: string): string {
  return title
    .replace(CVE_PATTERN, "")
    .replace(/^[\s\-–—:]+/, "")
    .trim();
}

/**
 * Extract a product/vendor name from a CVE title by finding the longest
 * sequence of capitalized words (proper nouns = product/vendor names).
 * e.g. "A security flaw in Tiandy Easy7 Integrated Management Platform 7.17.0"
 *   → "Tiandy Easy7 Integrated Management Platform"
 */
function extractProductSignature(title: string): string {
  const desc = stripCveId(title);
  // Match sequences of capitalized words (allowing digits, e.g. Easy7, V8)
  const matches = desc.match(/[A-Z][a-zA-Z0-9]*(?:\s+[A-Z][a-zA-Z0-9]*)*/g);
  if (matches && matches.length > 0) {
    // Return the longest capitalized sequence
    return matches.sort((a, b) => b.length - a.length)[0];
  }
  return "";
}

/**
 * Find the best product label for a group of CVE titles.
 * Uses the longest common capitalized sequence across all titles.
 */
function extractGroupLabel(titles: string[]): string {
  const signatures = titles.map(extractProductSignature);

  // Find the signature that appears (case-insensitive) in all titles
  // Try the longest signatures first
  const candidates = [...new Set(signatures)].sort((a, b) => b.length - a.length);

  for (const candidate of candidates) {
    if (!candidate) continue;
    const lower = candidate.toLowerCase();
    const allMatch = titles.every((t) => t.toLowerCase().includes(lower));
    if (allMatch) return candidate;
  }

  // Fallback: use the most common signature
  if (signatures[0]) return signatures[0];
  return "";
}

/**
 * Groups consecutive CVE entries from the same feed into collapsed groups.
 * Only groups 2+ consecutive CVE entries; singles pass through unchanged.
 */
export function groupConsecutiveEntries(
  entries: Entry[],
  minGroupSize = 2,
): DisplayItem[] {
  const result: DisplayItem[] = [];
  let i = 0;

  while (i < entries.length) {
    const entry = entries[i];
    const cveMatch = entry.title.match(CVE_PATTERN);

    if (!cveMatch) {
      result.push({ type: "single", entry, flatIndex: i });
      i++;
      continue;
    }

    // Start of a potential CVE run — collect consecutive same-feed CVE entries
    // that share a product signature (capitalized proper noun sequence)
    const sig = extractProductSignature(entry.title);
    const runStart = i;
    const run: Entry[] = [entry];
    const cveIds: string[] = [cveMatch[0]];

    let j = i + 1;
    while (j < entries.length) {
      const next = entries[j];
      const nextCve = next.title.match(CVE_PATTERN);
      if (!nextCve || next.feed_id !== entry.feed_id) break;

      // Check product similarity via capitalized noun signatures
      const nextSig = extractProductSignature(next.title);
      if (sig && nextSig && sig !== nextSig) break;

      run.push(next);
      cveIds.push(nextCve[0]);
      j++;
    }

    if (run.length >= minGroupSize) {
      const label = extractGroupLabel(run.map((e) => e.title));
      result.push({
        type: "group",
        entries: run,
        label: label || entry.feed_title || "Multiple CVEs",
        feedTitle: entry.feed_title || "",
        feedId: entry.feed_id,
        feedType: entry.feed_type ?? null,
        flatIndex: runStart,
        cveIds,
      });
    } else {
      for (const e of run) {
        result.push({ type: "single", entry: e, flatIndex: runStart + run.indexOf(e) });
      }
    }

    i = j;
  }

  return result;
}
