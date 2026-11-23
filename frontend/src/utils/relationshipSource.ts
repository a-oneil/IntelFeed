/**
 * Plain-English source, status and reason for one relationship row — what
 * the Relationships tab's list and evidence panel say about where a
 * relationship came from and how sure we are of it.
 */
import type { EntitySearchResult } from "@/api/types";
import type { RelRow } from "./relationshipBrowser";

export type SourceTone = "mitre" | "feed" | "ai" | "articles" | "analyst";

/** One way a relationship is known. `key` is what the Source filter matches. */
export interface SourcePart {
  key: string;
  label: string;
  tone: SourceTone;
}

const MITRE: SourcePart = { key: "mitre", label: "MITRE ATT&CK", tone: "mitre" };
const ANALYST: SourcePart = { key: "analyst", label: "Analyst", tone: "analyst" };
const AI_REVIEWED: SourcePart = { key: "ai_reviewed", label: "AI-reviewed articles", tone: "ai" };
const AI_EXTRACTED: SourcePart = { key: "ai_extracted", label: "AI, from an article", tone: "ai" };
const ARTICLES: SourcePart = { key: "articles", label: "Articles, not reviewed", tone: "articles" };

const REVIEWED = new Set(["corroborated", "kept"]);

const feed = (label: string): SourcePart => ({ key: `feed:${label}`, label, tone: "feed" });

/** A description short enough to be a source's name rather than a note. */
const asName = (s: string | null | undefined) => (s && s.trim().length <= 40 ? s.trim() : null);

/**
 * Every source behind a row, primary first. `via` is the enrichment sources
 * that also claim the pair (labels, from the claims endpoint).
 */
export function sourcesOf(row: RelRow, via: string[] = []): SourcePart[] {
  const item = row.item;
  let primary: SourcePart;
  if (!item.relationship_id) {
    // Country profiles' targeting/origin rows come from article tagging.
    primary = ARTICLES;
  } else {
    switch (item.relationship_source) {
      case "external_feed":
        primary = MITRE;
        break;
      case "enrichment":
        primary = feed(via[0] ?? asName(item.relationship_description) ?? "Enrichment feed");
        break;
      case "analyst_confirmed":
      case "analyst_created":
        primary = ANALYST;
        break;
      default:
        primary = REVIEWED.has(item.relationship_adjudication ?? "")
          ? AI_REVIEWED
          : item.relationship_source === "auto_extracted"
            ? AI_EXTRACTED
            : ARTICLES;
    }
  }
  const out = [primary];
  for (const v of via) if (!out.some((p) => p.label === v)) out.push(feed(v));
  return out;
}

/** "MITRE ATT&CK + ransomware.live" */
export function sourceLabel(parts: SourcePart[]): string {
  return parts.map((p) => p.label).join(" + ");
}

/** How sure we are, in a sentence. */
export function statusOf(item: EntitySearchResult): string | null {
  if (!item.relationship_id) return null;
  switch (item.relationship_adjudication) {
    case "corroborated":
      return "Confirmed by articles from two or more sources";
    case "kept":
      return "Confirmed by a reviewed article";
    case "disputed":
      return "Disputed: one article supports it, another doesn't";
  }
  if (item.relationship_source === "analyst_confirmed" || item.relationship_source === "analyst_created") {
    return "Confirmed by an analyst";
  }
  const fromSource = item.relationship_source === "external_feed" || item.relationship_source === "enrichment";
  switch (item.relationship_confidence) {
    case "confirmed":
      return "Confirmed";
    case "probable":
      return fromSource
        ? "Reported by the source, not checked against articles"
        : "Stated in an article, not confirmed by a second source yet";
    default:
      return "Not confirmed yet";
  }
}

/**
 * Why the relationship is listed: the reviewer's or source's own words when
 * there are any (`quote`), and a sentence naming who says so (`text`).
 */
export function reasonOf(row: RelRow, parts: SourcePart[]): { quote: string | null; text: string } {
  const item = row.item;
  const desc = item.relationship_description?.trim() || null;
  // A description that is only the source's name is not a reason.
  const quote = desc && !parts.some((p) => p.label === desc) ? desc : null;
  const [primary, ...others] = parts;
  const also = others.length ? ` ${others.map((p) => p.label).join(" and ")} ${others.length === 1 ? "lists" : "list"} it too.` : "";
  let text: string;
  switch (primary.tone) {
    case "mitre":
    case "feed":
      text = `${primary.label} lists this.${also}`;
      break;
    case "analyst":
      text = `An analyst added or confirmed this.${also}`;
      break;
    case "ai":
      text =
        primary.key === "ai_extracted"
          ? `The AI read it in an article. No reviewer has checked it yet.${also}`
          : `The AI reviewer found it stated in the articles.${also}`;
      break;
    default:
      text = item.relationship_id
        ? `Linked from articles that mention both. No reviewer has checked it yet.${also}`
        : "From articles tagged with both.";
  }
  return { quote, text };
}
