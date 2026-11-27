import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import type { EntitySearchResult } from "@/api/types";
import { useIntelStore } from "@/stores/intelStore";
import { useUIStore } from "@/stores/uiStore";
import { entityProfilePath } from "@/components/entityProfile/entityProfileConfig";
import { NO_SUGGESTIONS, type SuggestionSource } from "./types";
import { ALL_FIELDS, FIELD_HINTS, FIELD_VALUES } from "./queryFields";

/**
 * Helpers for entity search results.
 *
 * `/search` is the app's only search engine. This file does not run a search of its own; a separate one here (`useIntelSearch` against `/intelligence/search`, used by the workbench's mobile overlay) understood only `type:` filters, discarded every other field and never returned articles, so a phone got different answers from a laptop.
 *
 * What it holds: the display helpers and the routing table the results page uses, and the intelligence autocomplete dictionary (which completes from `queryFields.ts` like everything else).
 */

export const ENTITY_TYPE_LABELS: Record<string, string> = {
  threat_actor: "Threat Actors",
  malware: "Malware",
  cve: "CVEs",
  ttp: "TTPs",
  country: "Countries",
  sector: "Sectors",
  mitigation: "Mitigations",
  tool: "Tools",
  vendor: "Vendors",
  product: "Products",
  detection_rule: "Detection Rules",
  campaign: "Campaigns",
  intel_report: "Intel Reports",
  note: "Notes",
  entry: "Entries",
};

export function getSearchResultName(r: EntitySearchResult): string {
  // Catalog-keyed types lead with the id, the way the profile header does: "Use After Free" alone is ambiguous, "CWE-416 Use After Free" is not.
  if (r.cwe_id) return r.name && r.name !== r.cwe_id ? `${r.cwe_id} ${r.name}` : r.cwe_id;
  if (r.name) return r.name;
  if (r.cve_id) return r.cve_id;
  if (r.technique_id && r.technique_name && r.technique_name !== r.technique_id) return `${r.technique_id} - ${r.technique_name}`;
  if (r.technique_id) return r.technique_id;
  if (r.technique_name) return r.technique_name;
  if (r.value) return r.value;
  if (r.title) return r.title;
  return r.id;
}

export function getSearchResultSubtext(r: EntitySearchResult): string | null {
  if (r.type === "threat_actor") {
    const parts: string[] = [];
    if (r.country) parts.push(r.country);
    if (r.motivation) parts.push(r.motivation);
    return parts.length > 0 ? parts.join(" / ") : null;
  }
  if (r.type === "malware") return r.malware_type || null;
  if (r.type === "tool") return r.tool_type?.replace(/_/g, " ") || null;
  if (r.type === "cve") {
    if (r.severity && r.cvss_score != null) return `${r.severity.toUpperCase()} (${r.cvss_score})`;
    if (r.severity) return r.severity.toUpperCase();
    return null;
  }
  if (r.type === "ttp") return r.tactic || null;
  if (r.type === "vendor") return r.vendor_type?.replace(/_/g, " ") || null;
  if (r.type === "product") return r.vendor_name || r.product_type?.replace(/_/g, " ") || null;
  if (r.type === "mitigation") return r.mitre_id || null;
  if (r.type === "detection_rule") return r.rule_type || null;
  if (r.type === "campaign") return [r.status, r.tlp_marking].filter(Boolean).join(" / ") || null;
  if (r.type === "intel_report") return [r.template_type?.replace(/_/g, " "), r.status].filter(Boolean).join(" / ") || null;
  // A note is only meaningful next to what it is about, so the subtext shows its subject rather than a type name the badge already shows.
  if (r.type === "note") {
    if (r.note_source === "entity_note") {
      const subject = r.entity_name || r.entity_type?.replace(/_/g, " ");
      return [subject ? `on ${subject}` : null, r.note_type?.replace(/_/g, " ")].filter(Boolean).join(" · ") || null;
    }
    if (r.entry_title) return `on "${r.entry_title}"`;
    return "standalone note";
  }
  return null;
}

/** `type:` means **entity type** here and **feed type** in the unified entry grammar. That collision is deliberately left unresolved (risk R5), so this map is used only for the intelligence grammar. */
export const TYPE_FILTER_MAP: Record<string, string> = {
  ttp: "ttp",
  cve: "cve",
  actor: "threat_actor",
  malware: "malware",
  rule: "detection_rule",
  country: "country",
  sector: "sector",
  tool: "tool",
  vendor: "vendor",
  product: "product",
  mitigation: "mitigation",
  campaign: "campaign",
};

/**
 * The intelligence grammar's completions.
 *
 * Built from the same table in `queryFields.ts` that the reference card reads, so every documented field can be completed here. A hand-kept list here would fall behind the query language.
 */
export const INTEL_FILTER_FIELDS: Record<string, string[]> = {
  // Every field completes its name; an empty list means the field is known but its values are not, and the name is still worth offering.
  ...Object.fromEntries(
    ALL_FIELDS.map((f) => {
      const name = f.token.replace(/:$/, "");
      return [name, FIELD_VALUES[name] ?? []];
    }),
  ),
  // LAST on purpose: in the intelligence grammar `type:` means entity type, overriding the entry grammar's feed type (risk R5). Spread earlier, the feed-type values would win and `type:cve` would not complete.
  type: Object.keys(TYPE_FILTER_MAP),
};

export const INTEL_FIELD_DESCRIPTIONS: Record<string, string> = {
  type: "Entity type (cve, actor, rule, ...)",
  ...FIELD_HINTS,
};

export interface IntelSuggestion {
  insert: string;
  /** `"value"` completes the token (trailing space + dropdown closes); `"field"` leaves the caret after the colon. */
  type: "field" | "value";
  hint?: string;
}

/**
 * Completions for the intelligence grammar, from a local dictionary: `/intelligence/search` has no autocomplete endpoint and the fields it understands are a fixed vocabulary.
 *
 * Module scope because `OmniSearchInput` calls it as a hook (see `SuggestionSource`). It returns `NO_SUGGESTIONS` rather than a fresh `[]` because the shared hook's selection-reset effect depends on that identity (R6).
 */
export const useIntelSuggestions: SuggestionSource<IntelSuggestion> = (token, enabled) =>
  useMemo(() => {
    if (!enabled || !token) return NO_SUGGESTIONS;
    if (token.kind === "field_name") {
      const partial = token.partialValue.toLowerCase();
      const fields = Object.keys(INTEL_FILTER_FIELDS).filter((f) => f.startsWith(partial) && f !== partial);
      if (fields.length === 0) return NO_SUGGESTIONS;
      return fields.map((f) => ({ insert: `${f}:`, type: "field" as const, hint: INTEL_FIELD_DESCRIPTIONS[f] }));
    }
    if (token.kind === "field_value" && token.field && INTEL_FILTER_FIELDS[token.field]?.length) {
      const field = token.field;
      const partial = token.partialValue.toLowerCase();
      const values = INTEL_FILTER_FIELDS[field].filter((v) => v.toLowerCase().startsWith(partial));
      if (values.length === 0) return NO_SUGGESTIONS;
      return values.map((v) => ({ insert: `${field}:${v}`, type: "value" as const }));
    }
    return NO_SUGGESTIONS;
  }, [token, enabled]);

/** The workbench's entity routing table: entity profiles by route, the special cases (rule / campaign / report / note), and entries handed to the feed reader. `pir` and any other unlisted type fall through and do nothing, which the characterization tests check. */
export function useEntityResultNavigate() {
  const navigate = useNavigate();
  const addToRecentPivots = useIntelStore((s) => s.addToRecentPivots);

  return (r: EntitySearchResult) => {
    const { type, id } = r;

    if (type === "entry") {
      useUIStore.getState().setSelectedEntry(id);
      navigate("/");
      return;
    }
    if (type === "detection_rule") {
      navigate(`/workbench/rule/${id}`);
      return;
    }
    if (type === "campaign") {
      useIntelStore.getState().setActiveSection("campaigns");
      navigate("/workbench/explore");
      return;
    }
    if (type === "intel_report") {
      navigate(`/workbench/report/${id}`);
      return;
    }
    // Notes live in three places, so a note row opens the one that holds it: the entity's Notes tab, the article's reader panel, or the note browser filtered to the note's title so the matched note is on screen.
    if (type === "note") {
      if (r.note_source === "entity_note" && r.entity_type && r.entity_id) {
        navigate(`/workbench/${r.entity_type}/${r.entity_id}?tab=notes`);
        return;
      }
      if (r.entry_id) {
        useUIStore.getState().setSelectedEntry(r.entry_id);
        useUIStore.getState().setActiveReaderPanel("notes");
        navigate("/");
        return;
      }
      useUIStore.getState().setActivePanel("notes");
      // The browser has no per-note route; setting its filter to the note title puts the clicked note at the top of the list.
      useUIStore.getState().setPendingNoteSearch(r.title || "");
      navigate("/");
      return;
    }

    const entityTypes = ["threat_actor", "malware", "cve", "ttp", "country", "sector", "tool", "vendor", "product", "mitigation"];
    if (entityTypes.includes(type)) {
      const label = r.name || r.value || r.cve_id || r.technique_id || r.title;
      const entityType = type as import("@/stores/intelStore").EntityType;
      addToRecentPivots({ type, id, label: label || id, timestamp: Date.now() });
      navigate(entityProfilePath(entityType, id));
    }
  };
}
