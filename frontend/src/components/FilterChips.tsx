import styles from "./FilterChips.module.css";
import type { ParsedFilter } from "@/utils/queryParser";
import { getEntityColor } from "@/utils/entityTheme";

// Short filter tokens (`type:` values and entity-search field roots) →
// canonical entity type used by entityTheme, so chips share the profile colors.
const TYPE_VALUE_TO_ENTITY: Record<string, string> = {
  threat_actor: "threat_actor",
  rule: "detection_rule",
  cve: "cve",
  ttp: "ttp",
  malware: "malware",
  country: "country",
  tool: "tool",
  vendor: "vendor",
  product: "product",
  mitigation: "mitigation",
  cwe: "cwe",
  campaign: "campaign",
  ransomware_victim: "ransomware_victim",
};

const CATEGORY_COLORS: Record<string, string> = {
  cve: "#f97316",
  ttp: "#8b5cf6",
  malware: "#14b8a6",
  rule: "#06b6d4",
  pir: "#06b6d4",
  is: "#6366f1",
  tag: "#22c55e",
  type: "#64748b",
  date: "#eab308",
  sort: "#94a3b8",
  title: "#3b82f6",
  content: "#3b82f6",
  author: "#3b82f6",
  feed: "#3b82f6",
  media: "#64748b",
  lang: "#64748b",
};

function getChipColor(filter: ParsedFilter): string {
  const root = filter.field.split(".")[0];
  // Entity-search fields (cve:, ttp:, threat_actor:, malware:, rule:, and their
  // subfields like cve.severity) take the entity's own profile color.
  if (TYPE_VALUE_TO_ENTITY[root]) {
    return getEntityColor(TYPE_VALUE_TO_ENTITY[root]);
  }
  // `type:<entity>` chips resolve the color from the value instead.
  if (root === "type") {
    const entityType = TYPE_VALUE_TO_ENTITY[filter.value.toLowerCase()];
    if (entityType) return getEntityColor(entityType);
  }
  return CATEGORY_COLORS[root] || "#6b7280";
}

function formatLabel(filter: ParsedFilter): string {
  const prefix = filter.negated ? "NOT " : "";
  if (filter.exact) return `${prefix}${filter.field}: "${filter.value}"`;
  return `${prefix}${filter.field}: ${filter.value}`;
}

interface FilterChipsProps {
  filters: ParsedFilter[];
  onRemove: (filter: ParsedFilter) => void;
  /**
   * `"strip"` (default) is the original full-width band beneath a search field:
   * its own panel background, padding and bottom rule.
   *
   * `"inline"` is the chips alone, for callers that place them inside an
   * existing row. The strip's background is a step lighter than a toolbar's, so
   * nesting it there draws a stray lighter box around the chips.
   */
  variant?: "strip" | "inline";
}

export default function FilterChips({ filters, onRemove, variant = "strip" }: FilterChipsProps) {
  if (filters.length === 0) return null;

  return (
    <div className={variant === "inline" ? styles.chipsInline : styles.chipsContainer}>
      {filters.map((filter, idx) => (
        <span
          key={`${filter.raw}-${idx}`}
          className={styles.chip}
          style={{ borderColor: getChipColor(filter) }}
        >
          <span
            className={styles.chipDot}
            style={{ backgroundColor: getChipColor(filter) }}
          />
          <span className={styles.chipLabel}>{formatLabel(filter)}</span>
          <button
            className={styles.chipRemove}
            onClick={() => onRemove(filter)}
            aria-label={`Remove ${filter.field} filter`}
          >
            &times;
          </button>
        </span>
      ))}
    </div>
  );
}
