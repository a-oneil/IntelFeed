/**
 * Centralized entity type visual language.
 * Every component that renders entity types should use these functions
 * instead of hardcoding colors or icons.
 */

export type EntityType =
  | "threat_actor"
  | "malware"
  | "ttp"
  | "cve"
  | "cwe"
  | "country"
  | "detection_rule"
  | "campaign"
  | "vendor"
  | "product"
  | "tool"
  | "mitigation"
  | "ransomware_victim"
  | "observable"
  // Not an intelligence entity — the analyst's own writing about one. It lives
  // here so search rows and facet dots colour it like everything else they list.
  | "note";

interface EntityTheme {
  color: string;
  cssVar: string;
  label: string;
  pluralLabel: string;
  /** Lucide icon name */
  icon: string;
}

const ENTITY_THEMES: Record<EntityType, EntityTheme> = {
  ransomware_victim: {
    color: "#e0555b",
    cssVar: "var(--entity-victim)",
    label: "Victim",
    pluralLabel: "Victims",
    icon: "building",
  },
  threat_actor: {
    color: "#f97316",
    cssVar: "var(--entity-actor)",
    label: "Threat Actor",
    pluralLabel: "Threat Actors",
    icon: "users",
  },
  malware: {
    color: "#a855f7",
    cssVar: "var(--entity-malware)",
    label: "Malware",
    pluralLabel: "Malware",
    icon: "shield-alert",
  },
  ttp: {
    color: "#3b82f6",
    cssVar: "var(--entity-ttp)",
    label: "TTP",
    pluralLabel: "TTPs",
    icon: "flag",
  },
  cve: {
    color: "#ef4444",
    cssVar: "var(--entity-cve)",
    label: "CVE",
    pluralLabel: "CVEs",
    icon: "triangle-alert",
  },
  // Bronze. The palette's 13 hues leave no clean gap, so this one separates on
  // value rather than hue: no other entity color is dark-and-desaturated, so it
  // never reads as actor-orange despite sitting near it on the wheel.
  cwe: {
    color: "#b45309",
    cssVar: "var(--entity-cwe)",
    label: "Weakness",
    pluralLabel: "Weaknesses",
    icon: "bug",
  },
  country: {
    color: "#06b6d4",
    cssVar: "var(--entity-country)",
    label: "Country",
    pluralLabel: "Countries",
    icon: "globe",
  },
  // Fuchsia — the last real hue gap, between malware violet and product pink.
  // --entity-ioc predates this type (modules referenced it as a fallback var)
  // and used to duplicate tool-yellow; it diverges here so Observables and
  // Tools stop sharing a swatch.
  observable: {
    color: "#d946ef",
    cssVar: "var(--entity-ioc)",
    label: "Observable",
    pluralLabel: "Observables",
    icon: "crosshair",
  },
  detection_rule: {
    color: "#22c55e",
    cssVar: "var(--entity-rule)",
    label: "Detection Rule",
    pluralLabel: "Detection Rules",
    icon: "file-code",
  },
  campaign: {
    color: "#14b8a6",
    cssVar: "var(--entity-campaign)",
    label: "Campaign",
    pluralLabel: "Campaigns",
    icon: "book-open",
  },
  vendor: {
    color: "#6366f1",
    cssVar: "var(--entity-vendor)",
    label: "Vendor",
    pluralLabel: "Vendors",
    icon: "building-2",
  },
  product: {
    color: "#ec4899",
    cssVar: "var(--entity-product)",
    label: "Product",
    pluralLabel: "Products",
    icon: "package",
  },
  tool: {
    color: "#eab308",
    cssVar: "var(--entity-tool)",
    label: "Tool",
    pluralLabel: "Tools",
    icon: "wrench",
  },
  note: {
    color: "#9aa4b2",
    cssVar: "var(--entity-note)",
    label: "Note",
    pluralLabel: "Notes",
    icon: "sticky-note",
  },
  mitigation: {
    color: "#84cc16",
    cssVar: "var(--entity-mitigation)",
    label: "Mitigation",
    pluralLabel: "Mitigations",
    icon: "shield-check",
  },
};

/** Get the hex color for an entity type */
export function getEntityColor(type: string): string {
  return ENTITY_THEMES[type as EntityType]?.color ?? "#8b949e";
}

/** Get the CSS variable reference for an entity type */
export function getEntityCssVar(type: string): string {
  return ENTITY_THEMES[type as EntityType]?.cssVar ?? "var(--text-secondary)";
}

/** Get the display label for an entity type */
export function getEntityLabel(type: string): string {
  return ENTITY_THEMES[type as EntityType]?.label ?? type;
}

/** Get the plural display label for an entity type */
export function getEntityPluralLabel(type: string): string {
  return ENTITY_THEMES[type as EntityType]?.pluralLabel ?? type;
}

/** Get the Lucide icon name for an entity type */
export function getEntityIcon(type: string): string {
  return ENTITY_THEMES[type as EntityType]?.icon ?? "circle";
}

/** Get the full theme object for an entity type */
export function getEntityTheme(type: string): EntityTheme {
  return (
    ENTITY_THEMES[type as EntityType] ?? {
      color: "#8b949e",
      cssVar: "var(--text-secondary)",
      label: type,
      icon: "circle",
    }
  );
}

/**
 * Legacy-compatible color map for components that use Record<string, string>.
 * Prefer getEntityColor() for new code.
 */
export const ENTITY_COLOR_MAP: Record<string, string> = {
  cve: ENTITY_THEMES.cve.cssVar,
  ttp: ENTITY_THEMES.ttp.cssVar,
  threat_actor: ENTITY_THEMES.threat_actor.cssVar,
  malware: ENTITY_THEMES.malware.cssVar,
  country: ENTITY_THEMES.country.cssVar,
  detection_rule: ENTITY_THEMES.detection_rule.cssVar,
  campaign: ENTITY_THEMES.campaign.cssVar,
  vendor: ENTITY_THEMES.vendor.cssVar,
  product: ENTITY_THEMES.product.cssVar,
  tool: ENTITY_THEMES.tool.cssVar,
  mitigation: ENTITY_THEMES.mitigation.cssVar,
  cwe: ENTITY_THEMES.cwe.cssVar,
  observable: ENTITY_THEMES.observable.cssVar,
};
