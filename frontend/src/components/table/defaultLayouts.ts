/**
 * The instance's out-of-the-box column arrangement for each DataTable.
 *
 * Captured from the arrangement the instance owner curated in the UI, so a new
 * user opens the workbench on a usable table instead of the raw declaration
 * order with every optional column showing.
 *
 * Strictly a *fallback layer*: `DataTable` consults this only for a column the
 * user has no stored preference for. Toggle a column, drag a divider, or
 * rearrange the order and your choice wins here and stays won — per column for
 * visibility and width, and wholesale for order (reordering a table replaces the
 * default arrangement rather than merging with it).
 *
 * Filters and sort are deliberately absent: those are "what am I looking at
 * right now" state, not layout, and shipping one person's active filter as
 * everyone's default hides rows for no visible reason.
 *
 * To refresh this snapshot, read `state.tables` out of the `intelfeed-ui`
 * localStorage entry (or `settings.table_layouts` on the user profile) and drop
 * the filter/sort fields.
 */
export interface DefaultTableLayout {
  /** Explicit show/hide per column key; overrides the column's `defaultHidden`. */
  visibility?: Record<string, boolean>;
  /** Pixel widths per column key; overrides the column's declared `width`. */
  widths?: Record<string, number>;
  /** Left-to-right column order; keys absent from it keep their declared position. */
  order?: string[];
}

/** Keyed by DataTable `tableId` ("entries", "entity:threat_actor", ...). */
export const DEFAULT_TABLE_LAYOUTS: Record<string, DefaultTableLayout> = {
  "entries": {
    visibility: {
      "opportunity": true,
      "notes": false,
      "type": false,
      "domain": false,
      "author": false,
      "words": false,
      "rules": false,
      "status": true,
      "tags": false,
      "summary": true,
      "source": false,
      "ttps": true,
      "ai": false,
    },
    widths: {
      "title": 379,
      "status": 48,
      "date": 153,
      "summary": 905,
    },
    order: [
      "status",
      "source",
      "date",
      "title",
      "summary",
      "signal",
      "pir",
      "subject",
      "ttps",
      "cves",
      "rules",
      "ai",
      "opportunity",
      "notes",
      "tags",
      "type",
      "domain",
      "author",
      "words",
    ],
  },
  "entity:threat_actor": {
    visibility: {
      "linked_count": false,
      "top_link": true,
      "last_seen_at": false,
      "first_seen_at": true,
      "motivation": true,
      "mitre_id": false,
    },
    order: [
      "name",
      "mitre_id",
      "aliases",
      "country",
      "motivation",
      "targeted_sectors",
      "activity",
      "first_seen_at",
      "last_seen_at",
      "description",
      "ttp_count",
      "wikipedia_url",
      "linked_count",
      "top_link",
      "article_count",
    ],
  },
  "entity:malware": {
    visibility: {
      "malpedia_url": false,
      "wikipedia_url": false,
      "description": true,
      "linked_count": false,
      "top_link": true,
      "last_seen_at": false,
    },
    widths: {
      "first_seen_at": 196,
    },
    order: [
      "name",
      "aliases",
      "malware_type",
      "first_seen_at",
      "last_seen_at",
      "description",
      "actor_count",
      "malpedia_url",
      "wikipedia_url",
      "linked_count",
      "top_link",
      "article_count",
    ],
  },
  "entity:tool": {
    visibility: {
      "github_url": false,
      "detection_artifacts": false,
      "confidence": false,
      "description": true,
      "last_seen_at": false,
      "first_seen_at": true,
      "linked_count": false,
    },
    order: [
      "name",
      "description",
      "tool_type",
      "aliases",
      "platforms",
      "first_seen_at",
      "article_count",
      "last_seen_at",
      "github_url",
      "malpedia_url",
      "detection_artifacts",
      "confidence",
      "wikipedia_url",
      "linked_count",
      "top_link",
    ],
  },
  "entity:cve": {
    visibility: {
      "github_poc_count": false,
      "exploit_status": false,
      "linked_count": false,
      "exploit_sources": false,
      "first_seen_at": true,
      "updated_at": false,
    },
    order: [
      "cve_id",
      "risk_tier",
      "is_kev",
      "epss_score",
      "severity",
      "cvss_score",
      "description",
      "affected_products",
      "exploit_availability",
      "first_seen_at",
      "article_count",
      "updated_at",
      "kev_due_date",
      "kev_date_added",
      "epss_percentile",
      "exploit_status",
      "exploit_sources",
      "priority",
      "github_poc_count",
      "metasploit_module",
      "references",
      "linked_count",
      "top_link",
    ],
  },
  "entity:ttp": {
    visibility: {
      "linked_count": false,
      "parent_technique_id": false,
      "is_subtechnique": false,
      "matrix_domain": true,
      "data_sources": false,
      "platforms": true,
      "article_count": true,
      "first_seen_at": false,
      "last_seen_at": false,
      "tactics": true,
      "tactic": false,
      "mitre_url": true,
      "detection": false,
      "description": true,
    },
    widths: {
      "coverage": 86,
      "mitre_url": 90,
    },
    order: [
      "technique_id",
      "technique_name",
      "tactic",
      "description",
      "platforms",
      "data_sources",
      "first_seen_at",
      "last_seen_at",
      "matrix_domain",
      "is_subtechnique",
      "parent_technique_id",
      "tactics",
      "detection",
      "coverage",
      "mitre_url",
      "article_count",
      "rule_count",
      "linked_count",
      "top_link",
    ],
  },
  "entity:mitigation": {
    order: [
      "name",
      "mitre_id",
      "cis_controls",
      "nist_controls",
      "last_seen_at",
      "description",
      "first_seen_at",
      "source",
      "confidence",
      "mitre_url",
      "linked_count",
      "article_count",
      "top_link",
    ],
  },
  "entity:vendor": {
    visibility: {
      "first_seen_at": false,
      "last_seen_at": false,
      "aliases": true,
      "description": true,
      "linked_count": false,
      "website": false,
      "source": false,
      "confidence": false,
    },
    widths: {
      "name": 292,
      "description": 658,
      "aliases": 187,
    },
    order: [
      "name",
      "description",
      "aliases",
      "vendor_type",
      "website",
      "article_count",
      "first_seen_at",
      "last_seen_at",
      "source",
      "confidence",
      "linked_count",
      "top_link",
    ],
  },
  "entity:product": {
    visibility: {
      "website": false,
      "description": true,
      "last_seen_at": false,
      "first_seen_at": false,
      "linked_count": false,
    },
    order: [
      "name",
      "description",
      "product_type",
      "vendor_name",
      "article_count",
      "first_seen_at",
      "last_seen_at",
      "aliases",
      "website",
      "source",
      "confidence",
      "linked_count",
      "top_link",
    ],
  },
  "entity:country": {
    visibility: {
      "top_link": false,
      "targeting_actor_count": false,
      "aliases": false,
      "last_seen_at": false,
      "linked_count": false,
    },
    widths: {
      "name": 302,
      "iso_code": 448,
      "region": 286,
    },
    order: [
      "name",
      "region",
      "iso_code",
      "targeting_actor_count",
      "aliases",
      "article_count",
      "last_seen_at",
      "first_seen_at",
      "description",
      "linked_count",
      "top_link",
    ],
  },
};

export const EMPTY_DEFAULT_LAYOUT: DefaultTableLayout = {};
