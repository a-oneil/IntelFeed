// Canonical catalog of template variables available to AI prompts.
//
// These are editor hints only — they populate the clickable "Available
// Variables" chips in the prompt editor. Which variables are actually
// populated at render time depends on how the task is invoked (e.g. a
// single-entry task gets `entry.*`; a batch/digest task gets `entries` +
// `entry_count`). The backend renders whatever variables the runtime passes,
// so any variable below can be used in any prompt that receives it.

export interface AIVariableGroup {
  group: string;
  vars: string[];
}

export const AI_VARIABLE_GROUPS: AIVariableGroup[] = [
  {
    group: "Entry",
    vars: [
      "entry.title",
      "entry.content_text",
      "entry.content_html",
      "entry.summary",
      "entry.author",
      "entry.url",
      "entry.published_at",
      "entry.feed_title",
      "entry.feed_type",
      "entry.tags",
    ],
  },
  {
    group: "Intelligence",
    vars: [
      "ttps",
      "existing_ttps",
      "existing_cves",
      "threat_actor_profiles",
      "malware_profiles",
      "existing_detection_rules",
      "related_articles",
    ],
  },
  {
    group: "Detection",
    vars: ["rule_type", "rule_formats", "telemetry_sources", "focus"],
  },
  {
    group: "Batch / Digest",
    vars: ["entries", "entry_count", "date_label", "scope_label"],
  },
  {
    group: "Context",
    vars: ["fp_context", "question", "conversation_history"],
  },
];
