import { useState, useCallback } from "react";
import {
  useCreateAutomationRule,
  useUpdateAutomationRule,
} from "@/hooks/useAutomation";
import { useFeeds, useCategories } from "@/hooks/useFeeds";
import { useAITasks } from "@/hooks/useAI";
import { useWebhookPresets } from "@/hooks/useWebhookPresets";
import type { AutomationRule } from "@/api/types";
import { TagPicker } from "./TagPicker";
import styles from "./AutomationRuleEditor.module.css";

/** Coerce a stored tags config value (array or comma string) to a name array. */
function tagArray(config: Record<string, unknown>): string[] {
  const v = config.tags;
  if (Array.isArray(v)) return v as string[];
  if (typeof v === "string" && v) return v.split(",").map((s) => s.trim()).filter(Boolean);
  return [];
}

const TRIGGER_TYPES = [
  { value: "on_new_entry", label: "New entry arrives" },
  { value: "on_entry_scored", label: "Entry scored (signal engine)" },
  { value: "on_schedule", label: "On schedule (cron)" },
  { value: "on_keyword_match", label: "Keyword match" },
  { value: "on_cve_detected", label: "CVE detected" },
  { value: "on_manual", label: "Manual trigger" },
];

const ACTION_TYPES = [
  { value: "run_ai_task", label: "Run AI Task" },
  { value: "use_daily_summary", label: "Use Daily Summary" },
  { value: "extract_ttps", label: "Extract TTPs" },
  { value: "extract_cves", label: "Extract CVEs" },
  { value: "extract_threat_actors", label: "Extract Threat Actors" },
  { value: "extract_malware", label: "Extract Malware" },
  { value: "generate_detection_rules", label: "Generate Detection Rules" },
  { value: "track_on_threat_board", label: "Track on Threats Board" },
  { value: "add_tags", label: "Add Tags" },
  { value: "remove_tags", label: "Remove Tags" },
  { value: "send_notification", label: "Send Notification" },
  { value: "run_webhook", label: "Run Webhook" },
  { value: "add_to_campaign", label: "Add to Campaign" },
  { value: "mark_priority", label: "Mark Priority" },
  { value: "mark_read", label: "Mark as Read" },
  { value: "star_entry", label: "Star Entry" },
  { value: "bookmark_entry", label: "Bookmark Entry" },
  { value: "hide_entry", label: "Hide Entry" },
  { value: "create_note", label: "Create Note" },
  { value: "mark_false_positive", label: "Mark as False Positive" },
  { value: "create_intel_report", label: "Create Intel Report" },
  { value: "chain_rule", label: "Chain Rule" },
  { value: "export_to", label: "Export Data" },
  { value: "branch", label: "If/Else Branch" },
];

const CONDITION_TYPES = [
  { value: "feed_matches", label: "Feed matches" },
  { value: "content_contains", label: "Content contains" },
  { value: "severity_above", label: "Severity above" },
  { value: "author_matches", label: "Author matches" },
  { value: "tag_matches", label: "Tag matches" },
  { value: "feed_type_matches", label: "Feed type matches" },
  { value: "is_read", label: "Is read" },
  { value: "is_starred", label: "Is starred" },
  { value: "is_bookmarked", label: "Is bookmarked" },
  { value: "has_note", label: "Has note" },
  { value: "priority_score_above", label: "Priority score above (signals)" },
  { value: "has_signal", label: "Has signal type" },
  { value: "entity_watchlisted", label: "Watched entity mentioned" },
];

interface ConditionItem {
  type: string;
  config: Record<string, unknown>;
}

interface ConditionGroup {
  operator: "AND" | "OR";
  conditions: ConditionItem[];
}

interface ActionItem {
  type: string;
  config: Record<string, unknown>;
}

interface Props {
  rule: AutomationRule | null;
  onClose: () => void;
}

function parseConditions(raw: Record<string, unknown>): ConditionGroup {
  if (!raw || !raw.operator) {
    return { operator: "AND", conditions: [] };
  }
  return {
    operator: (raw.operator as string)?.toUpperCase() === "OR" ? "OR" : "AND",
    conditions: (
      (raw.conditions as Array<Record<string, unknown>>) ?? []
    ).map((c) => ({
      type: (c.type as string) ?? "",
      config: (c.config as Record<string, unknown>) ?? {},
    })),
  };
}

function parseActions(raw: Array<Record<string, unknown>>): ActionItem[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((a) => ({
    type: (a.type as string) ?? "",
    config: (a.config as Record<string, unknown>) ?? {},
  }));
}

function conditionConfigFields(type: string): Array<{
  key: string;
  label: string;
  placeholder: string;
  type?: "text" | "number";
}> {
  switch (type) {
    case "feed_matches":
      return [
        {
          key: "feed_ids",
          label: "Feed IDs (comma-separated)",
          placeholder: "uuid1, uuid2",
        },
        {
          key: "category_ids",
          label: "Category IDs (comma-separated)",
          placeholder: "uuid1, uuid2",
        },
      ];
    case "content_contains":
      return [
        { key: "pattern", label: "Pattern", placeholder: "CVE-\\d{4}" },
        { key: "is_regex", label: "Is regex? (true/false)", placeholder: "false" },
      ];
    case "severity_above":
      return [
        {
          key: "min_cvss",
          label: "Min CVSS",
          placeholder: "7.0",
          type: "number",
        },
      ];
    case "priority_score_above":
      return [
        {
          key: "min",
          label: "Min priority score",
          placeholder: "2.0",
          type: "number",
        },
      ];
    case "has_signal":
      return [
        {
          key: "types",
          label: "Signal types (comma-separated, empty = any)",
          placeholder: "novel_entity, kev_added, under_reported",
        },
      ];
    case "author_matches":
      return [
        {
          key: "authors",
          label: "Authors (comma-separated)",
          placeholder: "CISA, Microsoft",
        },
      ];
    case "tag_matches":
      return [
        {
          key: "tags",
          label: "Tags (comma-separated)",
          placeholder: "critical, needs-review",
        },
      ];
    case "feed_type_matches":
      return [
        {
          key: "types",
          label: "Feed types (comma-separated)",
          placeholder: "rss, youtube, github_releases",
        },
      ];
    case "is_read":
    case "is_starred":
    case "is_bookmarked":
    case "has_note":
      return []; // No config needed — these are boolean checks
    default:
      return [];
  }
}

interface ActionField {
  key: string;
  label: string;
  placeholder: string;
  multiline?: boolean;
  hint?: string;
  fieldType?: "select";
  options?: Array<{ value: string; label: string }>;
}

function actionConfigFields(
  type: string,
  aiTasks?: Array<{ name: string; display_name: string }>,
): ActionField[] {
  switch (type) {
    case "run_ai_task":
      return [
        {
          key: "task_id",
          label: "Task",
          placeholder: "",
          fieldType: "select",
          options: (aiTasks ?? []).map((t) => ({ value: t.name, label: t.display_name })),
          hint: "Prompt {{ }} variables depend on the trigger's execution mode — Per-entry: {{ entry.* }}; Batch: {{ entries }}, {{ entry_count }}, {{ entry.* }}. (date_label / scope_label are feed-UI only, not injected here.)",
        },
      ];
    case "use_daily_summary":
      return [
        {
          key: "day",
          label: "Day",
          placeholder: "yesterday",
          fieldType: "select",
          options: [
            { value: "yesterday", label: "Yesterday (complete day)" },
            { value: "today", label: "Today (partial day so far)" },
          ],
          hint: "Reuses the shared day-divider briefing instead of generating a second one — fills {ai_summary} for a following notification or webhook. Batch rules only.",
        },
        {
          key: "on_missing",
          label: "If not cached",
          placeholder: "generate",
          fieldType: "select",
          options: [
            { value: "generate", label: "Generate it (also fills the day divider)" },
            { value: "skip", label: "Skip — send nothing" },
          ],
        },
        {
          key: "links",
          label: "Article links",
          placeholder: "original",
          fieldType: "select",
          options: [
            { value: "original", label: "Original article URLs (for Discord/Slack)" },
            { value: "app", label: "IntelFeed reader links (needs PUBLIC_BASE_URL)" },
          ],
          hint: "The cached briefing links into the IntelFeed reader. Outside the app those links need a session, so they're rewritten to each article's source URL by default.",
        },
      ];
    case "extract_ttps":
      return [
        { key: "use_ai", label: "Use AI? (true/false)", placeholder: "true" },
      ];
    case "extract_cves":
    case "extract_threat_actors":
    case "extract_malware":
    case "track_on_threat_board":
      return []; // No config needed
    case "generate_detection_rules":
      return [
        {
          key: "rule_types",
          label: "Rule types (comma-separated)",
          placeholder: "sigma, splunk_spl, kql",
          hint: "Options: sigma, splunk_spl, crowdstrike_ql, elastic_ql, kql, yara, snort_suricata",
        },
      ];
    case "add_tags":
      return [
        {
          key: "tags",
          label: "Tags (comma-separated)",
          placeholder: "critical, needs-review",
        },
      ];
    case "remove_tags":
      return [
        {
          key: "tags",
          label: "Tags to remove (comma-separated)",
          placeholder: "needs-review, untriaged",
        },
      ];
    case "send_notification":
      return [
        { key: "platform", label: "Platform", placeholder: "slack, discord, or custom" },
        { key: "webhook_url", label: "Webhook URL", placeholder: "https://hooks.slack.com/..." },
        { key: "channel", label: "Channel", placeholder: "#threat-intel" },
        { key: "username", label: "Bot Name", placeholder: "IntelFeed" },
        {
          key: "message_template",
          label: "Message Template",
          placeholder: "**{title}**\\n{url}\\n{summary}",
          multiline: true,
          hint: "Single-brace variables (distinct from a Run AI Task's {{ }} prompt): {title}, {url}, {author}, {summary}, {published_at}, {ai_summary}, {feed_name}. {ai_summary} is the output of a preceding Run AI Task action.",
        },
      ];
    case "run_webhook":
      return [
        { key: "url", label: "URL", placeholder: "https://..." },
      ];
    case "add_to_campaign":
      return [
        { key: "campaign_id", label: "Campaign ID", placeholder: "uuid" },
        { key: "notes", label: "Notes (optional)", placeholder: "Auto-linked by automation" },
      ];
    case "mark_priority":
      return [
        { key: "level", label: "Level", placeholder: "high" },
      ];
    case "mark_read":
    case "star_entry":
    case "bookmark_entry":
    case "hide_entry":
      return []; // No config needed
    case "create_note":
      return [
        { key: "title", label: "Note Title", placeholder: "Auto-note: {title}" },
        {
          key: "content",
          label: "Note Content (markdown)",
          placeholder: "{summary}",
          multiline: true,
          hint: "Variables: {title}, {url}, {author}, {summary}, {ai_summary}, {published_at}",
        },
      ];
    case "mark_false_positive":
      return [
        { key: "reason", label: "Reason", placeholder: "Known benign infrastructure" },
      ];
    case "create_intel_report":
      return [
        { key: "title", label: "Report Title", placeholder: "Intel Report: {title}" },
        {
          key: "template_type",
          label: "Template",
          placeholder: "flash_alert",
          hint: "Options: flash_alert, ioc_bulletin, actor_profile, campaign_tracker, landscape_report, custom",
        },
        { key: "tlp_marking", label: "TLP Marking", placeholder: "TLP:GREEN" },
        {
          key: "summary",
          label: "Summary",
          placeholder: "{summary}",
          multiline: true,
          hint: "Variables: {title}, {url}, {author}, {summary}, {ai_summary}",
        },
      ];
    case "chain_rule":
      return [
        { key: "rule_id", label: "Rule ID", placeholder: "uuid" },
      ];
    case "export_to":
      return [
        { key: "format", label: "Format", placeholder: "csv, markdown" },
        { key: "destination", label: "Destination", placeholder: "webhook" },
        { key: "webhook_url", label: "Webhook URL", placeholder: "https://..." },
      ];
    default:
      return [];
  }
}

function configToDisplay(config: Record<string, unknown>, key: string): string {
  const val = config[key];
  if (Array.isArray(val)) return val.join(", ");
  if (val === true) return "true";
  if (val === false) return "false";
  return String(val ?? "");
}

function displayToConfig(
  value: string,
  key: string,
  _type: string
): unknown {
  // Handle array fields
  const arrayFields = [
    "feed_ids",
    "category_ids",
    "authors",
    "tags",
    "types",
    "rule_types",
    "values",
  ];
  if (arrayFields.includes(key)) {
    return value
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  if (key === "is_regex" || key === "use_ai") return value === "true";
  if (key === "min_cvss" || key === "min_count") return parseFloat(value) || 0;
  return value;
}

function BranchActionEditor({
  config,
  onUpdate,
  aiTasks,
}: {
  config: Record<string, unknown>;
  onUpdate: (config: Record<string, unknown>) => void;
  aiTasks: Array<{ name: string; display_name: string }>;
}) {
  const condition = (config.condition as Record<string, unknown>) ?? {};
  const condType = (condition.type as string) ?? "content_contains";
  const condConfig = (condition.config as Record<string, unknown>) ?? {};
  const thenActions = ((config.then_actions ?? []) as Array<Record<string, unknown>>).map(
    (a) => ({ type: (a.type as string) ?? "", config: (a.config as Record<string, unknown>) ?? {} })
  );
  const elseActions = ((config.else_actions ?? []) as Array<Record<string, unknown>>).map(
    (a) => ({ type: (a.type as string) ?? "", config: (a.config as Record<string, unknown>) ?? {} })
  );

  const condFields = conditionConfigFields(condType);

  const updateCondition = (updates: Record<string, unknown>) => {
    onUpdate({
      ...config,
      condition: { ...condition, ...updates },
    });
  };

  const updateSubAction = (
    branch: "then_actions" | "else_actions",
    index: number,
    key: string,
    value: string,
    actType: string
  ) => {
    const list = branch === "then_actions" ? [...thenActions] : [...elseActions];
    const action = { ...list[index] };
    action.config = { ...action.config, [key]: displayToConfig(value, key, actType) };
    list[index] = action;
    onUpdate({ ...config, [branch]: list });
  };

  const addSubAction = (branch: "then_actions" | "else_actions", type: string) => {
    const list = branch === "then_actions" ? [...thenActions] : [...elseActions];
    list.push({ type, config: {} });
    onUpdate({ ...config, [branch]: list });
  };

  const removeSubAction = (branch: "then_actions" | "else_actions", index: number) => {
    const list = branch === "then_actions" ? [...thenActions] : [...elseActions];
    list.splice(index, 1);
    onUpdate({ ...config, [branch]: list });
  };

  const NON_BRANCH_ACTION_TYPES = ACTION_TYPES.filter((a) => a.value !== "branch");

  return (
    <div className={styles.branchEditor}>
      {/* Condition */}
      <div className={styles.branchSection}>
        <label className={styles.branchLabel}>IF condition:</label>
        <select
          value={condType}
          onChange={(e) =>
            updateCondition({ type: e.target.value, config: {} })
          }
          className={styles.select}
        >
          {CONDITION_TYPES.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </select>
        {condFields.map((f) => (
          <div key={f.key} className={styles.itemField}>
            <label>{f.label}</label>
            <input
              type={f.type ?? "text"}
              placeholder={f.placeholder}
              value={configToDisplay(condConfig, f.key)}
              onChange={(e) =>
                updateCondition({
                  type: condType,
                  config: {
                    ...condConfig,
                    [f.key]: displayToConfig(e.target.value, f.key, condType),
                  },
                })
              }
            />
          </div>
        ))}
      </div>

      {/* Then actions */}
      <div className={styles.branchSection}>
        <label className={styles.branchLabel}>THEN (Yes):</label>
        {thenActions.map((action, i) => {
          const label = NON_BRANCH_ACTION_TYPES.find((a) => a.value === action.type)?.label ?? action.type;
          const fields = actionConfigFields(action.type, aiTasks);
          return (
            <div key={i} className={styles.branchSubAction}>
              <div className={styles.itemCardHeader}>
                <span className={styles.itemLabel}>{label}</span>
                <button className={styles.removeBtn} onClick={() => removeSubAction("then_actions", i)}>x</button>
              </div>
              {fields.map((f) => (
                <div key={f.key} className={styles.itemField}>
                  <label>{f.label}</label>
                  {f.key === "tags" ? (
                    <TagPicker
                      value={tagArray(action.config)}
                      onChange={(names) => updateSubAction("then_actions", i, "tags", names.join(","), action.type)}
                    />
                  ) : (
                    <input
                      type="text"
                      placeholder={f.placeholder}
                      value={configToDisplay(action.config, f.key)}
                      onChange={(e) => updateSubAction("then_actions", i, f.key, e.target.value, action.type)}
                    />
                  )}
                  {f.hint && <span className={styles.hint}>{f.hint}</span>}
                </div>
              ))}
            </div>
          );
        })}
        <select
          value=""
          onChange={(e) => {
            if (e.target.value) addSubAction("then_actions", e.target.value);
            e.target.value = "";
          }}
          className={styles.select}
        >
          <option value="">+ Add action...</option>
          {NON_BRANCH_ACTION_TYPES.map((a) => (
            <option key={a.value} value={a.value}>{a.label}</option>
          ))}
        </select>
      </div>

      {/* Else actions */}
      <div className={styles.branchSection}>
        <label className={styles.branchLabel}>ELSE (No):</label>
        {elseActions.map((action, i) => {
          const label = NON_BRANCH_ACTION_TYPES.find((a) => a.value === action.type)?.label ?? action.type;
          const fields = actionConfigFields(action.type, aiTasks);
          return (
            <div key={i} className={styles.branchSubAction}>
              <div className={styles.itemCardHeader}>
                <span className={styles.itemLabel}>{label}</span>
                <button className={styles.removeBtn} onClick={() => removeSubAction("else_actions", i)}>x</button>
              </div>
              {fields.map((f) => (
                <div key={f.key} className={styles.itemField}>
                  <label>{f.label}</label>
                  {f.key === "tags" ? (
                    <TagPicker
                      value={tagArray(action.config)}
                      onChange={(names) => updateSubAction("else_actions", i, "tags", names.join(","), action.type)}
                    />
                  ) : (
                    <input
                      type="text"
                      placeholder={f.placeholder}
                      value={configToDisplay(action.config, f.key)}
                      onChange={(e) => updateSubAction("else_actions", i, f.key, e.target.value, action.type)}
                    />
                  )}
                  {f.hint && <span className={styles.hint}>{f.hint}</span>}
                </div>
              ))}
            </div>
          );
        })}
        <select
          value=""
          onChange={(e) => {
            if (e.target.value) addSubAction("else_actions", e.target.value);
            e.target.value = "";
          }}
          className={styles.select}
        >
          <option value="">+ Add action...</option>
          {NON_BRANCH_ACTION_TYPES.map((a) => (
            <option key={a.value} value={a.value}>{a.label}</option>
          ))}
        </select>
      </div>
    </div>
  );
}

export function AutomationRuleEditor({ rule, onClose }: Props) {
  const { data: feedsData } = useFeeds();
  const { data: categoriesData } = useCategories();
  const { data: aiTasksData } = useAITasks();
  const { data: webhookPresetsData } = useWebhookPresets();
  const subscriptions = feedsData?.items ?? [];
  const categories = categoriesData ?? [];
  const aiTasks = aiTasksData ?? [];
  const webhookPresets = webhookPresetsData?.items ?? [];

  const createRule = useCreateAutomationRule();
  const updateRule = useUpdateAutomationRule();

  const [name, setName] = useState(rule?.name ?? "");
  const [description, setDescription] = useState(rule?.description ?? "");
  const [labelsText, setLabelsText] = useState(
    (rule?.labels ?? []).join(", ")
  );
  const [triggerType, setTriggerType] = useState(
    rule?.trigger_type ?? "on_new_entry"
  );
  const [triggerConfig, setTriggerConfig] = useState<Record<string, unknown>>(
    (rule?.trigger_config ?? {}) as Record<string, unknown>
  );
  const [showJsonTrigger, setShowJsonTrigger] = useState(false);
  const [jsonTrigger, setJsonTrigger] = useState(
    JSON.stringify(rule?.trigger_config ?? {}, null, 2)
  );
  const [conditionGroup, setConditionGroup] = useState<ConditionGroup>(
    parseConditions((rule?.conditions ?? {}) as Record<string, unknown>)
  );
  const [actionItems, setActionItems] = useState<ActionItem[]>(
    parseActions(
      (rule?.actions ?? []) as Array<Record<string, unknown>>
    )
  );
  const [showJsonConditions, setShowJsonConditions] = useState(false);
  const [showJsonActions, setShowJsonActions] = useState(false);
  const [feedSearch, setFeedSearch] = useState("");
  const [jsonConditions, setJsonConditions] = useState(
    JSON.stringify(rule?.conditions ?? {}, null, 2)
  );
  const [jsonActions, setJsonActions] = useState(
    JSON.stringify(rule?.actions ?? [], null, 2)
  );
  const [error, setError] = useState("");

  const handleSave = async () => {
    setError("");

    if (!name.trim()) {
      setError("Name is required");
      return;
    }

    let parsedTriggerConfig: Record<string, unknown>;
    if (showJsonTrigger) {
      try {
        parsedTriggerConfig = JSON.parse(jsonTrigger);
      } catch {
        setError("Invalid trigger config JSON");
        return;
      }
    } else {
      parsedTriggerConfig = triggerConfig;
    }

    let parsedConditions: Record<string, unknown>;
    let parsedActions: Array<Record<string, unknown>>;

    if (showJsonConditions) {
      try {
        parsedConditions = JSON.parse(jsonConditions);
      } catch {
        setError("Invalid conditions JSON");
        return;
      }
    } else {
      parsedConditions =
        conditionGroup.conditions.length > 0
          ? {
              operator: conditionGroup.operator,
              conditions: conditionGroup.conditions,
            }
          : {};
    }

    if (showJsonActions) {
      try {
        parsedActions = JSON.parse(jsonActions);
        if (!Array.isArray(parsedActions) || parsedActions.length === 0) {
          setError("At least one action is required");
          return;
        }
      } catch {
        setError("Invalid actions JSON");
        return;
      }
    } else {
      if (actionItems.length === 0) {
        setError("At least one action is required");
        return;
      }
      parsedActions = actionItems as unknown as Array<Record<string, unknown>>;
    }

    const data = {
      name: name.trim(),
      description: description.trim() || undefined,
      trigger_type: triggerType,
      trigger_config: parsedTriggerConfig,
      conditions: parsedConditions,
      labels: labelsText.split(",").map((l) => l.trim().toLowerCase()).filter(Boolean),
      actions: parsedActions,
    };

    try {
      if (rule) {
        await updateRule.mutateAsync({ ruleId: rule.id, data });
      } else {
        await createRule.mutateAsync(data);
      }
      onClose();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to save rule";
      setError(msg);
    }
  };

  const addCondition = useCallback(
    (type: string) => {
      setConditionGroup((prev) => ({
        ...prev,
        conditions: [...prev.conditions, { type, config: {} }],
      }));
    },
    []
  );

  const removeCondition = useCallback((index: number) => {
    setConditionGroup((prev) => ({
      ...prev,
      conditions: prev.conditions.filter((_, i) => i !== index),
    }));
  }, []);

  const updateConditionConfig = useCallback(
    (index: number, key: string, value: string, condType: string) => {
      setConditionGroup((prev) => {
        const next = { ...prev, conditions: [...prev.conditions] };
        const cond = { ...next.conditions[index] };
        cond.config = { ...cond.config, [key]: displayToConfig(value, key, condType) };
        next.conditions[index] = cond;
        return next;
      });
    },
    []
  );

  const addAction = useCallback((type: string) => {
    setActionItems((prev) => [...prev, { type, config: {} }]);
  }, []);

  const removeAction = useCallback((index: number) => {
    setActionItems((prev) => prev.filter((_, i) => i !== index));
  }, []);

  const updateActionConfig = useCallback(
    (index: number, key: string, value: string, actType: string) => {
      setActionItems((prev) => {
        const next = [...prev];
        const action = { ...next[index] };
        action.config = { ...action.config, [key]: displayToConfig(value, key, actType) };
        next[index] = action;
        return next;
      });
    },
    []
  );

  const updateTriggerField = useCallback(
    (key: string, value: unknown) => {
      setTriggerConfig((prev) => {
        const next = { ...prev };
        if (value === "" || value === undefined) {
          delete next[key];
        } else {
          next[key] = value;
        }
        return next;
      });
    },
    []
  );

  const updateEntryFilter = useCallback(
    (key: string, value: unknown) => {
      setTriggerConfig((prev) => {
        const ef = { ...((prev.entry_filter as Record<string, unknown>) ?? {}) };
        if (value === "" || value === undefined || (Array.isArray(value) && value.length === 0)) {
          delete ef[key];
        } else {
          ef[key] = value;
        }
        return { ...prev, entry_filter: Object.keys(ef).length > 0 ? ef : undefined } as Record<string, unknown>;
      });
    },
    []
  );

  const toggleJsonTrigger = () => {
    if (!showJsonTrigger) {
      setJsonTrigger(JSON.stringify(triggerConfig, null, 2));
    } else {
      try {
        const parsed = JSON.parse(jsonTrigger);
        setTriggerConfig(parsed);
      } catch {
        /* keep visual as-is */
      }
    }
    setShowJsonTrigger((v) => !v);
  };

  const toggleJsonConditions = () => {
    if (!showJsonConditions) {
      // Sync visual → JSON
      const obj =
        conditionGroup.conditions.length > 0
          ? { operator: conditionGroup.operator, conditions: conditionGroup.conditions }
          : {};
      setJsonConditions(JSON.stringify(obj, null, 2));
    } else {
      // Sync JSON → visual
      try {
        const parsed = JSON.parse(jsonConditions);
        setConditionGroup(parseConditions(parsed));
      } catch {
        /* keep visual as-is */
      }
    }
    setShowJsonConditions((v) => !v);
  };

  const toggleJsonActions = () => {
    if (!showJsonActions) {
      setJsonActions(JSON.stringify(actionItems, null, 2));
    } else {
      try {
        const parsed = JSON.parse(jsonActions);
        setActionItems(parseActions(parsed));
      } catch {
        /* keep visual as-is */
      }
    }
    setShowJsonActions((v) => !v);
  };

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <button onClick={onClose} className={styles.backBtn}>
          &larr; Back
        </button>
        <h1>{rule ? "Edit Rule" : "New Automation Rule"}</h1>
        <button
          onClick={handleSave}
          className={styles.saveBtn}
          disabled={createRule.isPending || updateRule.isPending}
        >
          {createRule.isPending || updateRule.isPending ? "Saving..." : "Save"}
        </button>
      </div>

      {error && <div className={styles.error}>{error}</div>}

      <div className={styles.form}>
        <div className={styles.field}>
          <label>Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g., Extract TTPs from Security Advisories"
          />
        </div>

        <div className={styles.field}>
          <label>Description</label>
          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional description"
          />
        </div>

        <div className={styles.field}>
          <label>Labels</label>
          <input
            type="text"
            value={labelsText}
            onChange={(e) => setLabelsText(e.target.value)}
            placeholder="e.g., triage, alerting, extraction"
          />
          <span className={styles.hint}>Comma-separated labels for organizing rules</span>
        </div>

        <div className={styles.columns}>
          {/* WHEN column */}
          <div className={styles.column}>
            <div className={styles.columnHeader}>
              <h3>WHEN (Trigger)</h3>
              <button
                onClick={toggleJsonTrigger}
                className={styles.toggleBtn}
                title={showJsonTrigger ? "Switch to visual editor" : "Switch to JSON editor"}
              >
                {showJsonTrigger ? "Visual" : "JSON"}
              </button>
            </div>
            <select
              value={triggerType}
              onChange={(e) => {
                setTriggerType(e.target.value);
                setTriggerConfig({});
              }}
              className={styles.select}
            >
              {TRIGGER_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>

            {showJsonTrigger ? (
              <textarea
                value={jsonTrigger}
                onChange={(e) => setJsonTrigger(e.target.value)}
                rows={6}
                className={styles.textarea}
              />
            ) : (
              <>
                <div className={styles.itemField}>
                  <label>Execution Mode</label>
                  <select
                    value={(triggerConfig.execution_mode as string) ?? "per_entry"}
                    onChange={(e) => updateTriggerField("execution_mode", e.target.value)}
                  >
                    <option value="per_entry">Per entry — actions run on each entry individually</option>
                    <option value="batch">Batch — all entries processed together (digest/briefing)</option>
                  </select>
                  <span className={styles.hint}>
                    {(triggerConfig.execution_mode as string) === "batch"
                      ? "AI tasks receive all entries at once. Notifications send one message."
                      : "Each matching entry triggers the full action chain separately."}
                  </span>
                </div>

                <div className={styles.itemField}>
                  <label>Max Entries</label>
                  <input
                    type="number"
                    value={(triggerConfig.max_entries as number) ?? 50}
                    onChange={(e) => {
                      const val = parseInt(e.target.value, 10);
                      updateTriggerField(
                        "max_entries",
                        isNaN(val) ? undefined : Math.min(Math.max(val, 1), 500),
                      );
                    }}
                    min={1}
                    max={500}
                  />
                  <span className={styles.hint}>Maximum entries to evaluate (1–500)</span>
                </div>

                {triggerType === "on_schedule" && (
                  <>
                    <div className={styles.itemField}>
                      <label>Cron Expression</label>
                      <input
                        type="text"
                        value={(triggerConfig.cron as string) ?? ""}
                        onChange={(e) => updateTriggerField("cron", e.target.value)}
                        placeholder="0 8 * * 1-5"
                      />
                      <span className={styles.hint}>min hour dom month dow (UTC)</span>
                    </div>
                    <div className={styles.itemField}>
                      <label>Lookback Window</label>
                      <select
                        value={((triggerConfig.entry_filter as Record<string, unknown>)?.since as string) ?? ""}
                        onChange={(e) => updateEntryFilter("since", e.target.value)}
                        className={styles.select}
                      >
                        <option value="">No entry filter (notification only)</option>
                        <option value="-1h">Last 1 hour</option>
                        <option value="-6h">Last 6 hours</option>
                        <option value="-12h">Last 12 hours</option>
                        <option value="-24h">Last 24 hours</option>
                        <option value="-48h">Last 48 hours</option>
                        <option value="-72h">Last 3 days</option>
                        <option value="-168h">Last 7 days</option>
                      </select>
                      <span className={styles.hint}>
                        How far back to scan for entries when the schedule fires
                      </span>
                    </div>
                    {((triggerConfig.entry_filter as Record<string, unknown>)?.since) && (
                      <>
                        <div className={styles.itemField}>
                          <label>Filter by Categories</label>
                          <div className={styles.quickAdd}>
                            {categories.map((cat) => {
                              const selected = ((triggerConfig.entry_filter as Record<string, unknown>)?.category_ids as string[]) ?? [];
                              const isActive = selected.includes(cat.id);
                              return (
                                <button
                                  key={cat.id}
                                  className={isActive ? styles.operatorActive : styles.chipBtn}
                                  onClick={() => {
                                    const next = isActive
                                      ? selected.filter((id) => id !== cat.id)
                                      : [...selected, cat.id];
                                    updateEntryFilter("category_ids", next);
                                  }}
                                >
                                  {cat.name}
                                </button>
                              );
                            })}
                          </div>
                        </div>
                        <div className={styles.itemField}>
                          <label>
                            Filter by Feeds
                            {(() => {
                              const sel = ((triggerConfig.entry_filter as Record<string, unknown>)?.feed_ids as string[]) ?? [];
                              return sel.length > 0 ? ` (${sel.length} selected)` : "";
                            })()}
                          </label>
                          <input
                            type="text"
                            value={feedSearch}
                            onChange={(e) => setFeedSearch(e.target.value)}
                            placeholder="Search feeds..."
                          />
                          <div className={styles.quickAdd} style={{ maxHeight: 200, overflowY: "auto" }}>
                            {(() => {
                              const selected = ((triggerConfig.entry_filter as Record<string, unknown>)?.feed_ids as string[]) ?? [];
                              const query = feedSearch.toLowerCase();
                              const selectedSubs = subscriptions.filter((s) => selected.includes(s.id));
                              const unselectedSubs = subscriptions.filter((s) => !selected.includes(s.id));
                              const filtered = query
                                ? unselectedSubs.filter((s) =>
                                    (s.custom_title ?? s.title).toLowerCase().includes(query)
                                  )
                                : unselectedSubs;
                              return [...selectedSubs, ...filtered].map((sub) => {
                                const isActive = selected.includes(sub.id);
                                return (
                                  <button
                                    key={sub.id}
                                    className={isActive ? styles.operatorActive : styles.chipBtn}
                                    onClick={() => {
                                      const next = isActive
                                        ? selected.filter((id: string) => id !== sub.id)
                                        : [...selected, sub.id];
                                      updateEntryFilter("feed_ids", next);
                                    }}
                                  >
                                    {sub.custom_title ?? sub.title}
                                  </button>
                                );
                              });
                            })()}
                          </div>
                        </div>
                      </>
                    )}
                  </>
                )}

                {triggerType === "on_keyword_match" && (
                  <>
                    <div className={styles.itemField}>
                      <label>Pattern</label>
                      <input
                        type="text"
                        value={(triggerConfig.pattern as string) ?? ""}
                        onChange={(e) => updateTriggerField("pattern", e.target.value)}
                        placeholder="CVE-\\d{4} or ransomware"
                      />
                    </div>
                    <div className={styles.itemField}>
                      <label>
                        <input
                          type="checkbox"
                          checked={(triggerConfig.is_regex as boolean) ?? false}
                          onChange={(e) => updateTriggerField("is_regex", e.target.checked)}
                        />{" "}
                        Use regex
                      </label>
                    </div>
                  </>
                )}

                {triggerType === "on_cve_detected" && (
                  <div className={styles.itemField}>
                    <label>Minimum Severity</label>
                    <select
                      value={(triggerConfig.min_severity as string) ?? ""}
                      onChange={(e) => updateTriggerField("min_severity", e.target.value)}
                      className={styles.select}
                    >
                      <option value="">Any</option>
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                )}

                {(triggerType === "on_new_entry" || triggerType === "on_manual") && (
                  <div className={styles.hint}>No additional configuration needed</div>
                )}
              </>
            )}
          </div>

          {/* IF column */}
          <div className={styles.column}>
            <div className={styles.columnHeader}>
              <h3>IF (Conditions)</h3>
              <button
                onClick={toggleJsonConditions}
                className={styles.toggleBtn}
                title={showJsonConditions ? "Switch to visual editor" : "Switch to JSON editor"}
              >
                {showJsonConditions ? "Visual" : "JSON"}
              </button>
            </div>

            {showJsonConditions ? (
              <textarea
                value={jsonConditions}
                onChange={(e) => setJsonConditions(e.target.value)}
                rows={12}
                className={styles.textarea}
              />
            ) : (
              <>
                <div className={styles.operatorToggle}>
                  <button
                    className={conditionGroup.operator === "AND" ? styles.operatorActive : styles.operatorBtn}
                    onClick={() =>
                      setConditionGroup((prev) => ({ ...prev, operator: "AND" }))
                    }
                  >
                    AND
                  </button>
                  <button
                    className={conditionGroup.operator === "OR" ? styles.operatorActive : styles.operatorBtn}
                    onClick={() =>
                      setConditionGroup((prev) => ({ ...prev, operator: "OR" }))
                    }
                  >
                    OR
                  </button>
                </div>

                <div className={styles.itemList}>
                  {conditionGroup.conditions.map((cond, i) => {
                    const label =
                      CONDITION_TYPES.find((c) => c.value === cond.type)
                        ?.label ?? cond.type;
                    const fields = conditionConfigFields(cond.type);
                    return (
                      <div key={i} className={styles.itemCard}>
                        <div className={styles.itemCardHeader}>
                          <span className={styles.itemLabel}>{label}</span>
                          <button
                            className={styles.removeBtn}
                            onClick={() => removeCondition(i)}
                          >
                            x
                          </button>
                        </div>
                        {fields.map((f) => (
                          <div key={f.key} className={styles.itemField}>
                            <label>{f.label}</label>
                            <input
                              type={f.type ?? "text"}
                              placeholder={f.placeholder}
                              value={configToDisplay(cond.config, f.key)}
                              onChange={(e) =>
                                updateConditionConfig(i, f.key, e.target.value, cond.type)
                              }
                            />
                          </div>
                        ))}
                      </div>
                    );
                  })}
                </div>

                <div className={styles.quickAdd}>
                  {CONDITION_TYPES.map((c) => (
                    <button
                      key={c.value}
                      onClick={() => addCondition(c.value)}
                      className={styles.chipBtn}
                    >
                      + {c.label}
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>

          {/* THEN column */}
          <div className={styles.column}>
            <div className={styles.columnHeader}>
              <h3>THEN (Actions)</h3>
              <button
                onClick={toggleJsonActions}
                className={styles.toggleBtn}
                title={showJsonActions ? "Switch to visual editor" : "Switch to JSON editor"}
              >
                {showJsonActions ? "Visual" : "JSON"}
              </button>
            </div>

            {showJsonActions ? (
              <textarea
                value={jsonActions}
                onChange={(e) => setJsonActions(e.target.value)}
                rows={12}
                className={styles.textarea}
              />
            ) : (
              <>
                <div className={styles.itemList}>
                  {actionItems.map((action, i) => {
                    const label =
                      ACTION_TYPES.find((a) => a.value === action.type)
                        ?.label ?? action.type;
                    const fields = actionConfigFields(action.type, aiTasks);
                    return (
                      <div key={i} className={styles.itemCard}>
                        <div className={styles.itemCardHeader}>
                          <span className={styles.itemLabel}>{label}</span>
                          <button
                            className={styles.removeBtn}
                            onClick={() => removeAction(i)}
                          >
                            x
                          </button>
                        </div>
                        {action.type === "branch" ? (
                          <BranchActionEditor
                            config={action.config}
                            onUpdate={(newConfig) => {
                              setActionItems((prev) => {
                                const next = [...prev];
                                next[i] = { ...next[i], config: newConfig };
                                return next;
                              });
                            }}
                            aiTasks={aiTasks}
                          />
                        ) : (
                          <>
                            {(action.type === "run_webhook" || action.type === "send_notification") &&
                              (() => {
                                const presetType = action.type === "send_notification" ? "notification" : "webhook";
                                const applicable = webhookPresets.filter((p) => p.preset_type === presetType);
                                if (applicable.length === 0) return null;
                                return (
                                  <div className={styles.itemField}>
                                    <label>Load Preset</label>
                                    <select
                                      value=""
                                      onChange={(e) => {
                                        const preset = applicable.find((p) => p.id === e.target.value);
                                        if (!preset) return;
                                        setActionItems((prev) => {
                                          const next = [...prev];
                                          const merged =
                                            action.type === "send_notification"
                                              ? {
                                                  ...action.config,
                                                  platform: preset.config.platform ?? "discord",
                                                  webhook_url: preset.url,
                                                  channel: preset.config.channel ?? "",
                                                  username: preset.config.username ?? "",
                                                  message_template: preset.config.message_template ?? "",
                                                }
                                              : {
                                                  ...action.config,
                                                  url: preset.url,
                                                  payload: preset.payload,
                                                  headers: preset.headers,
                                                };
                                          next[i] = { ...next[i], config: merged };
                                          return next;
                                        });
                                      }}
                                    >
                                      <option value="">Select preset...</option>
                                      {applicable.map((p) => (
                                        <option key={p.id} value={p.id}>
                                          {p.name}
                                        </option>
                                      ))}
                                    </select>
                                  </div>
                                );
                              })()}
                            {fields.map((f) => (
                            <div key={f.key} className={styles.itemField}>
                              <label>{f.label}</label>
                              {f.fieldType === "select" ? (
                                <select
                                  value={configToDisplay(action.config, f.key)}
                                  onChange={(e) =>
                                    updateActionConfig(i, f.key, e.target.value, action.type)
                                  }
                                >
                                  <option value="">Select...</option>
                                  {(f.options ?? []).map((o) => (
                                    <option key={o.value} value={o.value}>
                                      {o.label}
                                    </option>
                                  ))}
                                </select>
                              ) : f.key === "tags" ? (
                                <TagPicker
                                  value={tagArray(action.config)}
                                  onChange={(names) =>
                                    updateActionConfig(i, "tags", names.join(","), action.type)
                                  }
                                />
                              ) : f.multiline ? (
                                <textarea
                                  placeholder={f.placeholder}
                                  value={configToDisplay(action.config, f.key)}
                                  onChange={(e) =>
                                    updateActionConfig(i, f.key, e.target.value, action.type)
                                  }
                                  rows={3}
                                  className={styles.textarea}
                                />
                              ) : (
                                <input
                                  type="text"
                                  placeholder={f.placeholder}
                                  value={configToDisplay(action.config, f.key)}
                                  onChange={(e) =>
                                    updateActionConfig(i, f.key, e.target.value, action.type)
                                  }
                                />
                              )}
                              {f.hint && <span className={styles.hint}>{f.hint}</span>}
                            </div>
                            ))}
                          </>
                        )}
                      </div>
                    );
                  })}
                </div>

                <div className={styles.quickAdd}>
                  {ACTION_TYPES.map((a) => (
                    <button
                      key={a.value}
                      onClick={() => addAction(a.value)}
                      className={styles.chipBtn}
                    >
                      + {a.label}
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
