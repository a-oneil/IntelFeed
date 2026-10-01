import { memo, useState } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import {
  useAutomationRules,
  useAutomationVariableContexts,
} from "@/hooks/useAutomation";
import { useAITasks } from "@/hooks/useAI";
import {
  useWebhookPresets,
  useCreateWebhookPreset,
} from "@/hooks/useWebhookPresets";
import { Chip } from "@/components/primitives";
import styles from "./NodeStyles.module.css";

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
  { value: "create_intel_report", label: "Create Intel Report" },
  { value: "chain_rule", label: "Chain Rule" },
  { value: "export_to", label: "Export" },
];

const NOTIFICATION_PLATFORMS = [
  { value: "slack", label: "Slack" },
  { value: "discord", label: "Discord" },
  { value: "custom", label: "Custom" },
];

const EXPORT_FORMATS = [
  { value: "csv", label: "CSV" },
  { value: "markdown", label: "Markdown" },
];

interface ActionNodeData {
  actionType: string;
  config: Record<string, unknown>;
  executionMode?: string;
  onUpdate?: (data: Record<string, unknown>) => void;
  onDelete?: () => void;
  [key: string]: unknown;
}

export const ActionNode = memo(function ActionNode({ data }: NodeProps) {
  const d = data as unknown as ActionNodeData;
  const { actionType, config, onUpdate, onDelete } = d;
  const executionMode = d.executionMode ?? "per_entry";

  const { data: rulesData } = useAutomationRules();
  const { data: aiTasks } = useAITasks();
  const { data: varContexts } = useAutomationVariableContexts();
  const presetType = actionType === "send_notification" ? "notification" : "webhook";
  const { data: presetsData } = useWebhookPresets(
    actionType === "run_webhook" || actionType === "send_notification" ? presetType : undefined
  );
  const savePreset = useCreateWebhookPreset();
  const [savingPreset, setSavingPreset] = useState(false);
  const [presetName, setPresetName] = useState("");

  const rules = rulesData?.items ?? [];
  const tasks = aiTasks ?? [];
  const presets = presetsData?.items ?? [];

  return (
    <div className={`${styles.node} ${styles.actionNode}`}>
      <div className={styles.nodeHeader}>
        <Chip size="sm" tone="toned" tint="var(--node-action)" className={styles.badge}>
          THEN
        </Chip>
        <span className={styles.nodeTitle}>
          {ACTION_TYPES.find((a) => a.value === actionType)?.label ??
            actionType}
        </span>
        {onDelete && (
          <button onClick={onDelete} className={styles.deleteBtn}>
            x
          </button>
        )}
      </div>

      <div className={styles.nodeBody}>
        <label className={styles.fieldLabel}>Action</label>
        <select
          value={actionType}
          onChange={(e) =>
            onUpdate?.({ actionType: e.target.value, config: {} })
          }
          className={styles.select}
        >
          {ACTION_TYPES.map((a) => (
            <option key={a.value} value={a.value}>
              {a.label}
            </option>
          ))}
        </select>

        {actionType === "run_ai_task" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Task</label>
            <select
              value={(config?.task_id as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({ config: { ...config, task_id: e.target.value } })
              }
              className={styles.select}
            >
              <option value="">Select task...</option>
              {tasks.map((t) => (
                <option key={t.name} value={t.name}>
                  {t.display_name}
                </option>
              ))}
            </select>
            {(() => {
              const aiCtx = varContexts?.ai_prompt?.[executionMode];
              if (!aiCtx) return null;
              const names = aiCtx.groups.flatMap((g) =>
                g.variables.map((v) => v.name)
              );
              return (
                <span className={styles.hint}>
                  <strong>{aiCtx.label} mode</strong> — prompt variables (Jinja):{" "}
                  {names.map((n) => `{{ ${n} }}`).join(", ")}. {aiCtx.note}
                </span>
              );
            })()}
          </div>
        )}

        {actionType === "use_daily_summary" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Day</label>
            <select
              value={(config?.day as string) ?? "yesterday"}
              onChange={(e) => onUpdate?.({ config: { ...config, day: e.target.value } })}
              className={styles.select}
            >
              <option value="yesterday">Yesterday (complete day)</option>
              <option value="today">Today (partial day so far)</option>
            </select>
            <label className={styles.fieldLabel}>If not cached</label>
            <select
              value={(config?.on_missing as string) ?? "generate"}
              onChange={(e) => onUpdate?.({ config: { ...config, on_missing: e.target.value } })}
              className={styles.select}
            >
              <option value="generate">Generate it (also fills the day divider)</option>
              <option value="skip">Skip — send nothing</option>
            </select>
            <span className={styles.hint}>
              Reuses the shared day-divider briefing instead of generating a second one. Fills{" "}
              {"{ai_summary}"} for a following notification or webhook. Batch rules only.
            </span>
          </div>
        )}

        {actionType === "extract_ttps" && (
          <div className={styles.fieldGroup}>
            <label className={styles.checkLabel}>
              <input
                type="checkbox"
                checked={(config?.use_ai as boolean) ?? true}
                onChange={(e) =>
                  onUpdate?.({
                    config: { ...config, use_ai: e.target.checked },
                  })
                }
              />
              Use AI extraction
            </label>
          </div>
        )}

        {actionType === "generate_detection_rules" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Rule Types (comma-separated)</label>
            <input
              type="text"
              value={((config?.rule_types as string[]) ?? ["sigma"]).join(", ")}
              onChange={(e) =>
                onUpdate?.({
                  config: {
                    ...config,
                    rule_types: e.target.value
                      .split(",")
                      .map((s) => s.trim())
                      .filter(Boolean),
                  },
                })
              }
              placeholder="sigma, splunk_spl, kql"
              className={styles.input}
            />
            <span className={styles.hint}>
              sigma, splunk_spl, crowdstrike_ql, elastic_ql, kql, yara, snort_suricata
            </span>
          </div>
        )}

        {actionType === "add_to_campaign" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Campaign ID</label>
            <input
              type="text"
              value={(config?.campaign_id as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, campaign_id: e.target.value },
                })
              }
              placeholder="uuid"
              className={styles.input}
            />
            <label className={styles.fieldLabel}>Notes (optional)</label>
            <input
              type="text"
              value={(config?.notes as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, notes: e.target.value },
                })
              }
              placeholder="Auto-linked by automation"
              className={styles.input}
            />
            <label className={styles.checkLabel}>
              <input
                type="checkbox"
                checked={Boolean(config?.link_observables)}
                onChange={(e) =>
                  onUpdate?.({
                    config: { ...config, link_observables: e.target.checked || undefined },
                  })
                }
              />
              Also attach the entry's captured observables as campaign entities
            </label>
            {Boolean(config?.link_observables) && (
              <>
                <label className={styles.fieldLabel}>Observable roles (comma-separated, blank = any)</label>
                <input
                  type="text"
                  value={(config?.observable_roles as string) ?? ""}
                  onChange={(e) =>
                    onUpdate?.({
                      config: { ...config, observable_roles: e.target.value || undefined },
                    })
                  }
                  placeholder="c2, delivery, payload"
                  className={styles.input}
                />
              </>
            )}
          </div>
        )}

        {actionType === "create_intel_report" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Report Title</label>
            <input
              type="text"
              value={(config?.title as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, title: e.target.value },
                })
              }
              placeholder="Intel Report: {title}"
              className={styles.input}
            />
            <label className={styles.fieldLabel}>Template</label>
            <select
              value={(config?.template_type as string) ?? "flash_alert"}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, template_type: e.target.value },
                })
              }
              className={styles.select}
            >
              <option value="flash_alert">Flash Alert</option>
              <option value="ioc_bulletin">IOC Bulletin</option>
              <option value="actor_profile">Actor Profile</option>
              <option value="campaign_tracker">Campaign Tracker</option>
              <option value="landscape_report">Landscape Report</option>
              <option value="custom">Custom</option>
            </select>
            <label className={styles.fieldLabel}>TLP Marking</label>
            <select
              value={(config?.tlp_marking as string) ?? "TLP:GREEN"}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, tlp_marking: e.target.value },
                })
              }
              className={styles.select}
            >
              <option value="TLP:WHITE">TLP:WHITE</option>
              <option value="TLP:GREEN">TLP:GREEN</option>
              <option value="TLP:AMBER">TLP:AMBER</option>
              <option value="TLP:RED">TLP:RED</option>
            </select>
          </div>
        )}

        {(actionType === "add_tags" || actionType === "remove_tags") && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Tags (comma-separated)</label>
            <input
              type="text"
              value={((config?.tags as string[]) ?? []).join(", ")}
              onChange={(e) =>
                onUpdate?.({
                  config: {
                    ...config,
                    tags: e.target.value
                      .split(",")
                      .map((s) => s.trim())
                      .filter(Boolean),
                  },
                })
              }
              placeholder="critical, automated"
              className={styles.input}
            />
          </div>
        )}

        {actionType === "send_notification" && (
          <div className={styles.fieldGroup}>
            {presets.length > 0 && (
              <>
                <label className={styles.fieldLabel}>Load Preset</label>
                <select
                  value=""
                  onChange={(e) => {
                    const preset = presets.find((p) => p.id === e.target.value);
                    if (preset) {
                      onUpdate?.({
                        config: {
                          ...config,
                          platform: preset.config.platform ?? "discord",
                          webhook_url: preset.url,
                          channel: preset.config.channel ?? "",
                          username: preset.config.username ?? "",
                          message_template: preset.config.message_template ?? "",
                        },
                      });
                    }
                  }}
                  className={styles.select}
                >
                  <option value="">Select preset...</option>
                  {presets.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>
              </>
            )}
            <label className={styles.fieldLabel}>Platform</label>
            <select
              value={(config?.platform as string) ?? "discord"}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, platform: e.target.value },
                })
              }
              className={styles.select}
            >
              {NOTIFICATION_PLATFORMS.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
            <label className={styles.fieldLabel}>Webhook URL</label>
            <input
              type="text"
              value={(config?.webhook_url as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, webhook_url: e.target.value },
                })
              }
              placeholder="https://hooks.slack.com/..."
              className={styles.input}
            />
            <label className={styles.fieldLabel}>Channel</label>
            <input
              type="text"
              value={(config?.channel as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, channel: e.target.value },
                })
              }
              placeholder="#threat-intel"
              className={styles.input}
            />
            <label className={styles.fieldLabel}>Bot Name</label>
            <input
              type="text"
              value={(config?.username as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, username: e.target.value },
                })
              }
              placeholder="IntelFeed"
              className={styles.input}
            />
            <label className={styles.fieldLabel}>Message Template</label>
            <textarea
              value={(config?.message_template as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, message_template: e.target.value },
                })
              }
              placeholder={"**{title}**\n{url}\n{summary}"}
              className={styles.input}
              rows={3}
            />
            <span className={styles.hint}>
              Notification variables (single-brace, distinct from the AI
              prompt's {"{{ }}"}):{" "}
              {(varContexts?.notification_template ?? []).map((v) => `{${v.name}}`).join(", ")}.
              {" "}
              {"{ai_summary}"} is the output of a preceding Run AI Task action.
            </span>
            {!savingPreset ? (
              <button
                type="button"
                onClick={() => setSavingPreset(true)}
                className={styles.chip}
                style={{ alignSelf: "flex-start", marginTop: "0.25rem" }}
              >
                Save as preset
              </button>
            ) : (
              <div style={{ display: "flex", gap: "0.25rem", marginTop: "0.25rem" }}>
                <input
                  type="text"
                  value={presetName}
                  onChange={(e) => setPresetName(e.target.value)}
                  placeholder="Preset name"
                  className={styles.input}
                  style={{ flex: 1 }}
                  autoFocus
                />
                <button
                  type="button"
                  className={styles.chip}
                  disabled={!presetName.trim() || savePreset.isPending}
                  onClick={() => {
                    savePreset.mutate(
                      {
                        name: presetName.trim(),
                        preset_type: "notification",
                        url: (config?.webhook_url as string) ?? "",
                        config: {
                          platform: (config?.platform as string) ?? "discord",
                          channel: (config?.channel as string) ?? "",
                          username: (config?.username as string) ?? "",
                          message_template: (config?.message_template as string) ?? "",
                        },
                      },
                      {
                        onSuccess: () => {
                          setSavingPreset(false);
                          setPresetName("");
                        },
                      }
                    );
                  }}
                >
                  Save
                </button>
                <button
                  type="button"
                  className={styles.chip}
                  onClick={() => {
                    setSavingPreset(false);
                    setPresetName("");
                  }}
                >
                  Cancel
                </button>
              </div>
            )}
          </div>
        )}

        {actionType === "create_note" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Note Title</label>
            <input
              type="text"
              value={(config?.title as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, title: e.target.value },
                })
              }
              placeholder="Auto-note: {title}"
              className={styles.input}
            />
            <label className={styles.fieldLabel}>Note Content</label>
            <textarea
              value={(config?.content as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, content: e.target.value },
                })
              }
              placeholder={"{summary}"}
              className={styles.input}
              rows={3}
            />
            <span className={styles.hint}>
              Variables: {"{title}"}, {"{url}"}, {"{author}"}, {"{summary}"}, {"{ai_summary}"}
            </span>
          </div>
        )}

        {actionType === "run_webhook" && (
          <div className={styles.fieldGroup}>
            {presets.length > 0 && (
              <>
                <label className={styles.fieldLabel}>Load Preset</label>
                <select
                  value=""
                  onChange={(e) => {
                    const preset = presets.find((p) => p.id === e.target.value);
                    if (preset) {
                      onUpdate?.({
                        config: {
                          ...config,
                          url: preset.url,
                          payload: preset.payload,
                          headers: preset.headers,
                        },
                      });
                    }
                  }}
                  className={styles.select}
                >
                  <option value="">Select preset...</option>
                  {presets.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>
              </>
            )}
            <label className={styles.fieldLabel}>URL</label>
            <input
              type="text"
              value={(config?.url as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({ config: { ...config, url: e.target.value } })
              }
              placeholder="https://..."
              className={styles.input}
            />
            <label className={styles.fieldLabel}>Payload</label>
            <textarea
              value={(config?.payload as string) ?? "{}"}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, payload: e.target.value },
                })
              }
              placeholder="{}"
              className={styles.input}
              rows={4}
              style={{ fontFamily: "monospace", fontSize: "0.6875rem" }}
            />
            <span className={styles.hint}>
              Variables: {"{title}"}, {"{url}"}, {"{author}"}, {"{summary}"}, {"{ai_summary}"}, {"{published_at}"}, {"{feed_name}"}. Leave as {"{ }"} for default entry data.
            </span>
            {!savingPreset ? (
              <button
                type="button"
                onClick={() => setSavingPreset(true)}
                className={styles.chip}
                style={{ alignSelf: "flex-start", marginTop: "0.25rem" }}
              >
                Save as preset
              </button>
            ) : (
              <div style={{ display: "flex", gap: "0.25rem", marginTop: "0.25rem" }}>
                <input
                  type="text"
                  value={presetName}
                  onChange={(e) => setPresetName(e.target.value)}
                  placeholder="Preset name"
                  className={styles.input}
                  style={{ flex: 1 }}
                  autoFocus
                />
                <button
                  type="button"
                  className={styles.chip}
                  disabled={!presetName.trim() || savePreset.isPending}
                  onClick={() => {
                    savePreset.mutate(
                      {
                        name: presetName.trim(),
                        url: (config?.url as string) ?? "",
                        payload: (config?.payload as string) ?? "{}",
                        headers: (config?.headers as Record<string, string>) ?? {},
                      },
                      {
                        onSuccess: () => {
                          setSavingPreset(false);
                          setPresetName("");
                        },
                      }
                    );
                  }}
                >
                  Save
                </button>
                <button
                  type="button"
                  className={styles.chip}
                  onClick={() => {
                    setSavingPreset(false);
                    setPresetName("");
                  }}
                >
                  Cancel
                </button>
              </div>
            )}
          </div>
        )}

        {actionType === "mark_priority" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Priority Level</label>
            <select
              value={(config?.level as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, level: e.target.value },
                })
              }
              className={styles.select}
            >
              <option value="">Select...</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        )}

        {actionType === "chain_rule" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Chain to Rule</label>
            <select
              value={(config?.rule_id as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, rule_id: e.target.value },
                })
              }
              className={styles.select}
            >
              <option value="">Select rule...</option>
              {rules.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </select>
          </div>
        )}

        {actionType === "export_to" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Format</label>
            <select
              value={(config?.format as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, format: e.target.value },
                })
              }
              className={styles.select}
            >
              <option value="">Select format...</option>
              {EXPORT_FORMATS.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </select>
            <label className={styles.fieldLabel}>Destination</label>
            <input
              type="text"
              value={(config?.destination as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, destination: e.target.value },
                })
              }
              placeholder="webhook"
              className={styles.input}
            />
            <label className={styles.fieldLabel}>Webhook URL</label>
            <input
              type="text"
              value={(config?.webhook_url as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, webhook_url: e.target.value },
                })
              }
              placeholder="https://..."
              className={styles.input}
            />
          </div>
        )}
      </div>

      <Handle type="target" position={Position.Left} className={styles.handle} />
      <Handle type="source" position={Position.Right} className={styles.handle} />
    </div>
  );
});
