import { useEffect, useState } from "react";
import type { AITask } from "@/api/types";
import { useSystemSettings, useUpdateSystemSettings } from "@/hooks/useSystemSettings";
import {
  useAIProviders,
  useAITasks,
  useAllTaskAssignments,
  useDeleteAIProvider,
  useUpdateAIProvider,
  useUpdateAITask,
  useUserKeys,
} from "@/hooks/useAI";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { apiErrorInfo } from "@/api/errors";
import { Chip, Segmented } from "@/components/primitives";
import { AsyncStateLoading } from "@/components/AsyncState";
import page from "@/pages/SettingsPage.module.css";
import ai from "./AISettings.module.css";
import styles from "./UserKeysSection.module.css";

type Policy = "off" | "optional" | "required";

const PERSONAL_TYPES = ["claude", "openai_compatible", "ollama"] as const;

/**
 * Where a task's result shows up, from the flags the row already carries.
 * The two surfaces with no flag of their own (the copilot dock, Report
 * Studio) are named by task; everything else follows its category and its
 * reader-panel visibility, so a new task lands in the right bucket.
 */
function whereItRuns(task: AITask): string {
  if (task.category === "chat") return task.name === "copilot" ? "Copilot dock" : "Share page";
  if (task.name.startsWith("report_section")) return "Report Studio";
  if (task.user_provider_locked) {
    return task.category === "extraction" ? "Pipeline" : task.category === "maintenance" ? "Maintenance" : "Shared output";
  }
  if (task.show_in_entry_actions || task.show_in_entity_actions) return "Reader";
  return task.category ? task.category[0].toUpperCase() + task.category.slice(1) : "";
}

function NumberSetting({
  label,
  hint,
  value,
  unit,
  prefix,
  onSave,
}: {
  label: string;
  hint: string;
  value: number;
  unit?: string;
  prefix?: string;
  onSave: (next: number) => Promise<void>;
}) {
  const [text, setText] = useState(String(value));
  const [error, setError] = useState<string | null>(null);
  useEffect(() => setText(String(value)), [value]);
  const commit = async () => {
    const n = Number(text);
    if (!Number.isFinite(n) || n < 0) {
      setError("Enter a number of 0 or more.");
      return;
    }
    if (n === value) return;
    setError(null);
    try {
      await onSave(n);
    } catch (err) {
      setError(apiErrorInfo(err).message);
    }
  };
  return (
    <div className={page.settingRow}>
      <div className={page.settingInfo}>
        <span className={page.settingLabel}>{label}</span>
        <span className={page.settingHint}>
          {hint}
          {error && <span className={styles.error}> {error}</span>}
        </span>
      </div>
      <span className={styles.numInput}>
        {prefix && <span className={styles.muted}>{prefix}</span>}
        <input
          className={`${page.input} ${styles.mono}`}
          value={text}
          aria-label={label}
          onChange={(e) => setText(e.target.value)}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") (e.target as HTMLInputElement).blur();
          }}
        />
        {unit && <span className={styles.muted}>{unit}</span>}
      </span>
    </div>
  );
}

/**
 * AI Configuration → User keys: the admin's side of personal AI keys. The
 * policy, the allowed types, the caps, which tasks may use a personal key,
 * and every key people have added (to disable or delete, never to use).
 */
export function UserKeysSection() {
  const { data: settings, isLoading } = useSystemSettings();
  const updateSettings = useUpdateSystemSettings();
  const { data: tasks } = useAITasks();
  const { data: assignments } = useAllTaskAssignments();
  const { data: providers } = useAIProviders();
  const { data: userKeys } = useUserKeys();
  const updateTask = useUpdateAITask();
  const updateProvider = useUpdateAIProvider();
  const deleteProvider = useDeleteAIProvider();
  const undoableDelete = useUndoableDelete();
  const [taskError, setTaskError] = useState<string | null>(null);

  if (isLoading || !settings) return <AsyncStateLoading label="Loading policy…" compact />;

  const get = (key: string) => settings.settings[key]?.value;
  const allow = Boolean(get("allow_user_ai_providers"));
  const require = Boolean(get("require_user_ai_provider"));
  const policy: Policy = !allow ? "off" : require ? "required" : "optional";
  const types = String(get("user_ai_provider_types") ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const allowPrivate = Boolean(get("user_ai_allow_private_endpoints"));
  const monthly = Number(get("user_ai_default_monthly_usd") ?? 0);
  const daily = Number(get("user_ai_daily_request_cap") ?? 0);
  const allowance = Number(get("site_ai_user_daily_requests") ?? 0);
  const shareLimit = Number(get("share_ai_daily_requests") ?? 0);

  const save = (patch: Record<string, unknown>) => updateSettings.mutateAsync(patch).then(() => undefined);

  const setPolicy = (next: Policy) =>
    save({
      allow_user_ai_providers: next !== "off",
      require_user_ai_provider: next === "required",
    });

  const toggleType = (t: string) => {
    const next = types.includes(t) ? types.filter((x) => x !== t) : [...types, t];
    return save({ user_ai_provider_types: next.join(",") });
  };

  const live = (tasks ?? []).filter((t) => !t.is_deprecated);
  const open = live.filter((t) => t.allows_user_provider).length;
  const siteFor = (task: AITask) => {
    const a = assignments?.[task.id];
    if (!a) return null;
    const p = providers?.find((x) => x.id === a.provider_id);
    return p ? `${p.name} / ${a.model_name}` : a.model_name;
  };

  const policyHint =
    policy === "off"
      ? "Every task runs on your providers. People can't add keys."
      : policy === "optional"
        ? "People may add their own key. Tasks they start use it, and fall back to your providers if their key is missing, failing or over its cap."
        : "People must use their own key for the tasks they start. Without a working one, the task is refused.";

  return (
    <div className={ai.section}>
      <div className={ai.sectionHeader}>
        <h3>Who pays for interactive AI</h3>
      </div>

      <div className={page.settingRow}>
        <div className={page.settingInfo}>
          <span className={page.settingLabel}>User key policy</span>
          <span className={page.settingHint}>{policyHint}</span>
        </div>
        <Segmented<Policy>
          label="User key policy"
          size="sm"
          value={policy}
          onChange={setPolicy}
          options={[
            { value: "off", label: "Off" },
            { value: "optional", label: "Optional" },
            { value: "required", label: "Required" },
          ]}
        />
      </div>

      <div className={page.settingRow}>
        <div className={page.settingInfo}>
          <span className={page.settingLabel}>Allowed provider types</span>
          <span className={page.settingHint}>
            Claude Code can't be added by users. It runs on one CLI session for the whole instance.
          </span>
        </div>
        <span className={styles.chips}>
          {PERSONAL_TYPES.map((t) => {
            const on = types.includes(t);
            return (
              <Chip
                key={t}
                size="sm"
                tone={on ? "toned" : "outline"}
                tint={on ? "var(--success)" : undefined}
                onClick={() => void toggleType(t)}
                title={on ? "Allowed — click to disallow" : "Not allowed — click to allow"}
              >
                {t}
              </Chip>
            );
          })}
          <Chip size="sm" tone="quiet" className={styles.struck} title="One CLI sign-in for the whole instance">
            claude_code
          </Chip>
        </span>
      </div>

      <div className={page.settingRow}>
        <div className={page.settingInfo}>
          <span className={page.settingLabel}>Allow private network endpoints</span>
          <span className={page.settingHint}>
            Lets users point a key at a LAN address such as <span className={styles.mono}>192.168.1.20:11434</span>.
            Leave off on a public instance. The server will call whatever URL users enter.
          </span>
        </div>
        <label className={page.toggle}>
          <input
            type="checkbox"
            checked={allowPrivate}
            aria-label="Allow private network endpoints"
            onChange={(e) => void save({ user_ai_allow_private_endpoints: e.target.checked })}
          />
          <span className={page.toggleSlider} />
        </label>
      </div>

      <NumberSetting
        label="Default monthly cap per user"
        hint="The starting cap on a person's own keys. Users can lower it, not raise it. 0 = no cap."
        value={monthly}
        prefix="$"
        onSave={(n) => save({ user_ai_default_monthly_usd: n })}
      />
      <NumberSetting
        label="Daily request cap per user"
        hint="Counts calls, not dollars, because Ollama and unpriced models report $0 cost. 0 = no cap."
        value={daily}
        onSave={(n) => save({ user_ai_daily_request_cap: Math.round(n) })}
      />
      <NumberSetting
        label="Site-key allowance per user"
        hint="Caps how much of your providers one person can use each day for interactive tasks. This works even with user keys off. 0 = unlimited."
        value={allowance}
        unit="requests / day"
        onSave={(n) => save({ site_ai_user_daily_requests: Math.round(n) })}
      />
      <NumberSetting
        label="Share link daily limit"
        hint="AI questions and tasks one public share link may run each day, always on your providers, never the sharer's key. 0 = unlimited."
        value={shareLimit}
        unit="requests / day"
        onSave={(n) => save({ share_ai_daily_requests: Math.round(n) })}
      />

      <div className={ai.sectionHeader} style={{ marginTop: "1.5rem" }}>
        <h3>Tasks users can route to their own key</h3>
        <Chip size="sm">
          {open} of {live.length} live tasks
        </Chip>
      </div>
      {taskError && <div className={styles.error}>{taskError}</div>}
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Task</th>
              <th>Where it runs</th>
              <th>Site provider</th>
              <th className={styles.right}>User keys</th>
            </tr>
          </thead>
          <tbody>
            {live.map((t) => (
              <tr key={t.id} className={t.user_provider_locked ? styles.dim : ""}>
                <td>{t.display_name}</td>
                <td>{whereItRuns(t)}</td>
                <td className={styles.mono}>{siteFor(t) ?? <span className={styles.muted}>not set</span>}</td>
                <td className={styles.right}>
                  {t.user_provider_locked ? (
                    <span className={styles.lock} title="Writes results the whole instance reads">
                      🔒 Site only
                    </span>
                  ) : (
                    <label className={page.toggle}>
                      <input
                        type="checkbox"
                        checked={t.allows_user_provider}
                        aria-label={t.display_name}
                        onChange={(e) => {
                          setTaskError(null);
                          updateTask.mutate(
                            { taskId: t.id, allows_user_provider: e.target.checked },
                            { onError: (err) => setTaskError(apiErrorInfo(err).message) },
                          );
                        }}
                      />
                      <span className={page.toggleSlider} />
                    </label>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className={styles.footnote}>
        Locked tasks write results that the whole instance reads, such as entity links, briefs and story spines. They
        always run on your providers.
      </p>

      <div className={ai.sectionHeader} style={{ marginTop: "1.5rem" }}>
        <h3>Personal keys on this instance</h3>
        <Chip size="sm">{userKeys?.length ?? 0}</Chip>
      </div>
      <div className={styles.keyList}>
        {(userKeys ?? []).map((k) => (
          <div key={k.id} className={`${styles.key} ${!k.is_active ? styles.keyOff : ""}`}>
            <div className={styles.keyLeft}>
              <span className={styles.owner}>{k.owner_username}</span>
              <span className={styles.keyName}>{k.name}</span>
              <Chip size="sm">{k.provider_type}</Chip>
              {k.base_url && <span className={styles.keyUrl}>{k.base_url.replace(/^https?:\/\//, "")}</span>}
              {!k.is_active && <Chip size="sm" tone="quiet">disabled</Chip>}
            </div>
            <div className={styles.keyActions}>
              <button
                className={page.btnSmall}
                onClick={() => updateProvider.mutate({ id: k.id, is_active: !k.is_active })}
                title="Disable or enable this key without touching it"
              >
                {k.is_active ? "Disable" : "Enable"}
              </button>
              <button
                className={page.btnDangerSmall}
                onClick={() =>
                  undoableDelete({
                    label: `${k.owner_username}'s key "${k.name}"`,
                    key: `ai-provider-${k.id}`,
                    onDelete: () => deleteProvider.mutate(k.id),
                  })
                }
              >
                Delete
              </button>
            </div>
          </div>
        ))}
        {!userKeys?.length && <div className={styles.empty}>Nobody has added a key yet.</div>}
      </div>

      <div className={styles.custody}>
        <b>About custody.</b> User keys are encrypted with this instance's <span className={styles.mono}>ENCRYPTION_KEY</span>.
        As the admin, you could decrypt them. Users are told this when they add a key. You can disable or delete a key
        here, but never test or run one: that would call the person's endpoint with the person's key.
      </div>
    </div>
  );
}

export default UserKeysSection;
