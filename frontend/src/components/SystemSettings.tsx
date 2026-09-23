import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import {
  useSystemSettings,
  useUpdateSystemSettings,
  useResetSystemSetting,
} from "@/hooks/useSystemSettings";
import type { SettingValue } from "@/hooks/useSystemSettings";
import styles from "./SystemSettings.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";

/** A setting to scroll to and flash, set by a host that navigated here on the
 *  user's behalf (the Engine console's "Find a setting" search). `nonce` makes
 *  picking the same setting twice flash it twice. */
export const SettingsHighlightContext = createContext<{ key: string; nonce: number } | null>(null);

export default function SystemSettings({
  filterGroups,
  filterKeys,
  excludeKeys,
  renderAfterKey,
  hideGroupTitle,
  topSlot,
  flat,
}: {
  filterGroups?: string[];
  /** Render exactly these keys, in this order, as one ungrouped block —
   *  for hosts that own a feature rather than a settings group (a job row
   *  showing the knobs that tune it). Takes precedence over filterGroups. */
  filterKeys?: string[];
  excludeKeys?: string[];
  renderAfterKey?: Record<string, (pendingValue: unknown, meta: SettingValue) => React.ReactNode>;
  hideGroupTitle?: boolean;
  topSlot?: React.ReactNode;
  /** No group card chrome — for hosts (like Engine stage panels) that provide
   *  their own container. */
  flat?: boolean;
} = {}) {
  const { data, isLoading } = useSystemSettings();
  const highlight = useContext(SettingsHighlightContext);
  const updateSettings = useUpdateSystemSettings();
  const resetSetting = useResetSystemSetting();
  const [pendingChanges, setPendingChanges] = useState<
    Record<string, unknown>
  >({});
  const [saving, setSaving] = useState(false);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);

  const handleChange = useCallback((key: string, value: unknown) => {
    setPendingChanges((prev) => ({ ...prev, [key]: value }));
    setSavedMsg(null);
  }, []);

  const handleSave = async () => {
    if (Object.keys(pendingChanges).length === 0) return;
    setSaving(true);
    setSavedMsg(null);
    try {
      await updateSettings.mutateAsync(pendingChanges);
      setPendingChanges({});
      setSavedMsg("Settings saved");
      setTimeout(() => setSavedMsg(null), 3000);
    } catch {
      setSavedMsg("Failed to save settings");
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async (key: string) => {
    try {
      await resetSetting.mutateAsync(key);
      setPendingChanges((prev) => {
        const next = { ...prev };
        delete next[key];
        return next;
      });
    } catch {
      // ignore
    }
  };

  if (isLoading || !data) {
    return <AsyncStateLoading label="Loading system settings…" />;
  }

  const { settings, groups } = data;

  // Key-filtered mode: one synthetic group holding the requested keys in the
  // order the caller listed them.
  const KEY_GROUP = "__keys__";
  const grouped: Record<string, [string, SettingValue][]> = {};
  if (filterKeys) {
    grouped[KEY_GROUP] = filterKeys
      .filter((key) => settings[key] && !excludeKeys?.includes(key))
      .map((key) => [key, settings[key]] as [string, SettingValue]);
  } else {
    for (const [key, meta] of Object.entries(settings)) {
      if (excludeKeys?.includes(key)) continue;
      const group = meta.group || "other";
      (grouped[group] = grouped[group] || []).push([key, meta]);
    }
  }

  // Ordered group keys — filter if a subset was requested
  const allGroupOrder = [
    "security",
    "feeds",
    "feed_value",
    "image_proxy",
    "enrichment",
    "api_keys",
    "ai",
    "extraction",
    "intelligence",
    "autolink",
    "observables",
    "scoring",
    "threads",
    "maintenance",
    "retention",
    "translation",
    "content",
    "plans",
    "rate_limiting",
    "monitoring",
    "backup",
    "public_rss",
  ];
  // A group the backend names but this list doesn't would otherwise render
  // nowhere at all — append the leftovers instead of silently dropping them.
  const knownGroups = new Set(allGroupOrder);
  const groupOrderAll = [
    ...allGroupOrder,
    ...Object.keys(grouped).filter((g) => !knownGroups.has(g)),
  ];
  const groupOrder = filterKeys
    ? [KEY_GROUP]
    : filterGroups
      ? groupOrderAll.filter((g) => filterGroups.includes(g))
      : groupOrderAll;

  const hasPendingChanges = Object.keys(pendingChanges).length > 0;

  return (
    <div className={styles.container}>
      {groupOrder.map((groupKey, idx) => {
        const items = grouped[groupKey];
        if (!items) return null;
        return (
          <div key={groupKey} className={flat ? styles.groupFlat : styles.group}>
            {idx === 0 && topSlot && <div className={styles.topSlot}>{topSlot}</div>}
            {!hideGroupTitle && groupKey !== KEY_GROUP && (
              <h3 className={flat ? styles.groupTitleFlat : styles.groupTitle}>
                {groups[groupKey] || groupKey}
              </h3>
            )}
            <div className={flat ? styles.groupBodyFlat : styles.groupBody}>
              {items.map(([key, meta]) => (
                <React.Fragment key={key}>
                  <SettingRow
                    settingKey={key}
                    meta={meta}
                    highlighted={highlight?.key === key}
                    highlightNonce={highlight?.nonce}
                    pendingValue={pendingChanges[key]}
                    onChange={handleChange}
                    onReset={handleReset}
                  />
                  {renderAfterKey?.[key]?.(pendingChanges[key], meta)}
                </React.Fragment>
              ))}
            </div>
          </div>
        );
      })}

      <div className={styles.saveBar}>
        <button
          className={styles.saveBtn}
          onClick={handleSave}
          disabled={!hasPendingChanges || saving}
        >
          {saving ? "Saving..." : "Save Changes"}
        </button>
        {hasPendingChanges && (
          <button
            className={styles.discardBtn}
            onClick={() => setPendingChanges({})}
          >
            Discard
          </button>
        )}
        {savedMsg && <span className={styles.savedMsg}>{savedMsg}</span>}
      </div>
    </div>
  );
}

function SettingRow({
  settingKey,
  meta,
  pendingValue,
  onChange,
  onReset,
  highlighted,
  highlightNonce,
}: {
  settingKey: string;
  meta: SettingValue;
  pendingValue: unknown;
  onChange: (key: string, value: unknown) => void;
  onReset: (key: string) => void;
  highlighted?: boolean;
  highlightNonce?: number;
}) {
  const rowRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (highlighted) rowRef.current?.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [highlighted, highlightNonce]);

  const rowClass = highlighted ? `${styles.settingRow} ${styles.settingRowHit}` : styles.settingRow;
  const displayValue =
    pendingValue !== undefined ? pendingValue : meta.value;
  const isModified =
    pendingValue !== undefined || meta.source === "database";

  if (meta.is_secret) {
    return (
      <div className={rowClass} ref={rowRef}>
        <div className={styles.settingInfo}>
          <span className={styles.settingLabel}>{meta.label}</span>
          <span className={styles.settingHint}>{meta.description}</span>
        </div>
        <div className={styles.settingControl}>
          <input
            type="password"
            className={styles.input}
            placeholder={meta.is_set ? "••••••••" : "Not configured"}
            value={
              pendingValue !== undefined ? String(pendingValue) : ""
            }
            onChange={(e) => onChange(settingKey, e.target.value)}
          />
          {meta.source === "database" && (
            <button
              className={styles.resetBtn}
              onClick={() => onReset(settingKey)}
              title="Reset to default"
            >
              Reset
            </button>
          )}
          {meta.is_set && pendingValue === undefined && (
            <span className={styles.sourceTag}>
              {meta.source}
            </span>
          )}
        </div>
      </div>
    );
  }

  // Enumerated select (registry entries with an options list)
  if (meta.options && meta.options.length > 0) {
    return (
      <div className={rowClass} ref={rowRef}>
        <div className={styles.settingInfo}>
          <span className={styles.settingLabel}>{meta.label}</span>
          <span className={styles.settingHint}>{meta.description}</span>
        </div>
        <div className={styles.settingControl}>
          <select
            className={styles.input}
            value={displayValue !== null && displayValue !== undefined ? String(displayValue) : ""}
            onChange={(e) => onChange(settingKey, e.target.value)}
          >
            {meta.options.map((opt) => (
              <option key={opt} value={opt}>
                {opt.replace(/_/g, " ")}
              </option>
            ))}
          </select>
          {isModified && meta.source === "database" && pendingValue === undefined && (
            <button
              className={styles.resetBtn}
              onClick={() => onReset(settingKey)}
              title="Reset to default"
            >
              Reset
            </button>
          )}
          {meta.source === "database" && pendingValue === undefined && (
            <span className={styles.sourceTag}>customized</span>
          )}
        </div>
      </div>
    );
  }

  // Boolean toggle
  if (typeof meta.value === "boolean" || typeof meta.env_default === "boolean") {
    const checked = typeof displayValue === "boolean" ? displayValue : Boolean(displayValue);
    return (
      <div className={rowClass} ref={rowRef}>
        <div className={styles.settingInfo}>
          <span className={styles.settingLabel}>{meta.label}</span>
          <span className={styles.settingHint}>{meta.description}</span>
        </div>
        <div className={styles.settingControl}>
          <label className={styles.toggle}>
            <input
              type="checkbox"
              checked={checked}
              onChange={(e) => onChange(settingKey, e.target.checked)}
            />
            <span className={styles.toggleSlider} />
          </label>
          {isModified && meta.source === "database" && pendingValue === undefined && (
            <button
              className={styles.resetBtn}
              onClick={() => onReset(settingKey)}
              title="Reset to default"
            >
              Reset
            </button>
          )}
        </div>
      </div>
    );
  }

  // Number input
  if (typeof meta.value === "number" || typeof meta.env_default === "number") {
    return (
      <div className={rowClass} ref={rowRef}>
        <div className={styles.settingInfo}>
          <span className={styles.settingLabel}>{meta.label}</span>
          <span className={styles.settingHint}>{meta.description}</span>
        </div>
        <div className={styles.settingControl}>
          <input
            type="number"
            className={styles.input}
            value={displayValue !== null && displayValue !== undefined ? String(displayValue) : ""}
            onChange={(e) => {
              const val = e.target.value;
              // Determine if float or int based on env_default
              const isFloat = typeof meta.env_default === "number" && !Number.isInteger(meta.env_default);
              onChange(settingKey, val === "" ? null : isFloat ? parseFloat(val) : parseInt(val, 10));
            }}
            step={typeof meta.env_default === "number" && !Number.isInteger(meta.env_default) ? "0.01" : "1"}
          />
          {isModified && meta.source === "database" && pendingValue === undefined && (
            <button
              className={styles.resetBtn}
              onClick={() => onReset(settingKey)}
              title="Reset to default"
            >
              Reset
            </button>
          )}
          {meta.source === "database" && pendingValue === undefined && (
            <span className={styles.sourceTag}>customized</span>
          )}
        </div>
      </div>
    );
  }

  // Long text (false positive names)
  const isLongText = typeof displayValue === "string" && (displayValue as string).length > 100;

  if (isLongText) {
    return (
      <div className={rowClass} ref={rowRef}>
        <div className={styles.settingInfo}>
          <span className={styles.settingLabel}>{meta.label}</span>
          <span className={styles.settingHint}>{meta.description}</span>
        </div>
        <div className={styles.settingControlFull}>
          <textarea
            className={styles.textarea}
            value={displayValue !== null && displayValue !== undefined ? String(displayValue) : ""}
            onChange={(e) => onChange(settingKey, e.target.value)}
            rows={4}
          />
          {isModified && meta.source === "database" && pendingValue === undefined && (
            <button
              className={styles.resetBtn}
              onClick={() => onReset(settingKey)}
              title="Reset to default"
            >
              Reset
            </button>
          )}
        </div>
      </div>
    );
  }

  // Default: text input
  return (
    <div className={rowClass} ref={rowRef}>
      <div className={styles.settingInfo}>
        <span className={styles.settingLabel}>{meta.label}</span>
        <span className={styles.settingHint}>{meta.description}</span>
      </div>
      <div className={styles.settingControl}>
        <input
          type="text"
          className={styles.input}
          value={displayValue !== null && displayValue !== undefined ? String(displayValue) : ""}
          onChange={(e) => onChange(settingKey, e.target.value)}
        />
        {isModified && meta.source === "database" && pendingValue === undefined && (
          <button
            className={styles.resetBtn}
            onClick={() => onReset(settingKey)}
            title="Reset to default"
          >
            Reset
          </button>
        )}
        {meta.source === "database" && pendingValue === undefined && (
          <span className={styles.sourceTag}>customized</span>
        )}
      </div>
    </div>
  );
}
