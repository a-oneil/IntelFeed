import { memo, useState } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { useFeeds, useCategories } from "@/hooks/useFeeds";
import { useSavedSearches } from "@/hooks/useSearch";
import { Chip } from "@/components/primitives";
import styles from "./NodeStyles.module.css";

const TRIGGER_TYPES = [
  { value: "on_new_entry", label: "New Entry" },
  { value: "on_entry_scored", label: "Entry Scored (Signal Engine)" },
  { value: "on_schedule", label: "Schedule (Cron)" },
  { value: "on_keyword_match", label: "Keyword Match" },
  { value: "on_cve_detected", label: "CVE Detected" },
  { value: "on_correlation_event", label: "Correlation Event" },
  { value: "on_saved_search_match", label: "Saved Search Match" },
  { value: "on_manual", label: "Manual" },
];

interface TriggerNodeData {
  triggerType: string;
  triggerConfig: Record<string, unknown>;
  onUpdate?: (data: Record<string, unknown>) => void;
  onDelete?: () => void;
  [key: string]: unknown;
}

const LOOKBACK_OPTIONS = [
  { value: "", label: "No entry filter" },
  { value: "-1h", label: "Last 1 hour" },
  { value: "-6h", label: "Last 6 hours" },
  { value: "-12h", label: "Last 12 hours" },
  { value: "-24h", label: "Last 24 hours" },
  { value: "-48h", label: "Last 48 hours" },
  { value: "-168h", label: "Last 7 days" },
];

const CORRELATION_EVENT_TYPES: { key: string; label: string }[] = [
  { key: "new_ttp_for_known_actor", label: "New TTP for known actor" },
  { key: "new_ttp_for_known_malware", label: "New TTP for known malware" },
  { key: "new_malware_for_known_actor", label: "New malware for known actor" },
  { key: "actor_malware_cooccurrence", label: "Actor-malware co-occurrence" },
  { key: "coverage_gap", label: "Detection coverage gap" },
  { key: "exploit_status_change", label: "Exploit status change" },
  { key: "cve_score_change", label: "CVE score change" },
  { key: "new_exploit_discovered", label: "New exploit discovered" },
  { key: "kev_addition", label: "CISA KEV addition" },
  { key: "trending_entity", label: "Trending entity" },
  { key: "feed_stale", label: "Feed stale" },
  { key: "feed_error", label: "Feed error" },
];

interface FeedSub {
  id: string;
  title: string;
  custom_title?: string | null;
}

function FeedChipList({
  subscriptions,
  selectedFeedIds,
  onToggle,
}: {
  subscriptions: FeedSub[];
  selectedFeedIds: string[];
  onToggle: (feedId: string) => void;
}) {
  const [search, setSearch] = useState("");
  const query = search.toLowerCase();

  // Selected feeds always show first, then filter the rest by search
  const selected = subscriptions.filter((s) => selectedFeedIds.includes(s.id));
  const unselected = subscriptions.filter((s) => !selectedFeedIds.includes(s.id));
  const filtered = query
    ? unselected.filter((s) =>
        (s.custom_title ?? s.title).toLowerCase().includes(query)
      )
    : unselected;

  return (
    <>
      <label className={styles.fieldLabel}>
        Feeds {selectedFeedIds.length > 0 && `(${selectedFeedIds.length} selected)`}
      </label>
      <input
        type="text"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search feeds..."
        className={styles.input}
      />
      <div className={styles.chipList} style={{ maxHeight: 200, overflowY: "auto" }}>
        {selected.map((sub) => (
          <Chip
            key={sub.id}
            tone="toned"
            tint="var(--accent)"
            aria-pressed
            onClick={() => onToggle(sub.id)}
          >
            {sub.custom_title ?? sub.title}
          </Chip>
        ))}
        {filtered.map((sub) => (
          <Chip
            key={sub.id}
            className={styles.filterChip}
            aria-pressed={false}
            onClick={() => onToggle(sub.id)}
          >
            {sub.custom_title ?? sub.title}
          </Chip>
        ))}
        {!query && unselected.length > 0 && selected.length === 0 && (
          <span className={styles.hint}>{subscriptions.length} feeds available</span>
        )}
      </div>
    </>
  );
}

export const TriggerNode = memo(function TriggerNode({ data }: NodeProps) {
  const d = data as unknown as TriggerNodeData;
  const { triggerType, triggerConfig, onUpdate } = d;

  const { data: feedsData } = useFeeds();
  const { data: categoriesData } = useCategories();
  const { data: savedSearches = [] } = useSavedSearches();
  const subscriptions = feedsData?.items ?? [];
  const categories = categoriesData ?? [];

  const entryFilter = (triggerConfig?.entry_filter as Record<string, unknown>) ?? {};
  const selectedCatIds = (entryFilter.category_ids as string[]) ?? [];
  const selectedFeedIds = (entryFilter.feed_ids as string[]) ?? [];

  const updateEntryFilter = (key: string, value: unknown) => {
    const ef = { ...entryFilter };
    if (value === "" || value === undefined || (Array.isArray(value) && value.length === 0)) {
      delete ef[key];
    } else {
      ef[key] = value;
    }
    const newConfig = { ...triggerConfig, entry_filter: Object.keys(ef).length > 0 ? ef : undefined };
    onUpdate?.({ triggerConfig: newConfig });
  };

  const toggleArrayItem = (key: string, value: string, current: string[]) => {
    const next = current.includes(value)
      ? current.filter((v) => v !== value)
      : [...current, value];
    updateEntryFilter(key, next);
  };

  return (
    <div className={`${styles.node} ${styles.triggerNode}`}>
      <div className={styles.nodeHeader}>
        <Chip size="sm" tone="toned" tint="var(--node-trigger)" className={styles.badge}>
          WHEN
        </Chip>
        <span className={styles.nodeTitle}>Trigger</span>
      </div>

      <div className={styles.nodeBody}>
        <label className={styles.fieldLabel}>Event</label>
        <select
          value={triggerType}
          onChange={(e) => {
            const next = e.target.value;
            // Saved-search match defaults to batch (digest) mode unless the
            // user explicitly picks something else.
            if (next === "on_saved_search_match" && !triggerConfig?.execution_mode) {
              onUpdate?.({
                triggerType: next,
                triggerConfig: { ...triggerConfig, execution_mode: "batch" },
              });
            } else {
              onUpdate?.({ triggerType: next });
            }
          }}
          className={styles.select}
        >
          {TRIGGER_TYPES.map((t) => (
            <option key={t.value} value={t.value}>
              {t.label}
            </option>
          ))}
        </select>

        <label className={styles.fieldLabel}>Execution Mode</label>
        <select
          value={(triggerConfig?.execution_mode as string) ?? "per_entry"}
          onChange={(e) =>
            onUpdate?.({
              triggerConfig: { ...triggerConfig, execution_mode: e.target.value },
            })
          }
          className={styles.select}
        >
          <option value="per_entry">Per entry — actions run on each entry individually</option>
          <option value="batch">Batch — all entries processed together (digest/briefing)</option>
        </select>
        <span className={styles.hint}>
          {(triggerConfig?.execution_mode as string) === "batch"
            ? "AI tasks receive all entries at once. Notifications send one message."
            : "Each matching entry triggers the full action chain separately."}
        </span>

        <label className={styles.fieldLabel}>Max Entries</label>
        <input
          type="number"
          value={(triggerConfig?.max_entries as number) ?? 50}
          onChange={(e) => {
            const val = parseInt(e.target.value, 10);
            onUpdate?.({
              triggerConfig: {
                ...triggerConfig,
                max_entries: isNaN(val) ? undefined : Math.min(Math.max(val, 1), 500),
              },
            });
          }}
          min={1}
          max={500}
          className={styles.input}
        />
        <span className={styles.hint}>Maximum entries to evaluate (1–500)</span>

        {triggerType === "on_schedule" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Cron Expression</label>
            <input
              type="text"
              value={(triggerConfig?.cron as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  triggerConfig: { ...triggerConfig, cron: e.target.value },
                })
              }
              placeholder="0 8 * * 1-5"
              className={styles.input}
            />
            <span className={styles.hint}>min hour dom month dow (UTC)</span>

            <label className={styles.fieldLabel}>Scan Entries From</label>
            <select
              value={(entryFilter.since as string) ?? ""}
              onChange={(e) => updateEntryFilter("since", e.target.value)}
              className={styles.select}
            >
              {LOOKBACK_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>

            {(entryFilter.since as string) && (
              <>
                <label className={styles.fieldLabel}>Categories</label>
                <div className={styles.chipList}>
                  {categories.map((cat) => {
                    const active = selectedCatIds.includes(cat.id);
                    return (
                      <Chip
                        key={cat.id}
                        tone={active ? "toned" : "default"}
                        tint={active ? "var(--accent)" : undefined}
                        className={active ? undefined : styles.filterChip}
                        aria-pressed={active}
                        onClick={() => toggleArrayItem("category_ids", cat.id, selectedCatIds)}
                      >
                        {cat.name}
                      </Chip>
                    );
                  })}
                  {categories.length === 0 && (
                    <span className={styles.hint}>No categories</span>
                  )}
                </div>

                <FeedChipList
                  subscriptions={subscriptions}
                  selectedFeedIds={selectedFeedIds}
                  onToggle={(feedId) => toggleArrayItem("feed_ids", feedId, selectedFeedIds)}
                />
              </>
            )}
          </div>
        )}

        {triggerType === "on_keyword_match" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Pattern</label>
            <input
              type="text"
              value={(triggerConfig?.pattern as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  triggerConfig: { ...triggerConfig, pattern: e.target.value },
                })
              }
              placeholder="CVE-\d{4} or ransomware"
              className={styles.input}
            />
            <label className={styles.checkLabel}>
              <input
                type="checkbox"
                checked={(triggerConfig?.is_regex as boolean) ?? false}
                onChange={(e) =>
                  onUpdate?.({
                    triggerConfig: { ...triggerConfig, is_regex: e.target.checked },
                  })
                }
              />
              Regex
            </label>
          </div>
        )}

        {triggerType === "on_cve_detected" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Min Severity</label>
            <select
              value={(triggerConfig?.min_severity as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  triggerConfig: { ...triggerConfig, min_severity: e.target.value || undefined },
                })
              }
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

        {triggerType === "on_correlation_event" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Event Types</label>
            <span className={styles.hint}>
              Empty = fires on all event types. Click to toggle.
            </span>
            <div className={styles.chipList}>
              {CORRELATION_EVENT_TYPES.map((type) => {
                const selected = Array.isArray(triggerConfig?.event_types)
                  ? (triggerConfig.event_types as string[])
                  : [];
                const active = selected.includes(type.key);
                return (
                  <Chip
                    key={type.key}
                    tone={active ? "toned" : "default"}
                    tint={active ? "var(--accent)" : undefined}
                    className={active ? undefined : styles.filterChip}
                    aria-pressed={active}
                    onClick={() => {
                      const next = active
                        ? selected.filter((t) => t !== type.key)
                        : [...selected, type.key];
                      onUpdate?.({
                        triggerConfig: {
                          ...triggerConfig,
                          event_types: next.length > 0 ? next : undefined,
                        },
                      });
                    }}
                  >
                    {type.label}
                  </Chip>
                );
              })}
            </div>
          </div>
        )}

        {triggerType === "on_saved_search_match" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Saved Search</label>
            <select
              value={(triggerConfig?.saved_search_id as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  triggerConfig: { ...triggerConfig, saved_search_id: e.target.value },
                })
              }
              className={styles.select}
            >
              <option value="">Select a saved search…</option>
              {savedSearches.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.display_name || s.name}
                </option>
              ))}
            </select>

            <label className={styles.fieldLabel}>Max Matches Per Run</label>
            <input
              type="number"
              value={(triggerConfig?.max_per_run as number) ?? 10}
              onChange={(e) => {
                const val = parseInt(e.target.value, 10);
                onUpdate?.({
                  triggerConfig: {
                    ...triggerConfig,
                    max_per_run: isNaN(val) ? 10 : Math.min(Math.max(val, 1), 100),
                  },
                });
              }}
              min={1}
              max={100}
              className={styles.input}
            />
            <span className={styles.hint}>How many matches to dispatch per cycle (1–100)</span>

            <label className={styles.fieldLabel}>Watermark Floor (seconds)</label>
            <input
              type="number"
              value={(triggerConfig?.watermark_seconds_floor as number) ?? 600}
              onChange={(e) => {
                const val = parseInt(e.target.value, 10);
                onUpdate?.({
                  triggerConfig: {
                    ...triggerConfig,
                    watermark_seconds_floor: isNaN(val) ? 600 : Math.min(Math.max(val, 0), 3600),
                  },
                });
              }}
              min={0}
              max={3600}
              className={styles.input}
            />
            <span className={styles.hint}>
              Earliest entry to consider on each run. Defaults to 600s; raise if your
              feeds backdate published_at heavily.
            </span>
          </div>
        )}
      </div>

      <Handle type="source" position={Position.Right} className={styles.handle} />
    </div>
  );
});
