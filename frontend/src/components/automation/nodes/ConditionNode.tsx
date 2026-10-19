import { memo, useMemo, useState } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { useFeeds, useCategories } from "@/hooks/useFeeds";
import { useTags } from "@/hooks/useTags";
import { Chip } from "@/components/primitives";
import styles from "./NodeStyles.module.css";

const CONDITION_TYPES = [
  { value: "feed_matches", label: "Feed Matches" },
  { value: "content_contains", label: "Content Contains" },
  { value: "severity_above", label: "Severity Above" },
  { value: "author_matches", label: "Author Matches" },
  { value: "tag_matches", label: "Tag Matches" },
  { value: "feed_type_matches", label: "Feed Type" },
  { value: "is_read", label: "Is Read" },
  { value: "is_starred", label: "Is Starred" },
  { value: "is_bookmarked", label: "Is Bookmarked" },
  { value: "has_note", label: "Has Note" },
  { value: "priority_score_above", label: "Priority Score Above (Signals)" },
  { value: "has_signal", label: "Has Signal Type" },
  { value: "entity_watchlisted", label: "Watched Entity Mentioned" },
  { value: "has_observable", label: "Has Captured Observable (IOC)" },
];

const FEED_TYPES = [
  { value: "rss", label: "RSS" },
  { value: "youtube", label: "YouTube" },
  { value: "podcast", label: "Podcast" },
  { value: "github_releases", label: "GitHub" },
  { value: "reddit", label: "Reddit" },
  { value: "nvd", label: "NVD" },
];

interface ConditionNodeData {
  conditionType: string;
  config: Record<string, unknown>;
  onUpdate?: (data: Record<string, unknown>) => void;
  onDelete?: () => void;
  [key: string]: unknown;
}

export const ConditionNode = memo(function ConditionNode({
  data,
}: NodeProps) {
  const d = data as unknown as ConditionNodeData;
  const { conditionType, config, onUpdate, onDelete } = d;

  const { data: feedsData } = useFeeds();
  const { data: categoriesData } = useCategories();
  const { data: tagsData } = useTags();

  const subscriptions = feedsData?.items ?? [];
  const categories = categoriesData ?? [];
  const tags = tagsData ?? [];

  const [feedSearch, setFeedSearch] = useState("");

  const sortedFeeds = useMemo(() => {
    const sorted = [...subscriptions].sort((a, b) => {
      const nameA = (a.custom_title ?? a.title ?? "").toLowerCase();
      const nameB = (b.custom_title ?? b.title ?? "").toLowerCase();
      return nameA.localeCompare(nameB);
    });
    if (!feedSearch.trim()) return sorted;
    const q = feedSearch.toLowerCase();
    return sorted.filter((sub) =>
      (sub.custom_title ?? sub.title ?? "").toLowerCase().includes(q)
    );
  }, [subscriptions, feedSearch]);

  const selectedFeedIds = (config?.feed_ids as string[]) ?? [];
  const selectedCategoryIds = (config?.category_ids as string[]) ?? [];
  const selectedTags = (config?.tags as string[]) ?? [];
  const selectedTypes = (config?.types as string[]) ?? [];

  const toggleArrayItem = (
    key: string,
    value: string,
    current: string[]
  ) => {
    const next = current.includes(value)
      ? current.filter((v) => v !== value)
      : [...current, value];
    onUpdate?.({ config: { ...config, [key]: next } });
  };

  return (
    <div className={`${styles.node} ${styles.conditionNode}`}>
      <div className={styles.nodeHeader}>
        <Chip size="sm" tone="toned" tint="var(--node-condition)" className={styles.badge}>
          IF
        </Chip>
        <span className={styles.nodeTitle}>
          {CONDITION_TYPES.find((c) => c.value === conditionType)?.label ??
            conditionType}
        </span>
        {onDelete && (
          <button onClick={onDelete} className={styles.deleteBtn}>
            x
          </button>
        )}
      </div>

      <div className={styles.nodeBody}>
        <label className={styles.fieldLabel}>Type</label>
        <select
          value={conditionType}
          onChange={(e) =>
            onUpdate?.({ conditionType: e.target.value, config: {} })
          }
          className={styles.select}
        >
          {CONDITION_TYPES.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </select>

        {conditionType === "feed_matches" && (
          <>
            <label className={styles.fieldLabel}>Feeds</label>
            <input
              type="text"
              value={feedSearch}
              onChange={(e) => setFeedSearch(e.target.value)}
              placeholder="Search feeds..."
              className={styles.input}
              style={{ marginBottom: "0.25rem" }}
            />
            <div className={styles.chipList}>
              {sortedFeeds.map((sub) => {
                const active = selectedFeedIds.includes(sub.id);
                return (
                  <Chip
                    key={sub.id}
                    tone={active ? "toned" : "default"}
                    tint={active ? "var(--accent)" : undefined}
                    className={active ? undefined : styles.filterChip}
                    aria-pressed={active}
                    onClick={() =>
                      toggleArrayItem("feed_ids", sub.id, selectedFeedIds)
                    }
                  >
                    {sub.custom_title ?? sub.title}
                  </Chip>
                );
              })}
              {subscriptions.length === 0 && (
                <span className={styles.hint}>No feeds found</span>
              )}
              {subscriptions.length > 0 && sortedFeeds.length === 0 && (
                <span className={styles.hint}>No feeds match "{feedSearch}"</span>
              )}
            </div>
            <label className={styles.fieldLabel}>Categories</label>
            <div className={styles.chipList}>
              {categories.map((cat) => {
                const active = selectedCategoryIds.includes(cat.id);
                return (
                  <Chip
                    key={cat.id}
                    tone={active ? "toned" : "default"}
                    tint={active ? "var(--accent)" : undefined}
                    className={active ? undefined : styles.filterChip}
                    aria-pressed={active}
                    onClick={() =>
                      toggleArrayItem(
                        "category_ids",
                        cat.id,
                        selectedCategoryIds
                      )
                    }
                  >
                    {cat.name}
                  </Chip>
                );
              })}
            </div>
          </>
        )}

        {conditionType === "content_contains" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Pattern</label>
            <input
              type="text"
              value={(config?.pattern as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, pattern: e.target.value },
                })
              }
              placeholder="ransomware"
              className={styles.input}
            />
            <label className={styles.checkLabel}>
              <input
                type="checkbox"
                checked={(config?.is_regex as boolean) ?? false}
                onChange={(e) =>
                  onUpdate?.({
                    config: { ...config, is_regex: e.target.checked },
                  })
                }
              />
              Regex
            </label>
          </div>
        )}

        {conditionType === "severity_above" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Min CVSS Score</label>
            <input
              type="number"
              min={0}
              max={10}
              step={0.1}
              value={(config?.min_cvss as number) ?? 7.0}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, min_cvss: parseFloat(e.target.value) || 0 },
                })
              }
              className={styles.input}
            />
          </div>
        )}

        {conditionType === "author_matches" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Authors (comma-separated)</label>
            <input
              type="text"
              value={((config?.authors as string[]) ?? []).join(", ")}
              onChange={(e) =>
                onUpdate?.({
                  config: {
                    ...config,
                    authors: e.target.value
                      .split(",")
                      .map((s) => s.trim())
                      .filter(Boolean),
                  },
                })
              }
              placeholder="CISA, Microsoft"
              className={styles.input}
            />
          </div>
        )}

        {conditionType === "tag_matches" && (
          <>
            <label className={styles.fieldLabel}>Tags</label>
            <div className={styles.chipList}>
              {tags.map((tag) => {
                const active = selectedTags.includes(tag.name);
                return (
                  <Chip
                    key={tag.id}
                    tone={active ? "toned" : "default"}
                    tint={active ? "var(--accent)" : undefined}
                    className={active ? undefined : styles.filterChip}
                    aria-pressed={active}
                    onClick={() =>
                      toggleArrayItem("tags", tag.name, selectedTags)
                    }
                  >
                    {tag.name}
                  </Chip>
                );
              })}
              {tags.length === 0 && (
                <span className={styles.hint}>No tags found</span>
              )}
            </div>
          </>
        )}

        {conditionType === "feed_type_matches" && (
          <>
            <label className={styles.fieldLabel}>Feed Types</label>
            <div className={styles.chipList}>
              {FEED_TYPES.map((ft) => {
                const active = selectedTypes.includes(ft.value);
                return (
                  <Chip
                    key={ft.value}
                    tone={active ? "toned" : "default"}
                    tint={active ? "var(--accent)" : undefined}
                    className={active ? undefined : styles.filterChip}
                    aria-pressed={active}
                    onClick={() =>
                      toggleArrayItem("types", ft.value, selectedTypes)
                    }
                  >
                    {ft.label}
                  </Chip>
                );
              })}
            </div>
          </>
        )}

        {conditionType === "priority_score_above" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Min priority score (0–10)</label>
            <input
              type="number"
              min={0}
              max={10}
              step={0.1}
              value={(config?.min as number) ?? 1.0}
              onChange={(e) =>
                onUpdate?.({
                  config: { ...config, min: parseFloat(e.target.value) || 0 },
                })
              }
              placeholder="2.0"
              className={styles.input}
            />
          </div>
        )}

        {conditionType === "has_signal" && (
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>
              Signal types (comma-separated, empty = any)
            </label>
            <input
              type="text"
              value={((config?.types as string[]) ?? []).join(", ")}
              onChange={(e) =>
                onUpdate?.({
                  config: {
                    ...config,
                    types: e.target.value
                      .split(",")
                      .map((s) => s.trim())
                      .filter(Boolean),
                  },
                })
              }
              placeholder="novel_entity, kev_added, under_reported"
              className={styles.input}
            />
          </div>
        )}

        {conditionType === "has_observable" && (
          <div className={styles.fieldGroup}>
            <span className={styles.hint}>
              Entry carries an observable a reporting door captured (blocklist feeds excluded)
            </span>
            <label className={styles.fieldLabel}>Kinds (comma-separated, blank = any)</label>
            <input
              type="text"
              value={(config?.kinds as string) ?? ""}
              onChange={(e) => onUpdate?.({ config: { ...config, kinds: e.target.value || undefined } })}
              placeholder="ipv4, domain, sha256, cmdline"
              className={styles.input}
            />
            <label className={styles.fieldLabel}>Roles (comma-separated, blank = any)</label>
            <input
              type="text"
              value={(config?.roles as string) ?? ""}
              onChange={(e) => onUpdate?.({ config: { ...config, roles: e.target.value || undefined } })}
              placeholder="c2, delivery, persistence"
              className={styles.input}
            />
            <label className={styles.fieldLabel}>Minimum confidence (0–1, blank = any)</label>
            <input
              type="number"
              min={0}
              max={1}
              step={0.05}
              value={(config?.min_confidence as string | number) ?? ""}
              onChange={(e) =>
                onUpdate?.({ config: { ...config, min_confidence: e.target.value || undefined } })
              }
              placeholder="0.6"
              className={styles.input}
            />
            <label className={styles.checkLabel}>
              <input
                type="checkbox"
                checked={String(config?.exclude_infra_tagged ?? "true") !== "false"}
                onChange={(e) =>
                  onUpdate?.({
                    config: { ...config, exclude_infra_tagged: e.target.checked ? "true" : "false" },
                  })
                }
              />
              Ignore dual-use infrastructure (VPN / proxy / Tor / shared hosting)
            </label>
          </div>
        )}

        {conditionType === "entity_watchlisted" && (
          <div className={styles.fieldGroup}>
            <span className={styles.hint}>
              Matches entries linking an entity on your watchlist
            </span>
          </div>
        )}

        {(conditionType === "is_read" || conditionType === "is_starred" ||
          conditionType === "is_bookmarked" || conditionType === "has_note") && (
          <div className={styles.fieldGroup}>
            <span className={styles.hint}>No configuration needed</span>
          </div>
        )}
      </div>

      <Handle type="target" position={Position.Left} className={styles.handle} />
      <Handle type="source" position={Position.Right} className={styles.handle} />
    </div>
  );
});
