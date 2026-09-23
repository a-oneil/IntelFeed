import { memo } from "react";
import type { GroupItem } from "@/utils/groupEntries";
import type { EntryIntelCounts } from "@/hooks/useEntryIntelBadges";
import { EntryRow } from "./EntryList";
import { Chip } from "./primitives";
import { FeedTypeIcon } from "./FeedTypeIcon";
import { FeedNameMenuButton } from "./FeedNameMenuButton";
import { formatDate } from "@/utils/formatDate";
import styles from "./CVEGroupRow.module.css";
import entryStyles from "./EntryList.module.css";

export const CVEGroupRow = memo(function CVEGroupRow({
  group,
  expanded,
  onToggleExpand,
  selectedEntryId,
  selectedEntryIds,
  bulkMode,
  viewMode,
  onEntryClick,
  onCheckboxClick,
  onMarkRead,
  isMarking = false,
  intelBadges,
  feedIntelMap,
}: {
  group: GroupItem;
  expanded: boolean;
  onToggleExpand: () => void;
  selectedEntryId: string | null;
  selectedEntryIds: Set<string>;
  bulkMode: boolean;
  viewMode: "compact" | "expanded";
  onEntryClick: (entryId: string) => void;
  onCheckboxClick: (flatIndex: number, entryId: string, e: React.MouseEvent) => void;
  onMarkRead?: () => void;
  isMarking?: boolean;
  intelBadges?: Record<string, EntryIntelCounts>;
  feedIntelMap?: Record<string, { mode: string; auto: boolean }>;
}) {
  // Check if any entry in the group is selected (for highlighting)
  const hasSelectedEntry = group.entries.some((e) => e.id === selectedEntryId);
  const allRead = group.entries.every((e) => e.is_read);
  const someChecked = group.entries.some((e) => selectedEntryIds.has(e.id));
  const allChecked = group.entries.every((e) => selectedEntryIds.has(e.id));

  // Use the most recent date from the group (prefer published_at, fall back to fetched_at)
  const dates = group.entries
    .map((e) => e.published_at || e.fetched_at)
    .filter(Boolean)
    .sort();
  const dateDisplay = dates.length > 0 ? formatDate(dates[dates.length - 1], "") : "";

  const handleGroupCheck = (e: React.MouseEvent) => {
    e.stopPropagation();
    for (let i = 0; i < group.entries.length; i++) {
      onCheckboxClick(group.flatIndex + i, group.entries[i].id, e);
    }
  };

  if (expanded) {
    return (
      <div className={styles.expandedGroup}>
        <button
          className={styles.groupCollapseBar}
          onClick={onToggleExpand}
        >
          <span className={styles.collapseIcon}>▼</span>
          <span className={styles.groupLabel}>
            {group.entries.length} CVEs for {group.label}
          </span>
          <span className={styles.collapseHint}>collapse</span>
        </button>
        {group.entries.map((entry, i) => (
          <EntryRow
            key={entry.id}
            entry={entry}
            isSelected={selectedEntryId === entry.id}
            isChecked={selectedEntryIds.has(entry.id)}
            bulkMode={bulkMode}
            viewMode={viewMode}
            onClick={() => onEntryClick(entry.id)}
            onCheck={(e) => onCheckboxClick(group.flatIndex + i, entry.id, e)}
            intelCounts={intelBadges?.[entry.id]}
            intelMode={feedIntelMap?.[entry.feed_id]?.mode}
            autoExtract={feedIntelMap?.[entry.feed_id]?.auto}
          />
        ))}
      </div>
    );
  }

  return (
    <div
      className={`${styles.groupRow} ${allRead ? entryStyles.read : ""} ${
        hasSelectedEntry ? entryStyles.selected : ""
      } ${someChecked ? entryStyles.checked : ""} ${bulkMode ? entryStyles.bulkMode : ""}`}
      onClick={onToggleExpand}
    >
      <div
        className={entryStyles.checkboxWrapper}
        onClick={handleGroupCheck}
      >
        <input
          type="checkbox"
          className={entryStyles.checkbox}
          checked={allChecked}
          ref={(el) => { if (el) el.indeterminate = someChecked && !allChecked; }}
          onChange={() => {}}
          tabIndex={-1}
        />
      </div>
      <div className={styles.groupContent}>
        <div className={styles.groupHeader}>
          <FeedNameMenuButton feedId={group.feedId} className={entryStyles.feedNameBtn}>
            {group.feedType && <FeedTypeIcon type={group.feedType} size={11} />}
            {group.feedTitle}
          </FeedNameMenuButton>
          <span className={entryStyles.date}>{dateDisplay}</span>
        </div>
        <div className={styles.groupTitle}>
          <span className={styles.expandIcon}>▶</span>
          <span className={styles.count}>{group.entries.length}</span>
          <span>new CVEs for <strong>{group.label}</strong></span>
        </div>
        <div className={styles.cveList}>
          {group.cveIds.map((id) => (
            <Chip key={id} className={styles.cveBadge}>{id}</Chip>
          ))}
        </div>
      </div>
      {onMarkRead && (
        <button
          type="button"
          className={styles.clearBtn}
          disabled={isMarking}
          onClick={(e) => {
            e.stopPropagation();
            onMarkRead();
          }}
          title={isMarking ? "Marking…" : "Mark all read & clear"}
          aria-label={isMarking ? "Marking…" : "Mark all read & clear"}
        >
          {isMarking ? (
            <span className={styles.spinner} aria-hidden />
          ) : (
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
              <path d="M3 8.5l3 3 7-7" />
            </svg>
          )}
        </button>
      )}
    </div>
  );
});
