import type { DetectionRule, DetectionRuleVersion, VersionDiff } from "@/api/types";
import type { CommitTimeline } from "@/hooks/useDetectionRules";
import { formatDateTime } from "@/utils/formatDate";
import { DiffView, parseUnifiedDiff } from "./DiffView";
import { RuleCompare } from "./RuleCompare";
import bench from "./bench.module.css";
import styles from "./RuleHistoryPanel.module.css";

interface RuleHistoryPanelProps {
  rule?: DetectionRule;
  versions?: DetectionRuleVersion[];
  /** Upstream commits, for a rule mirrored from a git repo. */
  commitTimeline?: CommitTimeline;
  viewingVersion: string | null;
  diffVersion: number | null;
  diff?: VersionDiff;
  diffPending: boolean;
  onView: (versionId: string) => void;
  onDiff: (versionNumber: number) => void;
  onRollback: (versionId: string) => void;
  /** A near-duplicate being compared against the buffer, shown in place of the timeline. */
  compareRuleId: string | null;
  currentContent: string;
  onCloseCompare: () => void;
}

type Row =
  | { kind: "version"; at: string; version: DetectionRuleVersion }
  | { kind: "upstream"; at: string; commit: CommitTimeline["commits"][number]; imported: boolean }
  | { kind: "import"; at: string };

/**
 * One timeline, newest first: the versions saved here and the commits the
 * upstream repo made to the same file. Local versions diff and roll back as
 * before; upstream rows say what changed and link to the commit. The sync
 * snapshots the body it replaces as a version, so an upstream change has a
 * local version right beside it to diff against.
 */
export function RuleHistoryPanel({
  rule,
  versions,
  commitTimeline,
  viewingVersion,
  diffVersion,
  diff,
  diffPending,
  onView,
  onDiff,
  onRollback,
  compareRuleId,
  currentContent,
  onCloseCompare,
}: RuleHistoryPanelProps) {
  if (compareRuleId) {
    return (
      <>
        <div className={bench.railLabel}>
          Compare
          <b>
            <button type="button" className={bench.btn} onClick={onCloseCompare}>← Back to history</button>
          </b>
        </div>
        <RuleCompare otherRuleId={compareRuleId} currentContent={currentContent} />
      </>
    );
  }

  const commits = commitTimeline?.commits ?? [];
  const repo = commitTimeline?.owner && commitTimeline?.repo ? `${commitTimeline.owner}/${commitTimeline.repo}` : rule?.source_repo;
  // Two date sources, two offset spellings ("Z" vs "+00:00"): compare instants.
  const ts = (s: string | null | undefined) => (s ? Date.parse(s) || 0 : 0);
  // The import took the file as it was when the rule was created: the newest
  // commit at or before that moment. Older commits are the file's earlier
  // history, filled in by the upstream backfill. That commit's row carries the
  // v1 mark, so the import isn't a second row for the same sha.
  const imported = rule?.source_repo
    ? commits
        .filter((c) => c.date && ts(c.date) <= ts(rule.created_at))
        .sort((a, b) => ts(b.date) - ts(a.date))[0]
    : undefined;
  const rows: Row[] = [
    ...(versions ?? []).map((v): Row => ({ kind: "version", at: v.created_at, version: v })),
    ...commits
      .filter((c) => c.date)
      .map((c): Row => ({ kind: "upstream", at: c.date as string, commit: c, imported: c.sha === imported?.sha })),
  ];
  // No known commit to pin to: the import is its own row, dated by the import.
  if (rule && rule.source_repo && !imported) {
    rows.push({ kind: "import", at: rule.created_at });
  }
  rows.sort((a, b) => ts(b.at) - ts(a.at));

  if (rows.length === 0) return <div className={bench.empty}>No previous versions yet.</div>;

  return (
    <>
      <div className={bench.railLabel}>
        Timeline
        <b>{repo ? "local versions and upstream commits, newest first" : "newest first"}</b>
      </div>
      {rows.map((row) => {
        if (row.kind === "version") {
          const v = row.version;
          return (
            <div key={v.id} className={`${styles.version} ${viewingVersion === v.id ? styles.active : ""}`}>
              <div className={styles.head}>
                <span className={styles.num}>v{v.version_number}</span>
                <span className={styles.date}>{formatDateTime(v.created_at)}</span>
              </div>
              {v.change_description && <div className={styles.desc}>{v.change_description}</div>}
              <div className={styles.actions}>
                <button type="button" className={bench.btn} onClick={() => onView(v.id)}>View</button>
                <button type="button" className={bench.btn} onClick={() => onDiff(v.version_number)}>Diff</button>
                <button type="button" className={bench.btn} onClick={() => onRollback(v.id)}>Rollback</button>
              </div>
              {diffVersion === v.version_number && (
                diffPending ? (
                  <div className={bench.empty}>Loading diff…</div>
                ) : diff ? (
                  diff.has_changes ? (
                    <DiffView lines={parseUnifiedDiff(diff.diff)} />
                  ) : (
                    <div className={bench.empty}>No changes between versions</div>
                  )
                ) : null
              )}
            </div>
          );
        }
        if (row.kind === "upstream") {
          const c = row.commit;
          return (
            <div key={`c-${c.sha}`} className={`${styles.version} ${styles.upstream}`}>
              <div className={styles.head}>
                {row.imported && <span className={styles.num}>v1</span>}
                <span className={styles.upstreamTag}>upstream</span>
                <span className={styles.changeType}>{c.change_type}</span>
                {c.url ? (
                  <a className={styles.sha} href={c.url} target="_blank" rel="noopener noreferrer">{c.short_sha}</a>
                ) : (
                  <span className={styles.sha}>{c.short_sha}</span>
                )}
                <span className={styles.date}>{c.date ? formatDateTime(c.date) : "—"}</span>
              </div>
              {c.message && <div className={styles.desc}>{c.message.split("\n")[0]}</div>}
              <div className={styles.commitMeta}>
                <span>{row.imported ? `${c.author} · imported from ${repo} as the baseline` : c.author}</span>
                {commitTimeline?.file_path && <span className={styles.filePath}>{commitTimeline.file_path}</span>}
              </div>
              {c.url && (
                <div className={styles.actions}>
                  <a className={bench.btn} href={c.url} target="_blank" rel="noopener noreferrer">Open commit ↗</a>
                </div>
              )}
            </div>
          );
        }
        return (
          <div key="import" className={styles.version}>
            <div className={styles.head}>
              <span className={styles.num}>v1</span>
              <span className={styles.desc}>Imported from {repo}</span>
              <span className={styles.date}>{formatDateTime(row.at)}</span>
            </div>
          </div>
        );
      })}
    </>
  );
}
