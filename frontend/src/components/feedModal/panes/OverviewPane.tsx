import { toast } from "sonner";
import {
  useFeedValue,
  useFullSyncFeed,
  useRefreshFeed,
  useUpdateFeed,
} from "@/hooks/useFeeds";
import { formatDateTime } from "@/utils/formatDate";
import { describeHealthWarning, describePauseReason } from "@/utils/feedHealth";
import type { Feed } from "@/api/types";
import { MutedAIUsage } from "./MutedAIUsage";
import styles from "../fields.module.css";

/** "6m ago" / "3h ago" / "2d ago" — the sidebar tooltip's phrasing. */
function ago(iso: string | null): string {
  if (!iso) return "never";
  const minutes = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  if (minutes < 1440) return `${Math.round(minutes / 60)}h ago`;
  return `${Math.round(minutes / 1440)}d ago`;
}

/**
 * What this feed has actually done, before any of the knobs.
 *
 * The old modal showed one fact about a feed's behaviour — `last_error` — and
 * nothing else, so "is this source worth keeping?" was unanswerable from the
 * place you went to change it. The value score and reach already existed on
 * the Engine's feed tables; this brings the one row that concerns this feed.
 */
export function OverviewPane({ feed, isAdmin }: { feed: Feed; isAdmin: boolean }) {
  const value = useFeedValue(feed.id);
  const refresh = useRefreshFeed();
  const fullSync = useFullSyncFeed();
  const updateFeed = useUpdateFeed();

  const v = value.data;
  const healthy = feed.error_count === 0 && !feed.health_warning;

  const verdict = (() => {
    const bits: string[] = [];
    bits.push(feed.is_active ? "Active" : feed.pause_reason ? "Paused by the health check" : "Paused");
    bits.push(`fetched ${ago(feed.last_fetched_at)}`);
    bits.push(
      feed.error_count === 0
        ? "no errors"
        : `${feed.error_count} recent error${feed.error_count === 1 ? "" : "s"}`
    );
    return `${bits.join(", ")}.`;
  })();

  const stats: { value: string; label: string }[] = v?.scored
    ? [
        { value: v.tier ?? "—", label: "Value grade" },
        { value: String(v.articles ?? 0), label: `Articles ${v.days ?? 90}d` },
        { value: String(v.entity_introductions ?? 0), label: "First to report" },
        { value: String(v.correlation_events ?? 0), label: "Links made" },
        { value: String(v.detection_rules ?? 0), label: "Rules found" },
        { value: String(v.pir_matches ?? 0), label: "Requirement hits" },
      ]
    : [];

  const togglePause = () => {
    updateFeed.mutate(
      { feedId: feed.id, data: { is_active: !feed.is_active } },
      {
        onSuccess: () =>
          toast.success(feed.is_active ? "Feed paused" : "Feed resumed"),
      }
    );
  };

  return (
    <div className={styles.stack}>
      <p className={styles.verdict}>
        <span
          className={`${styles.dot} ${
            !feed.is_active ? styles.dotWarn : healthy ? styles.dotOk : styles.dotErr
          }`}
        />
        {verdict}
      </p>

      <MutedAIUsage feed={feed} isAdmin={isAdmin} />

      {value.isLoading && <p className={styles.note}>Working out what this feed has produced…</p>}

      {v?.scored && (
        <>
          <div className={styles.statGrid}>
            {stats.map((s) => (
              <div key={s.label} className={styles.stat}>
                <span className={styles.statValue}>{s.value}</span>
                <span className={styles.statLabel}>{s.label}</span>
              </div>
            ))}
          </div>
          {v.rank != null && (
            <p className={styles.note}>
              {v.rank} of {v.of} feeds by how much intelligence they produce.
              &ldquo;First to report&rdquo; counts entities this feed brought in
              before any other source had them.
            </p>
          )}
        </>
      )}

      {value.data && !value.data.scored && (
        <p className={styles.note}>
          Nothing to grade yet — this feed has not produced any intelligence in
          the last 90 days.
        </p>
      )}

      <div className={styles.actionRow}>
        <button
          type="button"
          className={styles.actionBtn}
          onClick={() =>
            refresh.mutate(feed.id, {
              onSuccess: () => toast.success("Refresh queued"),
            })
          }
          disabled={refresh.isPending}
        >
          {refresh.isPending ? "Queueing…" : "Refresh now"}
        </button>
        {isAdmin && (
          <button
            type="button"
            className={styles.actionBtn}
            onClick={togglePause}
            disabled={updateFeed.isPending}
          >
            {feed.is_active ? "Pause feed" : "Resume feed"}
          </button>
        )}
        {/* Full sync is a GitHub-repo-only endpoint; it 400s on anything else. */}
        {isAdmin && feed.feed_type === "github_repo" && (
          <button
            type="button"
            className={styles.actionBtn}
            onClick={() =>
              fullSync.mutate(feed.id, {
                onSuccess: () => toast.success("Full sync queued"),
              })
            }
            disabled={fullSync.isPending}
          >
            {fullSync.isPending ? "Queueing…" : "Full sync"}
          </button>
        )}
      </div>

      {!feed.is_active && feed.pause_reason && (
        <div className={styles.errorBox}>
          <span className={styles.errorLabel}>Why it is paused</span>
          <span className={styles.errorText}>
            {describePauseReason(feed.pause_reason)}
            {feed.pause_reason.paused_at && `, on ${formatDateTime(feed.pause_reason.paused_at)}`}.
            Resuming clears the streak and tries again.
          </span>
        </div>
      )}

      {feed.is_active && feed.health_warning && (
        <div className={styles.errorBox}>
          <span className={styles.errorLabel}>Not delivering</span>
          <span className={styles.errorText}>
            {describeHealthWarning(feed.health_warning)}. The feed URL has probably
            moved; check the site for its current feed.
          </span>
        </div>
      )}

      {feed.last_error && !feed.pause_reason && (
        <div className={styles.errorBox}>
          <span className={styles.errorLabel}>Last error</span>
          <span className={styles.errorText}>{feed.last_error}</span>
        </div>
      )}

      <div className={styles.field}>
        <span className={styles.sectionLabel}>Last assessed</span>
        <span className={styles.hint}>
          {feed.last_reviewed_at
            ? formatDateTime(feed.last_reviewed_at)
            : "Never rated. The Assessment tab is where you record what you make of it."}
        </span>
      </div>
    </div>
  );
}
