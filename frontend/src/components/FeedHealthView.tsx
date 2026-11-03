import { useState, useMemo } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import { useFeedHealth, useFeedValueScores } from "@/hooks/useAnalytics";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { formatDate } from "@/utils/formatDate";
import { describeHealthWarning } from "@/utils/feedHealth";
import type { FeedHealthFeed, FeedValueScore } from "@/api/types";
import { ReliabilityBadge } from "./ReliabilityBadge";
import { FeedSubscribersPanel } from "./FeedSubscribersPanel";
import styles from "./FeedHealthView.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";

/**
 * How many analysts a listed feed actually reaches, and a way to change that.
 *
 * `reach` is only sent to admins, so a non-admin renders nothing here and the
 * column collapses — a broken feed's blast radius is an admin's question.
 */
function ReachCell({ feed }: { feed: FeedHealthFeed }) {
  const [open, setOpen] = useState(false);
  if (!feed.reach) return <span className={styles.reachCol} />;

  const { subscriber_count, muted_count } = feed.reach;
  return (
    <span className={styles.reachCol}>
      <button
        className={styles.reachBtn}
        onClick={() => setOpen((v) => !v)}
        title={
          subscriber_count === 0
            ? "No readers — manage subscribers"
            : feed.reach.subscribers
                .map((s) => (s.is_muted ? `${s.username} (muted)` : s.username))
                .join(", ")
        }
        aria-expanded={open}
      >
        {subscriber_count === 0 ? (
          <span className={styles.reachNone}>none</span>
        ) : (
          <>
            {subscriber_count}
            {muted_count > 0 && (
              <span className={styles.reachMuted}> ({muted_count} muted)</span>
            )}
          </>
        )}
      </button>
      {open && (
        <div className={styles.reachPopover}>
          <FeedSubscribersPanel feedId={feed.id} feedTitle={feed.title} />
        </div>
      )}
    </span>
  );
}

type Tab = "health" | "value";

type SortKey =
  | "score"
  | "articles"
  | "unique_entities"
  | "entity_introductions"
  | "correlation_events"
  | "detection_rules"
  | "pir_matches"
;

const TIER_CLASS: Record<string, string> = {
  S: styles.tierS,
  A: styles.tierA,
  B: styles.tierB,
  C: styles.tierC,
  D: styles.tierD,
};

function DimensionBar({ value }: { value: number }) {
  const cls =
    value >= 60
      ? styles.dimBarFillHigh
      : value >= 30
        ? styles.dimBarFillMid
        : styles.dimBarFillLow;
  return (
    <span className={styles.dimBar}>
      <span className={styles.dimBarTrack}>
        <span
          className={`${styles.dimBarFill} ${cls}`}
          style={{ width: `${Math.min(value, 100)}%` }}
        />
      </span>
      <span className={styles.dimValue}>{value}</span>
    </span>
  );
}

const VALUE_COLUMNS: { key: SortKey; label: string; title: string }[] = [
  { key: "score", label: "Score", title: "Composite value score (0-100)" },
  { key: "articles", label: "Articles", title: "Total articles in time window" },
  { key: "unique_entities", label: "Entities", title: "Unique entities (actors, malware, CVEs, TTPs)" },
  { key: "entity_introductions", label: "Intros", title: "Entities first discovered via this feed" },
  { key: "correlation_events", label: "Correlations", title: "Correlation events triggered" },
  { key: "detection_rules", label: "Rules", title: "Detection rules generated from this feed" },
  { key: "pir_matches", label: "PIR", title: "Priority intelligence requirement matches" },
];

export function FeedHealthView({
  embedded = false,
}: {
  /** Engine-console skin: flat stats, console-style tabs and section labels. */
  embedded?: boolean;
} = {}) {
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>("health");
  const [staleDays, setStaleDays] = useState(7);
  const [valueDays, setValueDays] = useState(90);
  const [sortKey, setSortKey] = useState<SortKey>("score");
  const [sortAsc, setSortAsc] = useState(false);
  const [showReview, setShowReview] = useState(false);

  const { data: healthData, isLoading: healthLoading } = useFeedHealth(staleDays);
  const { data: valueData, isLoading: valueLoading } = useFeedValueScores(valueDays);

  const undoableDelete = useUndoableDelete();
  // Pool-level pause/resume (admin): with per-user subscriptions on, the PUT
  // is_active toggle only writes the caller's own pause, so it neither stopped
  // an erroring feed's polling nor brought a paused feed back for everyone.
  const invalidateFeedState = () => {
    queryClient.invalidateQueries({ queryKey: ["feed-health"] });
    queryClient.invalidateQueries({ queryKey: ["feeds"] });
    queryClient.invalidateQueries({ queryKey: ["analytics", "feed-value"] });
  };
  const resumeFeed = useMutation({
    mutationFn: async (feedId: string) => (await api.post(`/feeds/${feedId}/resume`)).data,
    onSuccess: invalidateFeedState,
  });
  const pauseFeed = useMutation({
    mutationFn: async (feedId: string) => (await api.post(`/feeds/${feedId}/pause`)).data,
    onSuccess: invalidateFeedState,
  });
  const togglePending = pauseFeed.isPending || resumeFeed.isPending;
  // Remove for everyone: DELETE /feeds/{id} only unsubscribes the caller, so a
  // dead feed stayed on every other reader's list. Entries are kept.
  const removeFeed = useMutation({
    mutationFn: async (feedId: string) => (await api.post(`/feeds/${feedId}/remove`)).data,
    onSuccess: invalidateFeedState,
  });

  const handleRemove = (feedId: string, title: string) => {
    undoableDelete({
      label: `Feed "${title}"`,
      key: `feed-${feedId}`,
      onDelete: () => removeFeed.mutate(feedId),
    });
  };

  const toggleActive = (feedId: string, currentlyActive: boolean) => {
    (currentlyActive ? pauseFeed : resumeFeed).mutate(feedId);
  };

  const pauseReviewCandidate = (feedId: string) => {
    pauseFeed.mutate(feedId);
  };

  const sortedFeeds = useMemo(() => {
    if (!valueData?.feeds) return [];
    const arr = [...valueData.feeds];
    arr.sort((a, b) => {
      const av = a[sortKey] as number;
      const bv = b[sortKey] as number;
      return sortAsc ? av - bv : bv - av;
    });
    return arr;
  }, [valueData, sortKey, sortAsc]);

  const handleSort = (key: SortKey) => {
    if (key === sortKey) {
      setSortAsc(!sortAsc);
    } else {
      setSortKey(key);
      setSortAsc(false);
    }
  };

  const sortIndicator = (key: SortKey) => {
    if (key !== sortKey) return <span className={styles.sortArrow}>&middot;</span>;
    return (
      <span className={styles.sortArrowActive}>
        {sortAsc ? "\u25B2" : "\u25BC"}
      </span>
    );
  };

  const isLoading = tab === "health" ? healthLoading : valueLoading;

  if (isLoading) {
    return (
      <div className={`${styles.container} ${embedded ? styles.embedded : ""}`}>
        <div className={styles.tabs}>
          <button className={`${styles.tab} ${tab === "health" ? styles.tabActive : ""}`} onClick={() => setTab("health")}>Health</button>
          <button className={`${styles.tab} ${tab === "value" ? styles.tabActive : ""}`} onClick={() => setTab("value")}>Intel Value</button>
        </div>
        <AsyncStateLoading
          label={tab === "health" ? "Loading feed health…" : "Calculating feed value scores…"}
        />
      </div>
    );
  }

  return (
    <div className={`${styles.container} ${embedded ? styles.embedded : ""}`}>
      <div className={styles.tabs}>
        <button className={`${styles.tab} ${tab === "health" ? styles.tabActive : ""}`} onClick={() => setTab("health")}>Health</button>
        <button className={`${styles.tab} ${tab === "value" ? styles.tabActive : ""}`} onClick={() => setTab("value")}>Intel Value</button>
      </div>

      {tab === "health" && (
        <>
          <div className={styles.toolbar}>
            <span className={styles.toolbarLabel}>Stale threshold:</span>
            <select
              value={staleDays}
              onChange={(e) => setStaleDays(Number(e.target.value))}
              className={styles.filterSelect}
            >
              <option value={3}>3 days</option>
              <option value={7}>7 days</option>
              <option value={14}>14 days</option>
              <option value={30}>30 days</option>
            </select>
            <span className={styles.resultCount}>
              {healthData?.summary.total ?? 0} feeds
            </span>
          </div>

          <div className={styles.content}>
            {healthData ? (
              <>
                <div className={styles.summaryRow}>
                  <div className={`${styles.summaryCard} ${styles.healthy}`}>
                    <span className={styles.summaryCount}>{healthData.summary.healthy}</span>
                    <span className={styles.summaryLabel}>Healthy</span>
                  </div>
                  <div className={`${styles.summaryCard} ${styles.stale}`}>
                    <span className={styles.summaryCount}>{healthData.summary.stale}</span>
                    <span className={styles.summaryLabel}>Stale</span>
                  </div>
                  <div className={`${styles.summaryCard} ${styles.erroring}`}>
                    <span className={styles.summaryCount}>{healthData.summary.erroring}</span>
                    <span className={styles.summaryLabel}>Erroring</span>
                  </div>
                  <div
                    className={`${styles.summaryCard} ${styles.dead}`}
                    title="Paused by the health check: every fetch answered HTTP 4xx for the configured window"
                  >
                    <span className={styles.summaryCount}>{healthData.summary.dead ?? 0}</span>
                    <span className={styles.summaryLabel}>Dead</span>
                  </div>
                  <div
                    className={`${styles.summaryCard} ${styles.stale}`}
                    title="Answers, but has stopped delivering articles: the feed URL redirects to a page with none, or the feed has been empty for days"
                  >
                    <span className={styles.summaryCount}>{healthData.summary.empty ?? 0}</span>
                    <span className={styles.summaryLabel}>Empty</span>
                  </div>
                  <div className={`${styles.summaryCard} ${styles.disabled}`}>
                    <span className={styles.summaryCount}>{healthData.summary.disabled}</span>
                    <span className={styles.summaryLabel}>Disabled</span>
                  </div>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryCount}>{healthData.summary.total}</span>
                    <span className={styles.summaryLabel}>Total</span>
                  </div>
                </div>

                {(healthData.dead_feeds?.length ?? 0) > 0 && (
                  <section className={styles.section}>
                    <h2 className={styles.sectionTitle}>
                      Dead Feeds ({healthData.dead_feeds.length})
                    </h2>
                    <p className={styles.sectionHint}>
                      Paused automatically: every fetch answered HTTP 4xx for the whole auto-pause window
                      (Fetch settings, below). Fix the URL and resume, or remove the feed.
                    </p>
                    <div className={styles.list}>
                      <div className={styles.listHeader}>
                        <span className={styles.nameCol}>Feed</span>
                        <span className={styles.errorCountCol}>Errors</span>
                        <span className={styles.errorMsgCol}>Last Error</span>
                        <span className={styles.reachCol}>Readers</span>
                        <span className={styles.actionCol}>Actions</span>
                      </div>
                      {healthData.dead_feeds.map((f) => (
                        <div key={f.id} className={styles.row}>
                          <span className={styles.nameCol}>
                            <span className={styles.feedNameRow}>
                              <span className={styles.feedName}>{f.title}</span>
                              <ReliabilityBadge rating={f.reliability_rating} />
                            </span>
                          </span>
                          <span className={`${styles.errorCountCol} ${styles.errorCount}`}>
                            {f.error_count}
                            {f.failing_for_days != null && (
                              <span className={styles.errorAge}> · {f.failing_for_days}d</span>
                            )}
                          </span>
                          <span className={`${styles.errorMsgCol} ${styles.errorMsg}`}>
                            {f.pause_reason?.last_error ?? f.last_error ?? "\u2014"}
                            {f.pause_reason?.client === "curl_cffi" && (
                              <span className={styles.errorAge}> · also with browser impersonation</span>
                            )}
                            {f.auto_paused_at && (
                              <span className={styles.errorAge}> · paused {formatDate(f.auto_paused_at)}</span>
                            )}
                          </span>
                          <ReachCell feed={f} />
                          <span className={styles.actionCol}>
                            <button
                              className={styles.actionBtn}
                              onClick={() => resumeFeed.mutate(f.id)}
                              disabled={resumeFeed.isPending}
                              title="Re-activate and clear the failure streak"
                            >
                              Resume
                            </button>
                            <button
                              className={`${styles.actionBtn} ${styles.removeBtn}`}
                              onClick={() => handleRemove(f.id, f.title)}
                              disabled={removeFeed.isPending}
                            >
                              Remove
                            </button>
                          </span>
                        </div>
                      ))}
                    </div>
                  </section>
                )}

                {(healthData.empty_feeds?.length ?? 0) > 0 && (
                  <section className={styles.section}>
                    <h2 className={styles.sectionTitle}>
                      Empty Feeds ({healthData.empty_feeds!.length})
                    </h2>
                    <p className={styles.sectionHint}>
                      These answer without an error but deliver no articles. Usually the feed
                      moved: the old URL redirects to a landing page. Find the new feed URL and
                      update it, or remove the feed.
                    </p>
                    <div className={styles.list}>
                      <div className={styles.listHeader}>
                        <span className={styles.nameCol}>Feed</span>
                        <span className={styles.errorMsgCol}>What it returns</span>
                        <span className={styles.reachCol}>Readers</span>
                        <span className={styles.actionCol}>Actions</span>
                      </div>
                      {healthData.empty_feeds!.map((f) => (
                        <div key={f.id} className={styles.row}>
                          <span className={styles.nameCol}>
                            <span className={styles.feedNameRow}>
                              <span className={styles.feedName}>{f.title}</span>
                              <ReliabilityBadge rating={f.reliability_rating} />
                            </span>
                          </span>
                          <span className={`${styles.errorMsgCol} ${styles.errorMsg}`}>
                            {f.health_warning ? describeHealthWarning(f.health_warning) : "\u2014"}
                            {f.health_warning?.since && (
                              <span className={styles.errorAge}> · since {formatDate(f.health_warning.since)}</span>
                            )}
                          </span>
                          <ReachCell feed={f} />
                          <span className={styles.actionCol}>
                            <button
                              className={styles.actionBtn}
                              onClick={() => toggleActive(f.id, f.is_active)}
                              disabled={togglePending}
                            >
                              Pause
                            </button>
                            <button
                              className={`${styles.actionBtn} ${styles.removeBtn}`}
                              onClick={() => handleRemove(f.id, f.title)}
                              disabled={removeFeed.isPending}
                            >
                              Remove
                            </button>
                          </span>
                        </div>
                      ))}
                    </div>
                  </section>
                )}

                {healthData.erroring_feeds.length > 0 && (
                  <section className={styles.section}>
                    <h2 className={styles.sectionTitle}>
                      Erroring Feeds ({healthData.erroring_feeds.length})
                    </h2>
                    <div className={styles.list}>
                      <div className={styles.listHeader}>
                        <span className={styles.nameCol}>Feed</span>
                        <span className={styles.errorCountCol}>Errors</span>
                        <span className={styles.errorMsgCol}>Last Error</span>
                        <span className={styles.reachCol}>Readers</span>
                        <span className={styles.actionCol}>Actions</span>
                      </div>
                      {healthData.erroring_feeds.map((f) => (
                        <div key={f.id} className={styles.row}>
                          <span className={styles.nameCol}>
                            <span className={styles.feedNameRow}>
                              <span className={styles.feedName}>{f.title}</span>
                              <ReliabilityBadge rating={f.reliability_rating} />
                            </span>
                          </span>
                          <span
                            className={`${styles.errorCountCol} ${styles.errorCount}`}
                            title={
                              f.failing_for_days != null
                                ? `Failing for ${f.failing_for_days} days (since ${f.error_since ? formatDate(f.error_since) : "?"})`
                                : undefined
                            }
                          >
                            {f.error_count}
                            {f.failing_for_days != null && (
                              <span className={styles.errorAge}> · {f.failing_for_days}d</span>
                            )}
                          </span>
                          <span className={`${styles.errorMsgCol} ${styles.errorMsg}`}>
                            {f.last_error
                              ? f.last_error.length > 80
                                ? f.last_error.slice(0, 80) + "..."
                                : f.last_error
                              : "\u2014"}
                          </span>
                          <ReachCell feed={f} />
                          <span className={styles.actionCol}>
                            <button
                              className={styles.actionBtn}
                              onClick={() => toggleActive(f.id, f.is_active)}
                              disabled={togglePending}
                            >
                              {f.is_active ? "Pause" : "Resume"}
                            </button>
                            <button
                              className={`${styles.actionBtn} ${styles.removeBtn}`}
                              onClick={() => handleRemove(f.id, f.title)}
                              disabled={removeFeed.isPending}
                            >
                              Remove
                            </button>
                          </span>
                        </div>
                      ))}
                    </div>
                  </section>
                )}

                {healthData.stale_feeds.length > 0 && (
                  <section className={styles.section}>
                    <h2 className={styles.sectionTitle}>
                      Stale Feeds ({healthData.stale_feeds.length})
                    </h2>
                    <div className={styles.list}>
                      <div className={styles.listHeader}>
                        <span className={styles.nameCol}>Feed</span>
                        <span className={styles.dateCol}>Last Fetched</span>
                        <span className={styles.reachCol}>Readers</span>
                        <span className={styles.actionCol}>Actions</span>
                      </div>
                      {healthData.stale_feeds.map((f) => (
                        <div key={f.id} className={styles.row}>
                          <span className={styles.nameCol}>
                            <span className={styles.feedNameRow}>
                              <span className={styles.feedName}>{f.title}</span>
                              <ReliabilityBadge rating={f.reliability_rating} />
                            </span>
                          </span>
                          <span className={styles.dateCol}>
                            {f.last_fetched_at
                              ? formatDate(f.last_fetched_at)
                              : "Never"}
                          </span>
                          <ReachCell feed={f} />
                          <span className={styles.actionCol}>
                            <button
                              className={styles.actionBtn}
                              onClick={() => toggleActive(f.id, f.is_active)}
                              disabled={togglePending}
                            >
                              {f.is_active ? "Pause" : "Resume"}
                            </button>
                            <button
                              className={`${styles.actionBtn} ${styles.removeBtn}`}
                              onClick={() => handleRemove(f.id, f.title)}
                              disabled={removeFeed.isPending}
                            >
                              Remove
                            </button>
                          </span>
                        </div>
                      ))}
                    </div>
                  </section>
                )}

                {healthData.disabled_feeds.length > 0 && (
                  <section className={styles.section}>
                    <h2 className={styles.sectionTitle}>
                      Disabled Feeds ({healthData.disabled_feeds.length})
                    </h2>
                    <div className={styles.list}>
                      <div className={styles.listHeader}>
                        <span className={styles.nameCol}>Feed</span>
                        <span className={styles.dateCol}>Last Fetched</span>
                        <span className={styles.reachCol}>Readers</span>
                        <span className={styles.actionCol}>Actions</span>
                      </div>
                      {healthData.disabled_feeds.map((f) => (
                        <div key={f.id} className={styles.row}>
                          <span className={styles.nameCol}>
                            <span className={styles.feedNameRow}>
                              <span className={styles.feedName}>{f.title}</span>
                              <ReliabilityBadge rating={f.reliability_rating} />
                            </span>
                          </span>
                          <span className={styles.dateCol}>
                            {f.last_fetched_at
                              ? formatDate(f.last_fetched_at)
                              : "Never"}
                          </span>
                          <ReachCell feed={f} />
                          <span className={styles.actionCol}>
                            <button
                              className={`${styles.actionBtn} ${styles.resumeBtn}`}
                              onClick={() => toggleActive(f.id, false)}
                              disabled={togglePending}
                            >
                              Resume
                            </button>
                            <button
                              className={`${styles.actionBtn} ${styles.removeBtn}`}
                              onClick={() => handleRemove(f.id, f.title)}
                              disabled={removeFeed.isPending}
                            >
                              Remove
                            </button>
                          </span>
                        </div>
                      ))}
                    </div>
                  </section>
                )}

                {healthData.erroring_feeds.length === 0 &&
                  healthData.stale_feeds.length === 0 &&
                  healthData.disabled_feeds.length === 0 && (
                    <div className={styles.allGood}>
                      All feeds are healthy and actively fetching.
                    </div>
                  )}
              </>
            ) : (
              <div className={styles.loading}>No data available</div>
            )}
          </div>
        </>
      )}

      {tab === "value" && (
        <>
          <div className={styles.toolbar}>
            <span className={styles.toolbarLabel}>Time window:</span>
            <select
              value={valueDays}
              onChange={(e) => setValueDays(Number(e.target.value))}
              className={styles.filterSelect}
            >
              <option value={30}>30 days</option>
              <option value={60}>60 days</option>
              <option value={90}>90 days</option>
              <option value={180}>180 days</option>
              <option value={365}>1 year</option>
            </select>
            <span className={styles.resultCount}>
              {valueData?.summary.total ?? 0} feeds scored
            </span>
          </div>

          <div className={styles.content}>
            {valueData ? (
              <>
                <div className={styles.summaryRow}>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryCount}>{valueData.summary.total}</span>
                    <span className={styles.summaryLabel}>Total Feeds</span>
                  </div>
                  <div className={`${styles.summaryCard} ${styles.avgScore}`}>
                    <span className={styles.summaryCount}>{valueData.summary.avg_score}</span>
                    <span className={styles.summaryLabel}>Avg Score</span>
                  </div>
                  <div className={`${styles.summaryCard} ${styles.producing}`}>
                    <span className={styles.summaryCount}>{valueData.summary.scored}</span>
                    <span className={styles.summaryLabel}>Producing Intel</span>
                  </div>
                  <div className={`${styles.summaryCard} ${styles.noValue}`}>
                    <span className={styles.summaryCount}>{valueData.summary.no_value}</span>
                    <span className={styles.summaryLabel}>No Intel Value</span>
                  </div>
                </div>

                {(valueData.review_candidates?.length ?? 0) > 0 && (
                  <section className={styles.section}>
                    <button
                      className={styles.reviewToggle}
                      onClick={() => setShowReview(!showReview)}
                      aria-expanded={showReview}
                    >
                      <span className={styles.reviewChevron}>{showReview ? "▾" : "▸"}</span>
                      Review candidates ({valueData.review_candidates.length})
                      <span className={styles.reviewHint}>
                        zero intel value and zero PIR matches in this window
                      </span>
                    </button>
                    {showReview && (
                      <div className={styles.list}>
                        <div className={styles.listHeader}>
                          <span className={styles.nameCol}>Feed</span>
                          <span className={styles.errorCountCol}>Articles</span>
                          <span className={styles.actionCol}>Actions</span>
                        </div>
                        {valueData.review_candidates.map((c) => (
                          <div key={c.feed_id} className={styles.row}>
                            <span className={styles.nameCol}>
                              <span className={styles.feedNameRow}>
                                <span className={styles.feedName}>{c.feed_title}</span>
                                <ReliabilityBadge rating={c.reliability_rating} />
                                <span className={styles.feedType}>{c.feed_type}</span>
                              </span>
                            </span>
                            <span className={styles.errorCountCol}>{c.articles}</span>
                            <span className={styles.actionCol}>
                              <button
                                className={styles.actionBtn}
                                onClick={() => pauseReviewCandidate(c.feed_id)}
                                disabled={togglePending}
                              >
                                Pause
                              </button>
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </section>
                )}

                {sortedFeeds.length === 0 ? (
                  <div className={styles.empty}>
                    No feed value data available. Feeds need intelligence extraction enabled to generate scores.
                  </div>
                ) : (
                  <div className={styles.tableWrap}>
                    <table className={styles.table}>
                      <thead>
                        <tr>
                          <th className={styles.rankCol}>#</th>
                          <th className={styles.feedCol}>Feed</th>
                          {VALUE_COLUMNS.map((col) => (
                            <th
                              key={col.key}
                              className={col.key === "score" ? styles.scoreCol : styles.numCol}
                              title={col.title}
                              onClick={() => handleSort(col.key)}
                            >
                              {col.label} {sortIndicator(col.key)}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {sortedFeeds.map((feed: FeedValueScore, i: number) => (
                          <tr key={feed.feed_id}>
                            <td className={styles.rankCol}>{i + 1}</td>
                            <td className={styles.feedCol}>
                              <span className={styles.feedNameRow}>
                                <span className={styles.feedName} title={feed.feed_title}>
                                  {feed.feed_title}
                                </span>
                                <ReliabilityBadge rating={feed.reliability_rating} />
                              </span>
                              <span className={styles.feedType}>{feed.feed_type}</span>
                            </td>
                            <td className={styles.scoreCol}>
                              <span className={styles.scoreCell}>
                                <span className={styles.scoreValue}>{feed.score}</span>
                                <span className={`${styles.tier} ${TIER_CLASS[feed.tier] ?? styles.tierD}`}>
                                  {feed.tier}
                                </span>
                              </span>
                            </td>
                            <td className={styles.numCol}>{feed.articles}</td>
                            <td className={styles.numCol}>{feed.unique_entities}</td>
                            <td className={styles.numCol}>
                              <DimensionBar value={feed.dimensions.entity_introductions} />
                            </td>
                            <td className={styles.numCol}>
                              <DimensionBar value={feed.dimensions.correlation_events} />
                            </td>
                            <td className={styles.numCol}>{feed.detection_rules}</td>
                            <td className={styles.numCol}>{feed.pir_matches}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            ) : (
              <div className={styles.empty}>No data available</div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
