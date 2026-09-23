import { useState, useMemo } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useFeedHealth, useFeedValueScores } from "@/hooks/useAnalytics";
import { useUpdateFeed, useDeleteFeed } from "@/hooks/useFeeds";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { formatDate } from "@/utils/formatDate";
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

  const updateFeed = useUpdateFeed();
  const deleteFeed = useDeleteFeed();
  const undoableDelete = useUndoableDelete();

  const handleRemove = (feedId: string, title: string) => {
    undoableDelete({
      label: `Feed "${title}"`,
      key: `feed-${feedId}`,
      onDelete: () => deleteFeed.mutate(feedId, {
        onSuccess: () => {
          queryClient.invalidateQueries({ queryKey: ["feed-health"] });
        },
      }),
    });
  };

  const toggleActive = (feedId: string, currentlyActive: boolean) => {
    updateFeed.mutate(
      { feedId, data: { is_active: !currentlyActive } },
      {
        onSuccess: () => {
          queryClient.invalidateQueries({ queryKey: ["feed-health"] });
        },
      },
    );
  };

  const pauseReviewCandidate = (feedId: string) => {
    updateFeed.mutate(
      { feedId, data: { is_active: false } },
      {
        onSuccess: () => {
          queryClient.invalidateQueries({ queryKey: ["feed-health"] });
          queryClient.invalidateQueries({ queryKey: ["analytics", "feed-value"] });
        },
      },
    );
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
                  <div className={`${styles.summaryCard} ${styles.disabled}`}>
                    <span className={styles.summaryCount}>{healthData.summary.disabled}</span>
                    <span className={styles.summaryLabel}>Disabled</span>
                  </div>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryCount}>{healthData.summary.total}</span>
                    <span className={styles.summaryLabel}>Total</span>
                  </div>
                </div>

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
                          <span className={`${styles.errorCountCol} ${styles.errorCount}`}>
                            {f.error_count}
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
                              disabled={updateFeed.isPending}
                            >
                              {f.is_active ? "Pause" : "Resume"}
                            </button>
                            <button
                              className={`${styles.actionBtn} ${styles.removeBtn}`}
                              onClick={() => handleRemove(f.id, f.title)}
                              disabled={deleteFeed.isPending}
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
                              disabled={updateFeed.isPending}
                            >
                              {f.is_active ? "Pause" : "Resume"}
                            </button>
                            <button
                              className={`${styles.actionBtn} ${styles.removeBtn}`}
                              onClick={() => handleRemove(f.id, f.title)}
                              disabled={deleteFeed.isPending}
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
                              disabled={updateFeed.isPending}
                            >
                              Resume
                            </button>
                            <button
                              className={`${styles.actionBtn} ${styles.removeBtn}`}
                              onClick={() => handleRemove(f.id, f.title)}
                              disabled={deleteFeed.isPending}
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
                                disabled={updateFeed.isPending}
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
