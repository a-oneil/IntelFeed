import { useEffect } from "react";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { Link } from "react-router-dom";
import { useBulkAction } from "@/hooks/useEntries";
import { useOpenThreadMutation, useThread } from "@/hooks/useThreads";
import { useIsVisitor } from "@/stores/authStore";
import { useIntelStore } from "@/stores/intelStore";
import { useUIStore } from "@/stores/uiStore";
import { useOpenEntry, useOpenThread } from "@/utils/openEntry";
import { entityDestination } from "@/utils/entityDestination";
import { formatDate } from "@/utils/formatDate";
import styles from "./ThreadReader.module.css";

interface ThreadReaderProps {
  slug: string;
}

const KIND_LABEL: Record<string, string> = {
  first_disclosure: "First disclosure",
  new_tradecraft: "New technique",
  peak: "Peak coverage",
  update: "Update",
};

/**
 * A story thread in the reader pane: the spine first, then the member articles.
 *
 * The spine is a dated list of the waves of coverage and what each one added, with repeat reports counted rather than listed. The member article list below it is there for when an analyst needs the sources, but the page leads with the spine.
 */
export function ThreadReader({ slug }: ThreadReaderProps) {
  const { data: thread, isLoading } = useThread(slug);
  // Docked in the workbench, this reader fills the dock rather than following the feed's selection: opening an article replaces it in the dock, and Close clears the dock.
  const openEntry = useOpenEntry();
  const openThread = useOpenThread();
  const setSelectedThread = useUIStore((s) => s.setSelectedThread);
  const closeReader = () => {
    setSelectedThread(null);
    useIntelStore.getState().closeWorkbenchReader();
  };
  const isMobile = useIsMobile();
  const markOpened = useOpenThreadMutation();
  const bulkAction = useBulkAction();
  const isVisitor = useIsVisitor();
  const dismissThread = useUIStore((s) => s.dismissThread);

  // The same clear action the thread's row in the queue offers, repeated here so finishing a story doesn't mean finding the row again in the list.
  const clearThread = () => {
    if (!thread) return;
    if (thread.entry_ids.length) {
      bulkAction.mutate({ entry_ids: thread.entry_ids, action: "read" });
    }
    dismissThread(thread.id);
    closeReader();
  };

  // Marks the thread opened; the "N new" count is measured from this point.
  const threadId = thread?.id;
  const markOpenedMutate = markOpened.mutate;
  useEffect(() => {
    if (threadId) markOpenedMutate(threadId);
  }, [threadId, markOpenedMutate]);

  const closeBar = (
    <div className={styles.topBar}>
      <button className={styles.closeBtn} onClick={closeReader}>
        {isMobile ? (
          <>
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <polyline points="15 18 9 12 15 6" />
            </svg>
            Back
          </>
        ) : (
          "Close"
        )}
      </button>
      {thread && !isVisitor && (
        <div className={styles.barActions}>
          <button
            type="button"
            className={styles.clearBtn}
            onClick={clearThread}
            disabled={bulkAction.isPending}
            title="Mark every article in this thread read"
          >
            {bulkAction.isPending ? "Marking…" : "Mark as read"}
          </button>
        </div>
      )}
    </div>
  );

  if (isLoading || !thread) {
    return (
      <div className={styles.readerContainer}>
        {closeBar}
        <div className={styles.loading}>{isLoading ? "Loading thread…" : "Thread not found."}</div>
      </div>
    );
  }

  const echoes = thread.members.filter((m) => m.role === "echo");
  const spineMembers = thread.members.filter((m) => m.role !== "echo");
  const firstMember = spineMembers[0];

  return (
    <div className={styles.readerContainer}>
      {closeBar}
      <article className={styles.reader}>
        <header className={styles.header}>
        <div className={styles.kicker}>
          <span className={styles.status}>{thread.status}</span>
          <span>
            {formatDate(thread.first_seen)} to {formatDate(thread.last_seen)}
          </span>
          {firstMember?.source && <span>first: {firstMember.source}</span>}
        </div>
        <h1 className={styles.title}>{thread.title}</h1>
        {thread.summary && <p className={styles.summary}>{thread.summary}</p>}

        <div className={styles.stats}>
          <span>
            <b>{thread.entry_count}</b> articles
          </span>
          <span>
            <b>{thread.source_count}</b> outlets
          </span>
          {thread.thread_yield.techniques > 0 && (
            <span>
              <b>{thread.thread_yield.techniques}</b> techniques
            </span>
          )}
          {thread.thread_yield.cves > 0 && (
            <span>
              <b>{thread.thread_yield.cves}</b> CVEs
            </span>
          )}
          {thread.thread_yield.rules > 0 && (
            <span>
              <b>{thread.thread_yield.rules}</b> rules
            </span>
          )}
          {thread.thread_yield.echoes_folded > 0 && (
            <span>
              <b>{thread.thread_yield.echoes_folded}</b> re-reports grouped
            </span>
          )}
        </div>

        {!thread.narrated_at && (
          <p className={styles.heuristicNote}>Timeline grouped by day. Summary not written yet.</p>
        )}

        {thread.key_entities.length > 0 && (
          <div className={styles.entities}>
            {thread.key_entities.slice(0, 8).map((e) => {
              const dest = entityDestination(e.entity_type, e.entity_id);
              return (
                <Link
                  key={`${e.entity_type}-${e.entity_id}`}
                  to={dest.path}
                  onClick={dest.before}
                  className={styles.entityChip}
                >
                  {e.label}
                  <span className={styles.entityCount}>{e.count}</span>
                </Link>
              );
            })}
          </div>
        )}
      </header>

      <section className={styles.spine}>
        <h2 className={styles.sectionTitle}>Timeline</h2>
        {thread.beats.map((beat) => (
          <div key={beat.id} className={styles.beat}>
            <div className={styles.beatMeta}>
              <span className={styles.beatDate}>{formatDate(beat.occurred_at)}</span>
              <span className={`${styles.beatKind} ${styles[beat.kind] ?? ""}`}>
                {KIND_LABEL[beat.kind] ?? beat.kind}
              </span>
            </div>
            <button
              className={styles.beatHeadline}
              onClick={() => beat.lead_entry_id && openEntry(beat.lead_entry_id)}
            >
              {beat.headline}
            </button>
            {beat.body && <p className={styles.beatBody}>{beat.body}</p>}
            {beat.collapsed_count > 0 && (
              <p className={styles.collapsed}>
                {beat.collapsed_count} near-duplicate {beat.collapsed_count === 1 ? "re-report" : "re-reports"} grouped
              </p>
            )}
          </div>
        ))}
      </section>

      <section className={styles.members}>
        <h2 className={styles.sectionTitle}>Coverage</h2>
        <ul className={styles.memberList}>
          {spineMembers.map((m) => (
            <li key={m.entry_id}>
              <button
                className={`${styles.member} ${m.is_read ? styles.read : ""}`}
                onClick={() => openEntry(m.entry_id)}
              >
                <span className={styles.memberMeta}>
                  {formatDate(m.published_at)} · {m.source ?? m.feed_title}
                  {m.role === "origin" && <span className={styles.originTag}>first</span>}
                </span>
                <span className={styles.memberTitle}>{m.title}</span>
              </button>
            </li>
          ))}
        </ul>
        {echoes.length > 0 && (
          <details className={styles.echoes}>
            <summary>
              {echoes.length} re-{echoes.length === 1 ? "report" : "reports"} grouped
            </summary>
            <ul className={styles.memberList}>
              {echoes.map((m) => (
                <li key={m.entry_id}>
                  <button className={styles.member} onClick={() => openEntry(m.entry_id)}>
                    <span className={styles.memberMeta}>
                      {formatDate(m.published_at)} · {m.source ?? m.feed_title} · {Math.round(m.similarity * 100)}%
                      match
                    </span>
                    <span className={styles.memberTitle}>{m.title}</span>
                  </button>
                </li>
              ))}
            </ul>
          </details>
        )}
      </section>

      {thread.nearest.length > 0 && (
        <section className={styles.nearest}>
          <h2 className={styles.sectionTitle}>Nearest threads</h2>
          <ul className={styles.nearestList}>
            {thread.nearest.map((n) => (
              <li key={n.slug}>
                <button className={styles.nearestLink} onClick={() => openThread(n.slug)}>
                  <span>{n.title}</span>
                  <span className={styles.nearestScore}>{n.similarity.toFixed(2)}</span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}
      </article>
    </div>
  );
}
