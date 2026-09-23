/**
 * SinceLastVisitRibbon — the Overview's opening beat: what changed on this
 * entity since you last opened its profile. Last-visit timestamps are tracked
 * client-side per entity in intelStore; counts come from the pivot data already
 * on the page. The visit is stamped by EntityProfilePage when the profile is
 * LEFT — stamping here on mount rebased the baseline on every tab flip back to
 * Overview and permanently suppressed the ribbon for the session.
 *
 * Articles are counted by ingest time (created_at) when the payload carries it:
 * most of what arrives between visits was published earlier (feed lag,
 * roundups, autolinker rescans), so a published_at comparison undercounts.
 * Events break down by kind — relationship changes, stories, the rest — with
 * KEV addition and new leak-site victims called out when the caller knows them.
 */
import { useState } from "react";
import { useIntelStore } from "@/stores/intelStore";
import { formatDate } from "@/utils/formatDate";
import type { TimelineEvent } from "@/api/types";
import styles from "./entityProfile.module.css";

export function SinceLastVisitRibbon({
  entityId,
  entries,
  events,
  kevAddedAt,
  victimDates,
  onCatchUp,
}: {
  entityId: string;
  entries: Array<{ id: string; published_at: string | null; created_at?: string | null }>;
  events: TimelineEvent[];
  /** CVE only: kev_date_added, for the "added to KEV" callout. */
  kevAddedAt?: string | null;
  /** Actor only: last_seen_at of the most recent leak-site victims. */
  victimDates?: Array<string | null>;
  onCatchUp: () => void;
}) {
  // Read once at mount — the stamp only moves when the profile is left, so
  // this stays the true previous visit for the whole stay.
  const [lastVisit] = useState<number | undefined>(
    () => useIntelStore.getState().entityLastVisit[entityId],
  );
  const [dismissed, setDismissed] = useState(false);
  const dismiss = () => {
    // Dismissing acknowledges the catch-up: rebase now so it stays gone.
    useIntelStore.getState().markEntityVisited(entityId);
    setDismissed(true);
  };

  if (!lastVisit || dismissed) return null;

  const since = new Date(lastVisit);
  const after = (iso: string | null | undefined) => !!iso && new Date(iso) > since;
  const newArticles = entries.filter((e) => after(e.created_at ?? e.published_at)).length;

  const fresh = events.filter((e) => e.event_type && e.event_type !== "article" && after(e.date));
  const relChanges = fresh.filter((e) => e.event_type === "relationship").length;
  const newStories = fresh.filter((e) => e.event_type === "story").length;
  const otherEvents = fresh.length - relChanges - newStories;

  const kevAdded = after(kevAddedAt);
  const newVictims = (victimDates ?? []).filter(after).length;

  if (newArticles === 0 && fresh.length === 0 && !kevAdded && newVictims === 0) return null;

  const plural = (n: number, noun: string) => `${n} ${noun}${n === 1 ? "" : "s"}`;
  const parts = [
    newArticles > 0 ? `${plural(newArticles, "new article")}` : null,
    kevAdded ? "added to KEV" : null,
    newVictims > 0 ? `${plural(newVictims, "new victim")}` : null,
    relChanges > 0 ? `${plural(relChanges, "relationship change")}` : null,
    newStories > 0 ? `${plural(newStories, "new story")}` : null,
    otherEvents > 0 ? `${plural(otherEvents, "other event")}` : null,
  ].filter(Boolean) as string[];

  return (
    <div className={styles.visitRibbon}>
      <span className={styles.visitRibbonLabel}>Since your last visit · {formatDate(since.toISOString())}</span>
      {parts.map((p) => (
        <span key={p}>{p}</span>
      ))}
      <button className={styles.visitRibbonGo} onClick={onCatchUp}>
        Catch up →
      </button>
      <button className={styles.visitRibbonDismiss} onClick={dismiss}>
        dismiss
      </button>
    </div>
  );
}
