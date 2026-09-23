import { useState, useRef, useEffect, useCallback } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import type { EntryIntelCounts, PIRMatch } from "@/hooks/useEntryIntelBadges";
import { useUIStore } from "@/stores/uiStore";
import styles from "./EntryIntelBadges.module.css";

interface EntryIntelBadgesProps {
  counts?: EntryIntelCounts;
  /** Personal state: the analyst starred this entry */
  starred?: boolean;
  /** Personal state: the analyst bookmarked this entry */
  bookmarked?: boolean;
  /** Signal engine: this entry is a near-duplicate (echo) of earlier coverage */
  echo?: boolean;
}

const CATEGORY_ORDER = ["tactical", "operational", "technical", "strategic"] as const;

const StarIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <path d="M12 2.5l2.9 6.1 6.6.6-5 4.4 1.5 6.5L12 16.9 6 20.1l1.5-6.5-5-4.4 6.6-.6z" />
  </svg>
);

const BookmarkIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <path d="M6.5 2.5h11a1 1 0 0 1 1 1v18l-6.5-3.9L5.5 21.5v-18a1 1 0 0 1 1-1z" />
  </svg>
);

const NoteIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <path d="M5 2.5h9.5L20 8v13a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1zm9 1.6V8h3.9z" />
  </svg>
);

const EchoIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <path d="M8.5 2.5h11a1 1 0 0 1 1 1v11a1 1 0 0 1-1 1H16V9a2.5 2.5 0 0 0-2.5-2.5H7.5v-4a1 1 0 0 1 1-1z" />
    <rect x="3.5" y="6.5" width="12" height="15" rx="1.5" />
  </svg>
);

function PirSummary({ pirs }: { pirs: PIRMatch[] }) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLSpanElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ top: number; left: number }>({ top: 0, left: 0 });
  const setHeaderSearchQuery = useUIStore((s) => s.setHeaderSearchQuery);
  const navigate = useNavigate();

  const updatePosition = useCallback(() => {
    if (!triggerRef.current) return;
    const rect = triggerRef.current.getBoundingClientRect();
    setPos({ top: rect.bottom + 4, left: rect.left });
  }, []);

  // Position popover and handle outside clicks
  useEffect(() => {
    if (!open) return;
    updatePosition();
    const handleClick = (e: MouseEvent) => {
      if (
        triggerRef.current?.contains(e.target as Node) ||
        popoverRef.current?.contains(e.target as Node)
      ) return;
      setOpen(false);
    };
    const handleScroll = () => setOpen(false);
    document.addEventListener("mousedown", handleClick);
    // Close on scroll in any ancestor
    window.addEventListener("scroll", handleScroll, true);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      window.removeEventListener("scroll", handleScroll, true);
    };
  }, [open, updatePosition]);

  const handlePirClick = (e: React.MouseEvent, pirTitle: string) => {
    e.stopPropagation();
    setHeaderSearchQuery(`pir:"${pirTitle}"`);
    navigate("/search");
    setOpen(false);
  };

  // Build category counts
  const byCat: Record<string, PIRMatch[]> = {};
  for (const pir of pirs) {
    (byCat[pir.category] ??= []).push(pir);
  }

  return (
    <>
      <span className={styles.pirSummaryWrap} ref={triggerRef}>
        <span
          className={`${styles.chip} ${styles.pirChip}`}
          onClick={(e) => { e.stopPropagation(); setOpen(!open); }}
          role="button"
          tabIndex={0}
          aria-haspopup="true"
          aria-expanded={open}
          title={`Matches ${pirs.length} of your standing intelligence requirements (PIRs) — click for detail`}
          onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.stopPropagation(); setOpen(!open); } }}
        >
          <span className={styles.chipNum}>{pirs.length}</span>
          <span className={styles.chipLabel}>PIR</span>
          <span className={styles.pirBar} aria-hidden="true">
            {CATEGORY_ORDER.map((cat) => {
              const count = byCat[cat]?.length;
              if (!count) return null;
              return (
                <i
                  key={cat}
                  className={styles.pirBarSeg}
                  data-category={cat}
                  style={{ flexGrow: count }}
                />
              );
            })}
          </span>
          <span className={styles.caret} aria-hidden="true">▾</span>
        </span>
      </span>
      {open && createPortal(
        <div
          ref={popoverRef}
          className={styles.pirPopover}
          style={{ top: pos.top, left: pos.left }}
        >
          <div className={styles.pirPopoverIntro}>
            Matches {pirs.length} of your standing intelligence requirements
          </div>
          {CATEGORY_ORDER.map((cat) => {
            const items = byCat[cat];
            if (!items?.length) return null;
            return (
              <div key={cat} className={styles.pirPopoverGroup}>
                <span className={styles.pirPopoverCat} data-category={cat}>{cat}</span>
                {items.map((pir) => (
                  <span
                    key={pir.id}
                    className={styles.pirPopoverItem}
                    data-priority={pir.priority}
                    onClick={(e) => handlePirClick(e, pir.title)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") handlePirClick(e as unknown as React.MouseEvent, pir.title); }}
                  >
                    {pir.title}
                    {pir.matched_on && (
                      <span className={styles.pirPopoverWhy}>
                        {pir.match_type === "entity" ? "entity" : pir.match_type === "manual" ? "manual" : "keyword"}
                        {": "}
                        {pir.matched_on}
                        {pir.relevance && (
                          <span className={styles.pirPopoverRelevance} data-relevance={pir.relevance}>
                            {pir.relevance}
                          </span>
                        )}
                      </span>
                    )}
                  </span>
                ))}
              </div>
            );
          })}
          <span
            className={styles.pirPopoverEdit}
            role="button"
            tabIndex={0}
            onClick={(e) => {
              e.stopPropagation();
              navigate("/workbench/explore?section=requirements");
              setOpen(false);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.stopPropagation();
                navigate("/workbench/explore?section=requirements");
                setOpen(false);
              }
            }}
          >
            Requirements are yours to edit →
          </span>
        </div>,
        document.body
      )}
    </>
  );
}

export function EntryIntelBadges({ counts, starred, bookmarked, echo }: EntryIntelBadgesProps) {
  const pirMatches = counts?.pir_matches;
  const hasPirs = !!pirMatches && pirMatches.length > 0;
  const noteCount = counts?.notes ?? 0;

  // Personal state markers — "I flagged this". Note presence rides on the intel
  // note count, so it shows here as a marker rather than as an evidence chip.
  const hasState = !!echo || !!starred || !!bookmarked || noteCount > 0;

  // Named subject — the "who / what" headline. Actors take precedence over
  // malware; a single chip names the primary entity with a +N overflow.
  const actors = counts?.actors ?? [];
  const malware = counts?.malware ?? [];
  const subjectName = actors[0] ?? malware[0];
  const subjectIsActor = actors.length > 0;
  const namedTotal = (counts?.actor_count ?? actors.length) + (counts?.malware_count ?? malware.length);
  const subjectExtra = subjectName ? namedTotal - 1 : 0;
  const hasSubject = !!subjectName;

  const hasIntel = hasPirs || hasSubject || (counts?.total ?? 0) > 0 || (counts?.rules ?? 0) > 0;

  if (!hasIntel && !hasState) return null;

  // Telemetry-aware opportunity tier; fall back to the legacy binary flag when
  // the API payload predates detection_opportunity.
  const opportunity =
    counts?.detection_opportunity !== undefined
      ? counts.detection_opportunity
      : counts?.has_detection_gap
        ? "actionable_gap"
        : null;
  // KEV / high-risk CVE elevation trumps tier display
  const hotOpportunity = !!counts?.has_detection_gap && !!counts?.has_high_risk_cve;
  const showOpportunity = hotOpportunity || opportunity != null;

  // Build intel evidence chips — fixed order so position is predictable across cards.
  const stats: { key: string; label: string; value: number; className: string; tooltip: string }[] = [];
  if ((counts?.ttps ?? 0) > 0) stats.push({ key: "ttp", label: counts!.ttps !== 1 ? "TTPs" : "TTP", value: counts!.ttps, className: styles.ttp, tooltip: `${counts!.ttps} MITRE ATT&CK technique${counts!.ttps !== 1 ? "s" : ""}` });
  if ((counts?.cves ?? 0) > 0) {
    const sev = counts?.cve_max_severity;
    const sevClass = sev === "critical" ? ` ${styles.cveCritical}` : sev === "high" ? ` ${styles.cveHigh}` : "";
    stats.push({ key: "cve", label: counts!.cves !== 1 ? "CVEs" : "CVE", value: counts!.cves, className: `${styles.cve}${sevClass}`, tooltip: `${counts!.cves} CVE${counts!.cves !== 1 ? "s" : ""} referenced${sev ? ` — worst severity ${sev}` : ""}` });
  }
  if ((counts?.rules ?? 0) > 0) stats.push({ key: "rule", label: counts!.rules !== 1 ? "Rules" : "Rule", value: counts!.rules, className: styles.rule, tooltip: `${counts!.rules} detection rule${counts!.rules !== 1 ? "s" : ""}` });

  const hasEvidence = stats.length > 0 || showOpportunity;

  return (
    <span className={styles.intelLine}>
      {/* Personal state markers — leading icon chips */}
      {echo && (
        <span
          className={`${styles.chip} ${styles.stateChip} ${styles.echo}`}
          title="Echo — near-duplicate of earlier coverage"
          aria-label="Echo — near-duplicate of earlier coverage"
        >
          <EchoIcon />
        </span>
      )}
      {starred && (
        <span className={`${styles.chip} ${styles.stateChip} ${styles.starred}`} title="Starred" aria-label="Starred">
          <StarIcon />
        </span>
      )}
      {bookmarked && (
        <span className={`${styles.chip} ${styles.stateChip} ${styles.bookmarked}`} title="Bookmarked" aria-label="Bookmarked">
          <BookmarkIcon />
        </span>
      )}
      {noteCount > 0 && (
        <span
          className={`${styles.chip} ${styles.stateChip} ${styles.noted}`}
          title={`${noteCount} analyst note${noteCount !== 1 ? "s" : ""}`}
          aria-label={`${noteCount} analyst note${noteCount !== 1 ? "s" : ""}`}
        >
          <NoteIcon />
          {noteCount > 1 && <span className={styles.chipNum}>{noteCount}</span>}
        </span>
      )}
      {/* Divider between personal markers and the intel signals */}
      {hasState && (hasSubject || hasPirs || hasEvidence) && (
        <span className={styles.divider} aria-hidden="true" />
      )}
      {/* Named subject — the "who / what" this entry is about */}
      {hasSubject && (
        <span
          className={`${styles.chip} ${styles.subject} ${subjectIsActor ? styles.actor : styles.malware}`}
          title={`${subjectIsActor ? "Threat actor" : "Malware"}: ${[...actors, ...malware].join(", ")}`}
        >
          <span className={styles.chipName}>{subjectName}</span>
          {subjectExtra > 0 && <span className={styles.chipExtra}>+{subjectExtra}</span>}
        </span>
      )}
      {/* PIR summary chip with popover */}
      {hasPirs && <PirSummary pirs={pirMatches} />}
      {/* Divider between the who/what + requirements and the evidence counts */}
      {(hasSubject || hasPirs) && hasEvidence && (
        <span className={styles.divider} aria-hidden="true" />
      )}
      {/* Intel evidence chips */}
      {stats.map((s) => (
        <span key={s.key} className={`${styles.chip} ${s.className}`} title={s.tooltip}>
          <span className={styles.chipNum}>{s.value}</span>
          <span className={styles.chipLabel}>{s.label}</span>
        </span>
      ))}
      {/* Detection opportunity — the filled call-to-action, always the row's endpoint */}
      {hotOpportunity ? (
        <span
          className={`${styles.chip} ${counts?.has_kev_cve ? styles.kev : styles.hot}`}
          title={
            counts?.has_kev_cve
              ? "CISA KEV CVE (actively exploited) with no detection rules — top detection engineering opportunity"
              : "High-risk CVE (high EPSS / weaponized) with no detection rules — priority detection engineering opportunity"
          }
        >
          {counts?.has_kev_cve ? "KEV opportunity" : "high-risk opportunity"}
        </span>
      ) : opportunity === "actionable_gap" ? (
        <span
          className={`${styles.chip} ${styles.gap}`}
          title="No detection rule exists for the observed TTPs/CVEs — actionable detection engineering opportunity"
        >
          detection opportunity
        </span>
      ) : opportunity === "telemetry_gap" ? (
        <span
          className={`${styles.chip} ${styles.tel}`}
          title="Library rules exist for the observed TTPs, but their required data sources aren't in your telemetry inventory"
        >
          telemetry gap
        </span>
      ) : null}
    </span>
  );
}
