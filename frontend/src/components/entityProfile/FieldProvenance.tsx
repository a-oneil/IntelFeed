/**
 * FieldProvenance — the "who says so" marker that sits beside a profile field.
 *
 * The relationship trust ladder already shows the evidence behind a link
 * between two entities. This is the same idea for the scalar facts on a
 * profile: click the marker beside a field and get every source that asserted
 * its value — the analyst, adapter or reference feed, the article and its feed
 * (with the feed's A–F grade), and the sentence behind it where one exists.
 *
 * Three states, and the third is the point: a field can be **sourced** (marker
 * shows how many sources agree), **contested** (at least one source asserted a
 * different value than the profile now shows), or **unsourced** — populated but
 * attributable to nothing. An unsourced field is marked, not hidden, because a
 * fact nobody can vouch for is exactly the one an analyst needs flagged.
 */
import { useEffect, useRef, useState } from "react";

import { formatDate } from "@/utils/formatDate";
import type { FieldClaim, FieldProvenanceBucket } from "@/hooks/useEntityProvenance";
import { Hint } from "@/components/primitives";

import styles from "./FieldProvenance.module.css";

/** Admiralty-style grade colouring: A/B trusted, C/D mixed, E/F weak. */
function gradeClass(grade: string | null): string {
  if (!grade) return styles.gradeNone;
  if (grade === "A" || grade === "B") return styles.gradeHigh;
  if (grade === "C" || grade === "D") return styles.gradeMid;
  return styles.gradeLow;
}

function ClaimRow({ claim, onOpenArticle }: { claim: FieldClaim; onOpenArticle?: (entryId: string) => void }) {
  return (
    <li className={`${styles.claim} ${claim.agrees === false ? styles.claimStale : ""}`}>
      <div className={styles.claimHead}>
        <span className={`${styles.kind} ${styles[`kind_${claim.source_kind}`] ?? ""}`}>
          {claim.source_label}
        </span>
        {claim.source_ref && <span className={styles.ref}>{claim.source_ref}</span>}
        {claim.analyst && <span className={styles.ref}>{claim.analyst}</span>}
        {claim.confidence && <span className={styles.conf}>{claim.confidence} confidence</span>}
        <span className={styles.when}>
          {claim.last_asserted_at ? formatDate(claim.last_asserted_at) : ""}
        </span>
      </div>

      {claim.agrees === false && (
        <div className={styles.stale}>
          Asserted a different value than the profile shows now:
          <span className={styles.staleValue}>{claim.value}</span>
        </div>
      )}

      {claim.entry && (
        <div className={styles.article}>
          <button
            className={styles.articleLink}
            onClick={() => claim.entry && onOpenArticle?.(claim.entry.id)}
            disabled={!onOpenArticle}
          >
            {claim.entry.title || "Untitled article"}
          </button>
          <span className={styles.articleMeta}>
            {claim.entry.feed_title}
            {claim.entry.feed_reliability ? (
              <span className={`${styles.grade} ${gradeClass(claim.entry.feed_reliability)}`}>
                {claim.entry.feed_reliability}
              </span>
            ) : (
              <span className={`${styles.grade} ${styles.gradeNone}`} title="This feed has no reliability grade set">
                ungraded
              </span>
            )}
            {claim.entry.published_at && <span> · {formatDate(claim.entry.published_at)}</span>}
          </span>
        </div>
      )}

      {claim.quote && <blockquote className={styles.quote}>{claim.quote}</blockquote>}
    </li>
  );
}

export function FieldProvenance({
  field,
  label,
  bucket,
  unsourced,
  onOpenArticle,
}: {
  field: string;
  /** Human name of the field, used in the popover heading. */
  label: string;
  bucket?: FieldProvenanceBucket;
  /** True when the field holds a value that no claim accounts for. */
  unsourced?: boolean;
  onOpenArticle?: (entryId: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [alignRight, setAlignRight] = useState(false);
  const wrapRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!wrapRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const claims = bucket?.claims ?? [];
  if (!claims.length && !unsourced) return null;

  const conflicting = bucket?.conflicting ?? 0;
  const agreeing = bucket?.agreeing ?? 0;

  const state = unsourced ? "unsourced" : conflicting > 0 ? "contested" : "sourced";
  const marker = unsourced ? "?" : conflicting > 0 ? "!" : String(agreeing || claims.length);
  const title = unsourced
    ? `${label} has no recorded source`
    : conflicting > 0
      ? `${agreeing} source${agreeing === 1 ? "" : "s"} agree, ${conflicting} asserted something else`
      : `${agreeing || claims.length} source${(agreeing || claims.length) === 1 ? "" : "s"}`;

  return (
    <span className={styles.wrap} ref={wrapRef}>
      <Hint
        title="Where this came from"
        body="Every field on a dossier records what asserted it and whether the sources agree."
        aside={`${title} — click to see the claims.`}
        place="left"
        align="center"
        disabled={open}
      >
      <button
        className={`${styles.marker} ${styles[state]}`}
        onClick={() =>
          setOpen((v) => {
            const next = !v;
            if (next && wrapRef.current) {
              // Flip to right-aligned when the popover would run off the
              // viewport — markers often sit near its right edge.
              const r = wrapRef.current.getBoundingClientRect();
              const popWidth = Math.min(420, window.innerWidth * 0.78);
              setAlignRight(r.left + popWidth > window.innerWidth - 12);
            }
            return next;
          })
        }
        aria-expanded={open}
        aria-label={`Sources for ${label}`}
      >
        {marker}
      </button>
      </Hint>

      {open && (
        <div
          className={`${styles.pop} ${alignRight ? styles.popRight : ""}`}
          role="dialog"
          aria-label={`Sources for ${label}`}
        >
          <div className={styles.popHead}>
            <span className={styles.popTitle}>{label}</span>
            <span className={styles.popCount}>{title}</span>
          </div>

          {unsourced ? (
            <p className={styles.unsourcedBody}>
              This value is on the profile but nothing recorded where it came from &mdash; it predates
              provenance tracking, or was written by a path that doesn&rsquo;t report one. Editing the
              field records you as its source.
            </p>
          ) : (
            <ul className={styles.claims}>
              {claims.map((c) => (
                <ClaimRow key={c.id} claim={c} onOpenArticle={onOpenArticle} />
              ))}
            </ul>
          )}
          <span className={styles.fieldName}>{field}</span>
        </div>
      )}
    </span>
  );
}
