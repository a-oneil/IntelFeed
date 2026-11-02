/**
 * ContextPanel — what the enabled enrichment sources say about this entity,
 * one block per source, each item drawn by the display type its manifest
 * declares (fact / chips / table / timeline / link). No per-source code lives
 * here: a new source shows up by declaring outputs. Badge items go to the
 * header instead (ProfileHeader).
 *
 * It is the Overview's Context section. Each source is a row that opens in
 * place: closed, it shows a digest of its first facts; the first source with
 * data starts open. The enrichment controls live in the header: Refresh
 * re-runs every source that applies, ↻ on a row re-runs that one. Each row
 * says when the source last answered and whether that answer is still fresh.
 * A source that is rate-limited queues the lookup (manual lane); the panel
 * says so in one quiet line. Visitors read it with no enrichment buttons.
 *
 * A CVE also gets "CVSS by source": every source's score from the field
 * claims, its vector from that source's context, and which one is shown.
 */
import { useId, useLayoutEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { Chip, Hint } from "@/components/primitives";
import { useEnrichEntity } from "@/hooks/useEnrichment";
import { useEntityProvenance, type FieldClaim } from "@/hooks/useEntityProvenance";
import {
  entityContextKey,
  useEntityContext,
  type ContextLinkValue,
  type EntityContext,
  type EntityContextItem,
  type EntityContextSource,
} from "@/hooks/useEntityContext";
import { useIsAdmin, useIsVisitor } from "@/stores/authStore";
import { formatDateTime } from "@/utils/formatDate";
import styles from "./ContextPanel.module.css";

/** Where an admin adds a missing key: the console's Keys view, at that source's
 * key. The entity popover's "Add key" goes to the same place. */
export const keyLink = (sourceType: string) =>
  `/settings?section=enrichment&key_for=${encodeURIComponent(sourceType)}`;

/** "2h", "3d" — the block header has room for a word, not a sentence. */
function shortAge(iso: string | null): string {
  if (!iso) return "";
  const ms = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(ms)) return "";
  const min = Math.floor(ms / 60_000);
  if (min < 1) return "now";
  if (min < 60) return `${min}m`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h}h`;
  const d = Math.floor(h / 24);
  if (d < 60) return `${d}d`;
  if (d < 730) return `${Math.floor(d / 30)}mo`;
  return `${Math.floor(d / 365)}y`;
}

function needsLabel(needs: string): string {
  return needs === "api_key" ? "key" : needs.replace(/_/g, " ");
}

function hasValue(item: EntityContextItem): boolean {
  switch (item.display) {
    case "badge":
      return false;
    case "fact":
      return item.value !== null && item.value !== undefined && String(item.value) !== "";
    case "chips":
    case "timeline":
      return Array.isArray(item.value) && item.value.length > 0;
    case "table":
      return !!item.value && item.value.rows?.length > 0;
    case "link":
      return !!linkParts(item.value).url;
  }
}

function linkParts(value: ContextLinkValue): { url: string; text: string } {
  return { url: value?.url ?? "", text: value?.label || value?.url || "" };
}

const DIGEST_ITEMS = 3;
const DIGEST_VALUE_CHARS = 40;

/** A closed row's one line: its first few facts, each "Label value". */
function sourceDigest(items: EntityContextItem[]): string {
  const parts: string[] = [];
  for (const item of items) {
    if (parts.length === DIGEST_ITEMS) break;
    switch (item.display) {
      case "fact": {
        const text = factText(item.value);
        parts.push(`${item.label} ${text.length > DIGEST_VALUE_CHARS ? `${text.slice(0, DIGEST_VALUE_CHARS).trimEnd()}…` : text}`);
        break;
      }
      case "link":
        parts.push(item.label);
        break;
      case "chips":
      case "timeline":
        parts.push(`${item.label} ${item.value.length}`);
        break;
      case "table":
        parts.push(`${item.label} ${item.value.rows.length} row${item.value.rows.length === 1 ? "" : "s"}`);
        break;
      case "badge":
        break;
    }
  }
  return parts.join(" · ");
}

/** The sources that have answered with at least one value. */
export function contextSourcesWithData(data: EntityContext | undefined): EntityContextSource[] {
  return (data?.sources ?? []).filter((s) => s.items.some(hasValue));
}

/**
 * The Overview section row's digest for Context: which sources answered and
 * how fresh they are, or that nothing has been looked up yet and how many
 * sources would answer. Null when no source applies to the entity at all
 * (the section then hides).
 */
export function contextDigest(data: EntityContext | undefined): string | null {
  if (!data) return null;
  const sources = data.sources ?? [];
  const unavailable = data.unavailable ?? [];
  if (sources.length === 0 && unavailable.length === 0) return null;
  const withData = contextSourcesWithData(data);
  const parts: string[] = [];
  if (withData.length > 0) {
    parts.push(withData.map((s) => s.label).join(" · "));
    const stale = withData.filter((s) => s.stale).length;
    parts.push(
      stale === 0 ? "all fresh" : stale === withData.length ? "all stale" : `${stale} stale, ${withData.length - stale} fresh`,
    );
  } else if (sources.length > 0) {
    parts.push(`Not looked up yet · ${sources.length} source${sources.length === 1 ? "" : "s"} appl${sources.length === 1 ? "ies" : "y"}`);
  }
  // A source with data reads as answered, whatever it lacks now.
  const answered = new Set(withData.map((s) => s.source_type));
  const missing = unavailable.filter((u) => !answered.has(u.source_type)).length;
  if (missing > 0) parts.push(`${missing} need${missing === 1 ? "s" : ""} a key`);
  return parts.join(" · ");
}

/** A value longer than this reads as prose, on its own line under its label. */
const PROSE_AT = 48;
const ISO_DATETIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;
const HAS_ZONE = /(Z|[+-]\d{2}:?\d{2})$/i;
/** abuse.ch's "2024-04-12 08:15:06 UTC". */
const SPACED_UTC = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}(?::\d{2})?) UTC$/;

function factText(value: string | number): string {
  const text = String(value);
  const spaced = SPACED_UTC.exec(text);
  const iso = spaced ? `${spaced[1]}T${spaced[2]}Z` : text;
  if (!ISO_DATETIME.test(iso)) return text;
  // A timestamp with no zone is UTC (NVD's "2024-04-12T08:15:06.230");
  // new Date() would read it as local time.
  return formatDateTime(HAS_ZONE.test(iso) ? iso : `${iso}Z`, text);
}

/** Prose clamps to four lines; the toggle shows only when the text runs past them. */
function ProseFact({ label, text }: { label: string; text: string }) {
  const id = useId();
  const ref = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [overflows, setOverflows] = useState(false);
  useLayoutEffect(() => {
    const el = ref.current;
    if (el && !open) setOverflows(el.scrollHeight > el.clientHeight);
  }, [text, open]);
  return (
    <div className={styles.block}>
      <dt className={styles.key}>{label}</dt>
      <dd>
        <div id={id} ref={ref} className={`${styles.prose} ${open ? "" : styles.clamped}`}>
          {text}
        </div>
        {overflows && (
          <button
            type="button"
            className={styles.more}
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
            aria-controls={id}
            aria-label={`Show ${open ? "less" : "more"} of ${label}`}
          >
            {open ? "less" : "more"}
          </button>
        )}
      </dd>
    </div>
  );
}

function ItemView({ item }: { item: EntityContextItem }) {
  switch (item.display) {
    case "fact": {
      const text = factText(item.value);
      if (text.length > PROSE_AT) return <ProseFact label={item.label} text={text} />;
      return (
        <div className={styles.fact}>
          <dt className={styles.key}>{item.label}</dt>
          <dd className={styles.val}>{text}</dd>
        </div>
      );
    }
    case "link": {
      const { url, text } = linkParts(item.value);
      return (
        <div className={styles.fact}>
          <dt className={styles.key}>{item.label}</dt>
          <dd className={styles.val}>
            <a className={styles.link} href={url} target="_blank" rel="noopener noreferrer" title={url}>
              {text} ↗
            </a>
          </dd>
        </div>
      );
    }
    case "chips":
      return (
        <div className={styles.block}>
          <dt className={styles.key}>{item.label}</dt>
          <dd className={styles.chips}>
            {item.value.map((v) => (
              <Chip key={v} tone="quiet" size="sm">
                {v}
              </Chip>
            ))}
          </dd>
        </div>
      );
    case "timeline":
      return (
        <div className={styles.block}>
          <dt className={styles.key}>{item.label}</dt>
          <dd>
            <ol className={styles.timeline}>
              {item.value.map((ev, i) => (
                <li key={`${ev.date}-${i}`} className={styles.event}>
                  <span className={styles.date}>{ev.date}</span>
                  <span>{ev.text}</span>
                </li>
              ))}
            </ol>
          </dd>
        </div>
      );
    case "table":
      return (
        <div className={styles.block}>
          <dt className={styles.key}>{item.label}</dt>
          <dd className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  {item.value.columns.map((c) => (
                    <th key={c} scope="col">
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {item.value.rows.map((row, r) => (
                  <tr key={r}>
                    {row.map((cell, c) => (
                      <td key={c}>{cell ?? "—"}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </dd>
        </div>
      );
    case "badge":
      return null;
  }
}

function SourceBlock({
  source,
  onRefresh,
  busy,
  open,
  onToggle,
}: {
  source: EntityContextSource;
  /** Absent for visitors and anyone who can't enrich. */
  onRefresh?: () => void;
  busy: boolean;
  open: boolean;
  onToggle: () => void;
}) {
  const items = source.items.filter(hasValue);
  const age = shortAge(source.observed_at);
  const lastRun = source.observed_at ? `Last looked up ${formatDateTime(source.observed_at, source.observed_at)}` : undefined;
  const bodyId = useId();
  return (
    <section className={styles.source} aria-label={source.label}>
      <div className={styles.sourceHead}>
        <button
          type="button"
          className={styles.sourceToggle}
          onClick={onToggle}
          aria-expanded={open}
          aria-controls={bodyId}
        >
          <svg className={`${styles.caret} ${open ? styles.caretOpen : ""}`} viewBox="0 0 16 16" aria-hidden="true">
            <path d="M6 3.5 10.5 8 6 12.5" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span className={styles.sourceName}>{source.label}</span>
          {!open && <span className={styles.sourceDigest}>{sourceDigest(items)}</span>}
        </button>
        <span className={styles.age} title={lastRun}>
          {age}
          {age ? " · " : ""}
          {source.stale ? <span className={styles.stale}>stale</span> : "fresh"}
        </span>
        {onRefresh && (
          <button
            type="button"
            className={styles.iconBtn}
            onClick={onRefresh}
            disabled={busy}
            aria-label={`Refresh ${source.label}`}
            title={`Look this up again at ${source.label}`}
          >
            ↻
          </button>
        )}
      </div>
      {open && (
        <div id={bodyId}>
          <dl className={styles.items}>
            {items.map((item) => (
              <ItemView key={item.key} item={item} />
            ))}
          </dl>
          {source.license && (
            <div className={styles.license}>
              {source.license.name}
              {source.license.attribution ? ` · ${source.license.attribution}` : ""}
            </div>
          )}
        </div>
      )}
    </section>
  );
}

/** "nvd" → "NVD"; "cvelist:adp" → "CVE record · ADP". */
const CVSS_SOURCE: Record<string, string> = { nvd: "NVD", cvelist: "CVE record", cna: "CNA", adp: "ADP" };

interface CvssRow {
  key: string;
  source: string;
  score: string;
  vector: string | null;
  shown: boolean;
}

function cvssRows(claims: FieldClaim[], sources: EntityContextSource[]): CvssRow[] {
  const vectorOf = (sourceType: string): string | null => {
    const item = sources.find((s) => s.source_type === sourceType)?.items.find((i) => i.key === "cvss_vector");
    return item && item.display === "fact" && item.value != null ? String(item.value) : null;
  };
  const labelOf = (ref: string): string => {
    const [base, part] = ref.split(":");
    const name = sources.find((s) => s.source_type === base)?.label ?? CVSS_SOURCE[base] ?? base;
    return part ? `${name} · ${CVSS_SOURCE[part] ?? part.toUpperCase()}` : name;
  };
  // One source's latest run only: a value it has since replaced drops out,
  // while two values from that run (a CNA and an ADP score) both stay.
  const latest = new Map<string, string>();
  for (const c of claims) {
    const key = c.source_kind === "enrichment" ? (c.source_ref ?? "enrichment") : c.source_kind;
    const at = c.last_asserted_at ?? "";
    if (at > (latest.get(key) ?? "")) latest.set(key, at);
  }
  const rows: CvssRow[] = [];
  const seen = new Set<string>();
  for (const c of claims) {
    const key = c.source_kind === "enrichment" ? (c.source_ref ?? "enrichment") : c.source_kind;
    if ((c.last_asserted_at ?? "") !== (latest.get(key) ?? "") || seen.has(`${key}|${c.value}`)) continue;
    seen.add(`${key}|${c.value}`);
    const enrichment = c.source_kind === "enrichment" && !!c.source_ref;
    rows.push({
      key: `${key}|${c.value}`,
      source: enrichment ? labelOf(c.source_ref!) : c.source_label,
      score: c.value,
      vector: enrichment ? vectorOf(c.source_ref!.split(":")[0]) : null,
      shown: c.agrees === true,
    });
  }
  // The one on the profile first, then the rest as the sources sent them.
  return rows.sort((a, b) => Number(b.shown) - Number(a.shown));
}

/** A row like the source rows: starts open, closes to one line of scores. */
function CvssBySource({ rows }: { rows: CvssRow[] }) {
  const [open, setOpen] = useState(true);
  const bodyId = useId();
  return (
    <section className={styles.source} aria-label="CVSS by source">
      <div className={styles.sourceHead}>
        <button
          type="button"
          className={styles.sourceToggle}
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          aria-controls={bodyId}
        >
          <svg className={`${styles.caret} ${open ? styles.caretOpen : ""}`} viewBox="0 0 16 16" aria-hidden="true">
            <path d="M6 3.5 10.5 8 6 12.5" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span className={styles.sourceName}>CVSS by source</span>
          {!open && (
            <span className={styles.sourceDigest}>
              {rows.slice(0, DIGEST_ITEMS).map((r) => `${r.source} ${r.score}`).join(" · ")}
            </span>
          )}
        </button>
        <span className={styles.age}>highest rank shown</span>
      </div>
      {open && (
        <dl id={bodyId} className={styles.items}>
          {rows.map((r) => (
            <div key={r.key} className={styles.fact}>
              <dt className={styles.key}>{r.source}</dt>
              <dd className={styles.val}>
                {r.score}
                {r.vector && <span className={styles.vector}> · {r.vector}</span>}
                <span className={r.shown ? styles.shownTag : styles.claimTag}>{r.shown ? "shown" : "claim"}</span>
              </dd>
            </div>
          ))}
        </dl>
      )}
    </section>
  );
}

export function ContextPanel({ entityType, entityId }: { entityType: string; entityId: string }) {
  const { data } = useEntityContext(entityType, entityId);
  // Same query (and key) as the profile header's provenance markers.
  const { data: provenance } = useEntityProvenance(entityType === "cve" ? entityType : undefined, entityId);
  const isVisitor = useIsVisitor();
  const isAdmin = useIsAdmin();
  const enrich = useEnrichEntity();
  const qc = useQueryClient();
  const [queued, setQueued] = useState<string[]>([]);
  // Lookups that failed on the last press: they stay listed with a retry
  // instead of vanishing.
  const [failed, setFailed] = useState<Array<{ source_type: string; error?: string }>>([]);
  // Rows the analyst opened or closed here; anything else follows the default
  // (first source with data open, the rest closed).
  const [openSources, setOpenSources] = useState<Record<string, boolean>>({});

  if (!data) return null;
  const sources = data.sources ?? [];
  // A source that answered before its key went missing shows its block, not
  // a "needs key" row as well.
  const answered = new Set(contextSourcesWithData(data).map((s) => s.source_type));
  const unavailable = (data.unavailable ?? []).filter((u) => !answered.has(u.source_type));
  const cvss = cvssRows(provenance?.fields?.cvss_score?.claims ?? [], sources);
  if (sources.length === 0 && unavailable.length === 0 && cvss.length === 0) return null;

  const withData = contextSourcesWithData(data);
  const canEnrich = data.can_enrich && !isVisitor && sources.length > 0;
  // Nothing to read and nothing to press: a visitor gets no empty section.
  if (withData.length === 0 && unavailable.length === 0 && cvss.length === 0 && !canEnrich) return null;

  const labelOf = (sourceType: string) => sources.find((s) => s.source_type === sourceType)?.label ?? sourceType;
  // Named explicitly: with no list the server runs only manual-mode sources.
  const allSources = sources.map((s) => s.source_type);
  const run = (sourceTypes: string[], refresh = false) => {
    setQueued([]);
    setFailed((prev) => prev.filter((f) => !sourceTypes.includes(f.source_type)));
    enrich.mutate(
      { entityType, entityId, sourceTypes, refresh },
      {
        onSuccess: (res) => {
          setQueued(res.queued ?? []);
          setFailed((prev) => [
            ...prev,
            ...(res.results ?? []).filter((r) => r.status === "error").map((r) => ({ source_type: r.source_type, error: r.error })),
          ]);
          return qc.invalidateQueries({ queryKey: entityContextKey(entityType, entityId) });
        },
      },
    );
  };

  const needKey = unavailable.filter((u) => u.needs === "api_key").length;
  const otherNeeds = unavailable.length - needKey;
  // Counts the source blocks shown, not every source that applies.
  const summary = [
    withData.length > 0 ? `${withData.length} source${withData.length === 1 ? "" : "s"}` : "nothing looked up yet",
    ...(needKey ? [`${needKey} need${needKey === 1 ? "s" : ""} key`] : []),
    ...(otherNeeds ? [`${otherNeeds} unavailable`] : []),
  ].join(" · ");

  return (
    <section className={styles.panel} aria-labelledby={`context-${entityId}`}>
      <div className={styles.head}>
        <h3 className={styles.title} id={`context-${entityId}`}>
          Context
        </h3>
        <span className={styles.summary}>{summary}</span>
        {canEnrich && withData.length > 0 && (
          <Hint
            title="Refresh"
            body="Looks this up again at every source that applies."
            aside="A rate-limited source queues the lookup and runs it when it can."
          >
            <button type="button" className={styles.btn} onClick={() => run(allSources, true)} disabled={enrich.isPending}>
              {enrich.isPending ? "Refreshing…" : "Refresh"}
            </button>
          </Hint>
        )}
      </div>

      {queued.length > 0 && (
        <div className={styles.note} role="status">
          queued: {queued.map(labelOf).join(", ")}
        </div>
      )}

      {withData.map((s, i) => {
        const open = openSources[s.source_type] ?? i === 0;
        return (
          <SourceBlock
            key={s.source_type}
            source={s}
            busy={enrich.isPending}
            onRefresh={canEnrich ? () => run([s.source_type], true) : undefined}
            open={open}
            onToggle={() => setOpenSources((prev) => ({ ...prev, [s.source_type]: !open }))}
          />
        );
      })}

      {failed.map((f) => (
        <div key={f.source_type} className={styles.ghost} role="status">
          <span>
            {labelOf(f.source_type)} · lookup failed{f.error ? `: ${f.error}` : ""}
          </span>
          {canEnrich && (
            <button type="button" className={styles.btn} onClick={() => run([f.source_type], true)} disabled={enrich.isPending}>
              Retry
            </button>
          )}
        </div>
      ))}

      {cvss.length > 0 && <CvssBySource rows={cvss} />}

      {withData.length === 0 && canEnrich && (
        <div className={styles.ghost}>
          <span>No context yet</span>
          <button type="button" className={styles.btn} onClick={() => run(allSources)} disabled={enrich.isPending}>
            {enrich.isPending ? "Enriching…" : "Enrich now"}
          </button>
        </div>
      )}

      {unavailable.map((u) => (
        <div key={u.source_type} className={styles.ghost}>
          <span>
            {u.label} · needs {needsLabel(u.needs)}
          </span>
          {isAdmin && !isVisitor && (
            <Link className={styles.ghostLink} to={keyLink(u.source_type)}>
              {u.needs === "api_key" ? "Add key" : "Open Enrichment"}
            </Link>
          )}
        </div>
      ))}
    </section>
  );
}
