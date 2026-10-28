/**
 * ContextPanel — what the enabled enrichment sources say about this entity,
 * one block per source, each item drawn by the display type its manifest
 * declares (fact / chips / table / timeline / link). No per-source code lives
 * here: a new source shows up by declaring outputs. Badge items go to the
 * header instead (ProfileHeader).
 *
 * The enrichment controls live in the header: Refresh re-runs every source
 * that applies, ↻ on a block re-runs that one. A source that is rate-limited
 * queues the lookup; the panel says so in one quiet line. Visitors read it
 * with no buttons.
 */
import { useState } from "react";
import { Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { Chip, Hint } from "@/components/primitives";
import { useEnrichEntity } from "@/hooks/useEnrichment";
import {
  entityContextKey,
  useEntityContext,
  type ContextLinkValue,
  type EntityContextItem,
  type EntityContextSource,
} from "@/hooks/useEntityContext";
import { useIsAdmin, useIsVisitor } from "@/stores/authStore";
import { formatDateTime } from "@/utils/formatDate";
import styles from "./ContextPanel.module.css";

/** Where an admin fixes a missing key or a paused source. */
const ENRICHMENT_CONSOLE = "/settings?section=enrichment";

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
  return needs === "api_key" ? "API key" : needs.replace(/_/g, " ");
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

/** A value longer than this reads as prose, on its own line under its label. */
const PROSE_AT = 48;
/** Prose longer than this starts clamped, with a toggle. */
const CLAMP_AT = 240;
const ISO_DATETIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;

function factText(value: string | number): string {
  const text = String(value);
  return ISO_DATETIME.test(text) ? formatDateTime(text, text) : text;
}

function ProseFact({ label, text }: { label: string; text: string }) {
  const [open, setOpen] = useState(false);
  const long = text.length > CLAMP_AT;
  return (
    <div className={styles.block}>
      <dt className={styles.key}>{label}</dt>
      <dd className={`${styles.prose} ${long && !open ? styles.clamped : ""}`}>{text}</dd>
      {long && (
        <button type="button" className={styles.more} onClick={() => setOpen((o) => !o)} aria-expanded={open}>
          {open ? "less" : "more"}
        </button>
      )}
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
}: {
  source: EntityContextSource;
  /** Absent for visitors and anyone who can't enrich. */
  onRefresh?: () => void;
  busy: boolean;
}) {
  const items = source.items.filter(hasValue);
  const age = shortAge(source.observed_at);
  return (
    <section className={styles.source} aria-label={source.label}>
      <div className={styles.sourceHead}>
        <span className={styles.sourceName}>{source.label}</span>
        <span className={styles.age} title={source.observed_at ?? undefined}>
          {age}
          {source.stale && <span className={styles.stale}>{age ? " · " : ""}stale</span>}
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
    </section>
  );
}

export function ContextPanel({ entityType, entityId }: { entityType: string; entityId: string }) {
  const { data } = useEntityContext(entityType, entityId);
  const isVisitor = useIsVisitor();
  const isAdmin = useIsAdmin();
  const enrich = useEnrichEntity();
  const qc = useQueryClient();
  const [queued, setQueued] = useState<string[]>([]);

  if (!data) return null;
  const sources = data.sources ?? [];
  const unavailable = data.unavailable ?? [];
  if (sources.length === 0 && unavailable.length === 0) return null;

  const withData = sources.filter((s) => s.items.some(hasValue));
  const canEnrich = data.can_enrich && !isVisitor && sources.length > 0;
  // Nothing to read and nothing to press: a visitor gets no empty shell.
  if (withData.length === 0 && unavailable.length === 0 && !canEnrich) return null;

  const labelOf = (sourceType: string) => sources.find((s) => s.source_type === sourceType)?.label ?? sourceType;
  const run = (sourceTypes?: string[], refresh = false) => {
    setQueued([]);
    enrich.mutate(
      { entityType, entityId, sourceTypes, refresh },
      {
        onSuccess: (res) => {
          setQueued(res.queued ?? []);
          return qc.invalidateQueries({ queryKey: entityContextKey(entityType, entityId) });
        },
      },
    );
  };

  const summary = [
    `${sources.length} source${sources.length === 1 ? "" : "s"}`,
    ...(unavailable.length ? [`${unavailable.length} unavailable`] : []),
  ].join(" · ");

  return (
    <div className={styles.panel}>
      <div className={styles.head}>
        <span className={styles.title}>Context</span>
        <span className={styles.summary}>{summary}</span>
        {canEnrich && withData.length > 0 && (
          <Hint
            title="Refresh"
            body="Looks this up again at every source that applies."
            aside="A rate-limited source queues the lookup and runs it when it can."
          >
            <button type="button" className={styles.btn} onClick={() => run(undefined, true)} disabled={enrich.isPending}>
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

      {withData.map((s) => (
        <SourceBlock
          key={s.source_type}
          source={s}
          busy={enrich.isPending}
          onRefresh={canEnrich ? () => run([s.source_type], true) : undefined}
        />
      ))}

      {withData.length === 0 && canEnrich && (
        <div className={styles.ghost}>
          <span>No context yet</span>
          <button type="button" className={styles.btn} onClick={() => run()} disabled={enrich.isPending}>
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
            <Link className={styles.ghostLink} to={ENRICHMENT_CONSOLE}>
              Open Enrichment
            </Link>
          )}
        </div>
      ))}
    </div>
  );
}
