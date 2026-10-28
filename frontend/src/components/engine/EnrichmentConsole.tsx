/**
 * Settings → Engine → Enrichment: one page for sources, jobs, queue and
 * coverage. The table answers three questions per source — is it on, does it
 * work, what does it fill — and everything else (limits, usage, queue, fill
 * rates, jobs) is one click away in the expanded row. Color only marks things
 * that need action.
 */
import { Fragment, useContext, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import SystemSettings, { SettingsHighlightContext } from "@/components/SystemSettings";
import { AsyncStateLoading } from "@/components/AsyncState";
import { Hint } from "@/components/primitives";
import { useEnrichGap, useEnrichmentGaps } from "@/hooks/useHygiene";
import {
  useEnrichmentConsole,
  useEnrichmentSources,
  usePauseEnrichment,
  useUpdateEnrichmentSource,
  type EnrichmentConsoleSource,
  type EnrichmentSourceStatus,
} from "@/hooks/useEnrichment";
import type { EnrichmentSource } from "@/api/types";
import { getEntityLabel } from "@/utils/entityTheme";

import { SourceDetail } from "./EnrichmentSourceDetail";
import s from "./EnrichmentConsole.module.css";

const STATUS_WORD: Record<EnrichmentSourceStatus, string> = {
  ok: "ok",
  failing: "failing",
  off: "off",
  needs_key: "needs key",
};

const num = (n: number) => n.toLocaleString("en-US");

export function EnrichmentConsole({ initialSource }: { initialSource?: string | null }) {
  const [tab, setTab] = useState<string>("all");
  const [attentionOnly, setAttentionOnly] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(initialSource ?? null);
  const [editing, setEditing] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);

  const qc = useQueryClient();
  const consoleQ = useEnrichmentConsole(tab === "all" ? undefined : tab);
  const { data: rows } = useEnrichmentSources();
  const pause = usePauseEnrichment();
  const update = useUpdateEnrichmentSource();

  const rowByType = useMemo(() => {
    const m = new Map<string, EnrichmentSource>();
    for (const r of rows ?? []) m.set(r.source_type, r);
    return m;
  }, [rows]);

  const data = consoleQ.data;
  if (!data) {
    return consoleQ.isError ? (
      <p className={s.note}>Couldn't load the enrichment console.</p>
    ) : (
      <AsyncStateLoading label="Loading enrichment…" />
    );
  }

  const { summary } = data;
  const visible = attentionOnly ? data.sources.filter((x) => x.attention) : data.sources;
  const addable = data.sources.filter((x) => x.status === "off" || x.status === "needs_key");

  const setEnabled = (src: EnrichmentConsoleSource, on: boolean) => {
    const row = rowByType.get(src.source_type);
    if (!row) return;
    update.mutate(
      { sourceId: row.id, is_enabled: on },
      {
        onSuccess: () => qc.invalidateQueries({ queryKey: ["enrichment-console"] }),
        onError: (e) => toast.error(`Couldn't update ${src.label}: ${(e as Error).message}`),
      },
    );
  };

  const toggleExpand = (type: string) => {
    setExpanded((cur) => (cur === type ? null : type));
    setEditing(null);
  };

  const openForKey = (type: string) => {
    setAddOpen(false);
    setAttentionOnly(false);
    setExpanded(type);
    setEditing(type);
  };

  const togglePause = () =>
    pause.mutate(!summary.paused, {
      onError: (e) => toast.error(`Couldn't change pause: ${(e as Error).message}`),
    });

  return (
    <div className={s.page}>
      <div className={s.head}>
        <span className={s.line}>
          {summary.sources_on} of {summary.sources_total} sources on
          {summary.needs_attention > 0 && (
            <>
              {" · "}
              <button
                type="button"
                className={s.attn}
                aria-pressed={attentionOnly}
                onClick={() => setAttentionOnly((v) => !v)}
              >
                {summary.needs_attention} need{summary.needs_attention === 1 ? "s" : ""} attention
              </button>
            </>
          )}
          {attentionOnly && (
            <button type="button" className={s.link} onClick={() => setAttentionOnly(false)}>
              show all
            </button>
          )}
        </span>
        <span className={s.spacer} />
        <Hint
          title={summary.paused ? "Resume enrichment" : "Pause enrichment"}
          body="Stops every request to outside sources at once. Queued lookups wait and resume when you unpause."
        >
          <button type="button" className={s.btn} onClick={togglePause} disabled={pause.isPending}>
            {summary.paused ? "Resume enrichment" : "Pause enrichment"}
          </button>
        </Hint>
        <button
          type="button"
          className={s.btn}
          aria-expanded={addOpen}
          aria-controls="enrichment-add-source"
          onClick={() => setAddOpen((v) => !v)}
        >
          Add source
        </button>
      </div>

      {summary.paused ? (
        <p className={s.warn}>
          Enrichment is paused. No requests leave the box; lookups wait in the queue until you resume.
        </p>
      ) : (
        <p className={s.note}>
          Pause stops all calls to outside sources at once, for example when an API starts rate-limiting
          or bans the key. Per-source settings don't change.
        </p>
      )}

      {addOpen && (
        <div id="enrichment-add-source" className={s.addList}>
          {addable.length === 0 && <p className={s.note}>Every available source is on.</p>}
          {addable.map((x) => (
            <div key={x.source_type} className={s.addRow}>
              <span className={s.addName}>{x.label}</span>
              <span className={s.muted}>{x.fills}</span>
              {x.status === "needs_key" ? (
                <button type="button" className={s.link} onClick={() => openForKey(x.source_type)}>
                  Add key
                </button>
              ) : (
                <button
                  type="button"
                  className={s.link}
                  disabled={!rowByType.has(x.source_type)}
                  onClick={() => setEnabled(x, true)}
                >
                  Turn on
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      <details className={s.activity} open={!summary.redis_ok || undefined}>
        <summary>Activity · last 24h</summary>
        <div className={s.activityBody}>
          {num(summary.activity_24h.requests)} requests · {num(summary.activity_24h.queued)} queued ·{" "}
          {num(summary.activity_24h.deferred)} deferred (rate limit or budget) ·{" "}
          {num(summary.activity_24h.iocs_sent_off_box)} indicators sent off-box ·{" "}
          {summary.redis_ok ? (
            "Redis ok, fails closed"
          ) : (
            <span className={s.bad}>Redis unreachable: every request is refused until it's back</span>
          )}
        </div>
      </details>

      <div className={s.tabs} role="tablist" aria-label="Filter by entity type">
        <TabButton id="all" label="All" count={summary.sources_total} tab={tab} setTab={setTab} />
        {data.entity_types.map((t) => (
          <TabButton
            key={t.entity_type}
            id={t.entity_type}
            label={t.label}
            count={t.source_count}
            tab={tab}
            setTab={setTab}
          />
        ))}
      </div>

      <div className={s.scroll} role="tabpanel">
        <table className={s.table}>
          <thead>
            <tr>
              <th>Source</th>
              <th>Status</th>
              <th>Fills</th>
              <th className={s.on}>On</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((x) => {
              const open = expanded === x.source_type;
              const detailId = `enrichment-detail-${x.source_type}`;
              return (
                <Fragment key={x.source_type}>
                  <tr className={open ? s.open : undefined} onClick={() => toggleExpand(x.source_type)}>
                    <td>
                      <button
                        type="button"
                        className={s.expander}
                        aria-expanded={open}
                        aria-controls={open ? detailId : undefined}
                        onClick={(e) => {
                          e.stopPropagation();
                          toggleExpand(x.source_type);
                        }}
                      >
                        <span className={s.caret} aria-hidden>
                          {open ? "▾" : "▸"}
                        </span>
                        {x.label}
                      </button>
                    </td>
                    <td>
                      <span
                        className={x.status === "failing" ? s.bad : x.status === "ok" ? undefined : s.muted}
                        title={x.attention ?? undefined}
                      >
                        {STATUS_WORD[x.status]}
                      </span>
                    </td>
                    <td className={s.fills}>{x.fills}</td>
                    <td className={s.on} onClick={(e) => e.stopPropagation()}>
                      <button
                        type="button"
                        role="switch"
                        aria-checked={x.enabled}
                        aria-label={`${x.label} on`}
                        className={s.switch}
                        disabled={!rowByType.has(x.source_type) || update.isPending}
                        onClick={() => setEnabled(x, !x.enabled)}
                      />
                    </td>
                  </tr>
                  {open && (
                    <tr className={s.detailRow}>
                      <td colSpan={4} id={detailId}>
                        <SourceDetail
                          source={x}
                          row={rowByType.get(x.source_type)}
                          editing={editing === x.source_type}
                          onEdit={(on) => setEditing(on ? x.source_type : null)}
                        />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
            {visible.length === 0 && (
              <tr>
                <td colSpan={4} className={s.muted}>
                  No sources here.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <AiResearch entityType={tab === "all" ? null : tab} />
      <EnrichmentSettingsBlock />
    </div>
  );
}

function TabButton({
  id,
  label,
  count,
  tab,
  setTab,
}: {
  id: string;
  label: string;
  count: number;
  tab: string;
  setTab: (t: string) => void;
}) {
  return (
    <button type="button" role="tab" aria-selected={tab === id} onClick={() => setTab(id)}>
      {label} <span className={s.count}>{count}</span>
    </button>
  );
}

// (entity_type:field) pairs the AI research task can fill today.
const AI_SUPPORTED = new Set([
  "threat_actor:mitre_id",
  "threat_actor:country",
  "threat_actor:motivation",
  "threat_actor:description",
  "malware:malware_type",
  "malware:description",
  "product:vendor_id",
  "cve:cvss",
]);

const FIELD_LABEL: Record<string, string> = {
  mitre_id: "MITRE ID",
  malware_type: "malware type",
  vendor_id: "vendor",
  cvss: "CVSS score",
};

/** Fields no source filled, researched by the AI instead (10 entities a
 *  batch). Not a source, so it sits under the table rather than in it. The
 *  gap report only loads once the section is opened. */
function AiResearch({ entityType }: { entityType: string | null }) {
  const [open, setOpen] = useState(false);
  return (
    <details className={s.section} onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
      <summary>AI research for missing fields</summary>
      {open && <AiResearchList entityType={entityType} />}
    </details>
  );
}

function AiResearchList({ entityType }: { entityType: string | null }) {
  const gaps = useEnrichmentGaps();
  const enrichGap = useEnrichGap();
  const [busy, setBusy] = useState<string | null>(null);

  const buckets = (gaps.data?.buckets ?? []).filter(
    (b) => b.missing > 0 && (!entityType || b.entity_type === entityType),
  );

  const dispatch = async (entity_type: string, field: string) => {
    setBusy(`${entity_type}:${field}`);
    try {
      const r = await enrichGap.mutateAsync({ entity_type, field, limit: 10 });
      if (!r.supported) toast.error(r.message ?? "AI research isn't wired up for this field");
      else if (r.enqueued === 0) toast.message(r.message ?? "Nothing to research");
      else toast.success(`Researching ${r.batch_size} of ${num(r.total_missing)}; results fill in over about a minute`);
    } catch (e) {
      toast.error(`Research failed: ${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  };

  if (gaps.isLoading) return <p className={s.note}>Loading gaps…</p>;
  return (
    <div className={s.sectionBody}>
      <p className={s.note}>
        The AI looks up entities still missing a key field, 10 at a time. Use it for what no source
        covers.
      </p>
      {buckets.length === 0 && <p className={s.note}>Nothing missing here.</p>}
      {buckets.length > 0 && (
        <table className={s.mini}>
          <tbody>
            {buckets.map((b) => {
              const key = `${b.entity_type}:${b.field}`;
              return (
                <tr key={key}>
                  <td>
                    {getEntityLabel(b.entity_type)} with no {FIELD_LABEL[b.field] ?? b.field.replace(/_/g, " ")}
                  </td>
                  <td className={s.r}>{num(b.missing)}</td>
                  <td className={s.r}>
                    {AI_SUPPORTED.has(key) ? (
                      <button
                        type="button"
                        className={s.link}
                        disabled={busy === key}
                        onClick={() => dispatch(b.entity_type, b.field)}
                      >
                        {busy === key ? "Queuing…" : "Research 10"}
                      </button>
                    ) : (
                      <span className={s.muted}>manual</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

/** The enrichment + api_keys system settings. Collapsed, but opens itself
 *  when the Engine's settings search jumped here to flash one of them. */
function EnrichmentSettingsBlock() {
  const highlight = useContext(SettingsHighlightContext);
  const [open, setOpen] = useState(false);
  const shown = open || !!highlight;
  return (
    <details
      className={s.section}
      open={shown}
      onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}
    >
      <summary>Settings</summary>
      {shown && (
        <div className={s.sectionBody}>
          <SystemSettings filterGroups={["enrichment", "api_keys"]} />
        </div>
      )}
    </details>
  );
}
