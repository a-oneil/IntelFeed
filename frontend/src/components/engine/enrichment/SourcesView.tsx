/**
 * Sources: the list answers three things per source (is it on, does it work,
 * what does it fill); the side panel holds the rest. Sources that are on come
 * first, problems at the top; the rest sit under "Available".
 */
import { useState } from "react";
import { toast } from "sonner";

import {
  useUpdateEnrichmentSource,
  type EnrichmentConsole,
  type EnrichmentConsoleSource,
} from "@/hooks/useEnrichment";

import { SourcePanel } from "./SourcePanel";
import { num, statusOf, type Tone } from "./format";
import s from "../EnrichmentConsole.module.css";

export type PanelTab = "overview" | "limits" | "fields" | "jobs";

/** Which source the side panel shows, and on which tab. */
export interface Selection {
  source: string | null;
  tab: PanelTab;
}

export const TONE_DOT: Record<Tone, string> = { ok: s.dotOk, bad: s.dotBad, warn: s.dotWarn, off: s.dotOff };

export function SourcesView({
  data,
  sel,
  setSel,
  openKey,
}: {
  data: EnrichmentConsole;
  sel: Selection;
  setSel: (sel: Selection) => void;
  openKey: (key: string) => void;
}) {
  const [filter, setFilter] = useState<string>("all");
  const shown = data.sources.filter((x) => filter === "all" || x.applies_to.includes(filter));
  // Problems first, then by name; the server already sorts this way.
  const on = shown.filter((x) => x.enabled);
  const off = shown.filter((x) => !x.enabled);
  const selected = data.sources.find((x) => x.source_type === sel.source) ?? on[0] ?? data.sources[0];

  return (
    <div className={s.split}>
      <div className={s.list}>
        <div className={s.filters} role="group" aria-label="Filter by entity type">
          {[{ entity_type: "all", label: "All", source_count: data.sources.length }, ...data.entity_types].map((t) => (
            <button
              key={t.entity_type}
              type="button"
              className={s.chip}
              aria-pressed={filter === t.entity_type}
              onClick={() => setFilter(t.entity_type)}
            >
              {t.label}
              <span>{t.source_count}</span>
            </button>
          ))}
        </div>
        <div className={s.group}>On · {on.length}</div>
        {on.map((x) => (
          <Row key={x.source_type} x={x} current={x === selected} onPick={() => setSel({ source: x.source_type, tab: "overview" })} />
        ))}
        {off.length > 0 && <div className={s.group}>Available · {off.length}</div>}
        {off.map((x) => (
          <Row key={x.source_type} x={x} current={x === selected} onPick={() => setSel({ source: x.source_type, tab: "overview" })} />
        ))}
        {shown.length === 0 && <p className={s.note}>No sources fill this type.</p>}
      </div>
      {selected && (
        <SourcePanel
          key={selected.source_type}
          x={selected}
          tab={sel.source === selected.source_type ? sel.tab : "overview"}
          setTab={(tab) => setSel({ source: selected.source_type, tab })}
          openKey={openKey}
        />
      )}
    </div>
  );
}

function Row({ x, current, onPick }: { x: EnrichmentConsoleSource; current: boolean; onPick: () => void }) {
  const { word, tone } = statusOf(x);
  const pct = x.daily_budget ? Math.min(100, Math.round((x.used_today / x.daily_budget) * 100)) : null;
  return (
    <button type="button" className={s.row} aria-current={current} onClick={onPick}>
      <span className={`${s.dot} ${TONE_DOT[tone]}`} aria-hidden />
      <span className={s.rowName}>
        {x.label}
        {x.new && <small title="Added in the last two weeks">new</small>}
      </span>
      <span className={`${s.rowStatus} ${s[`tone_${tone}`]}`}>{word}</span>
      <span className={s.rowUse} title={pct == null ? "No daily cap" : `${num(x.used_today)} of ${num(x.daily_budget!)} requests today`}>
        {x.enabled && pct != null && (
          <>
            <i>
              <b className={pct >= 90 ? s.barWarn : undefined} style={{ width: `${pct}%` }} />
            </i>
            <em>{pct}%</em>
          </>
        )}
      </span>
      <span className={s.rowFills}>{x.fills}</span>
      {x.trigger_mode && (
        <span
          className={x.trigger_mode === "auto" ? `${s.mode} ${s.modeAuto}` : s.mode}
          title={x.trigger_mode === "auto" ? "Looks up new entities on its own" : "Runs when someone asks, and in its jobs"}
        >
          {x.trigger_mode === "auto" ? "Auto" : "Manual"}
        </span>
      )}
    </button>
  );
}

/** The on/off switch, shared by the panel header. */
export function SourceSwitch({ x }: { x: EnrichmentConsoleSource }) {
  const update = useUpdateEnrichmentSource();
  return (
    <button
      type="button"
      role="switch"
      aria-checked={x.enabled}
      aria-label={`${x.label} on`}
      className={s.switch}
      disabled={update.isPending}
      onClick={() =>
        update.mutate(
          { sourceId: x.id, is_enabled: !x.enabled },
          {
            onError: (e) => toast.error(`Couldn't turn ${x.label} ${x.enabled ? "off" : "on"}: ${(e as Error).message}`),
          },
        )
      }
    />
  );
}
