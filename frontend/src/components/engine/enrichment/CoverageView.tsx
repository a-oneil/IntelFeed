/**
 * Coverage: how full each field the sources fill is, who fills it, and the
 * one thing to do about the rest. "Ask the AI" appears only where no lookup
 * source can fill the gap.
 */
import { useState } from "react";
import { toast } from "sonner";

import { useEnrichmentCoverage, useQueueBackfill, type EnrichmentCoverageField } from "@/hooks/useEnrichment";
import { useEnrichGap } from "@/hooks/useHygiene";

import { Bar } from "./SourcePanel";
import { num } from "./format";
import s from "../EnrichmentConsole.module.css";

export function CoverageView({ openSource }: { openSource: (source: string) => void }) {
  const covQ = useEnrichmentCoverage();
  const [type, setType] = useState("all");
  if (!covQ.data) {
    return <p className={s.note}>{covQ.isError ? "Couldn't load coverage." : "Counting fields…"}</p>;
  }
  const types = [...new Map(covQ.data.map((f) => [f.entity_type, f.entity_label])).entries()];
  const shown = covQ.data.filter((f) => type === "all" || f.entity_type === type);

  return (
    <div className={s.stack}>
      <p className={s.note}>How full each field is across every entity of its type, and who fills it.</p>
      <div className={s.filters} role="group" aria-label="Filter by entity type">
        {[["all", "All"] as const, ...types].map(([id, label]) => (
          <button key={id} type="button" className={s.chip} aria-pressed={type === id} onClick={() => setType(id)}>
            {label}
          </button>
        ))}
      </div>
      <div className={s.scroll}>
        <table className={s.cov}>
          <thead>
            <tr>
              <th>Field</th>
              <th>Filled</th>
              <th>Filled by</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {shown.map((f) => (
              <tr key={`${f.entity_type}.${f.field}`}>
                <td>
                  <b>{f.entity_label}</b> · {f.label}
                </td>
                <td title={`${num(f.filled)} of ${num(f.total)}`}>
                  {f.filled_pct == null ? <span className={s.muted}>none yet</span> : <Bar pct={f.filled_pct} />}
                </td>
                <td className={s.muted}>
                  {f.sources.map((x, i) => (
                    <span key={x.source_type}>
                      {i > 0 && ", "}
                      <button type="button" className={x.enabled ? s.link : `${s.link} ${s.muted}`} onClick={() => openSource(x.source_type)}>
                        {x.label}
                      </button>
                      {!x.enabled && " (off)"}
                    </span>
                  ))}
                </td>
                <td className={s.r}>
                  <FieldAction f={f} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className={s.note}>"Ask the AI" researches 10 entities at a time, for fields no lookup source can fill.</p>
    </div>
  );
}

function FieldAction({ f }: { f: EnrichmentCoverageField }) {
  const backfill = useQueueBackfill();
  const ai = useEnrichGap();
  const a = f.action;
  if (!a) return <span className={s.muted}>{f.total > f.filled && f.cadence ? f.cadence.toLowerCase() : ""}</span>;

  if (a.kind === "backfill") {
    return (
      <button
        type="button"
        className={s.link}
        disabled={backfill.isPending}
        onClick={() =>
          backfill.mutate(
            { sourceType: a.source, entityType: f.entity_type, limit: a.count },
            {
              onSuccess: (r) =>
                r.queued
                  ? toast.success(`Queued ${num(r.queued)} lookups`)
                  : toast.message("Nothing to queue: the rest are waiting already or outside the source's reach"),
              onError: (e) => toast.error(`Backfill failed: ${(e as Error).message}`),
            },
          )
        }
      >
        Backfill
      </button>
    );
  }
  return (
    <button
      type="button"
      className={s.link}
      disabled={ai.isPending}
      onClick={() =>
        ai.mutate(
          { entity_type: f.entity_type, field: a.field, limit: 10 },
          {
            onSuccess: (r) => {
              if (!r.supported) toast.error(r.message ?? "AI research can't fill this field");
              else if (r.enqueued === 0) toast.message(r.message ?? "Nothing to research");
              else toast.success(`Researching ${r.batch_size} of ${num(r.total_missing)}; results fill in over about a minute`);
            },
            onError: (e) => toast.error(`Research failed: ${(e as Error).message}`),
          },
        )
      }
    >
      Ask the AI for 10
    </button>
  );
}
