/**
 * Activity: the queue by lane, the lookups that gave up (with retry), and
 * requests by source over the last 24 hours.
 */
import { toast } from "sonner";

import { useEnrichmentActivity, useRetryFailedLookups, type EnrichmentLane } from "@/hooks/useEnrichment";

import { num } from "./format";
import s from "../EnrichmentConsole.module.css";

const LANE: Record<EnrichmentLane, [string, string]> = {
  manual: ["Asked by a person", "first"],
  new: ["New entities", "next"],
  refresh: ["Refresh", "then"],
  backfill: ["Backfill", "last"],
};

export function ActivityView() {
  const actQ = useEnrichmentActivity();
  const retry = useRetryFailedLookups();
  const a = actQ.data;
  if (!a) return <p className={s.note}>{actQ.isError ? "Couldn't load activity." : "Loading activity…"}</p>;

  const doRetry = (source?: string) =>
    retry.mutate(source, {
      onSuccess: (r) => toast.success(`Queued ${num(r.queued)} lookups again`),
      onError: (e) => toast.error(`Couldn't retry: ${(e as Error).message}`),
    });
  const max = Math.max(1, ...(a.requests ?? []).map((r) => r.requests));
  const gaveUp = a.failed.reduce((n, f) => n + f.count, 0);

  return (
    <div className={s.act}>
      <div className={s.stack}>
        <h4 className={s.h4}>Queue</h4>
        <table className={s.mini}>
          <thead>
            <tr>
              <th>Lane</th>
              <th className={s.r}>Waiting</th>
              <th className={s.r}>Put off</th>
              <th>Runs</th>
            </tr>
          </thead>
          <tbody>
            {a.lanes.map((l) => (
              <tr key={l.lane}>
                <td>{LANE[l.lane]?.[0] ?? l.lane}</td>
                <td className={s.r}>{num(l.waiting)}</td>
                <td className={s.r}>{num(l.deferred)}</td>
                <td className={s.muted}>
                  {LANE[l.lane]?.[1]}
                  {l.lane === "backfill" && `, up to ${Math.round(a.backfill_share * 100)}% of each daily cap`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <h4 className={s.h4}>Gave up · {num(gaveUp)}</h4>
        {a.failed.length === 0 ? (
          <p className={s.note}>No lookup has given up.</p>
        ) : (
          <>
            {a.failed.map((f) => (
              <div key={f.source_type} className={s.gaveUp}>
                <span className={`${s.dot} ${s.dotWarn}`} aria-hidden />
                <span>
                  <b>{num(f.count)}</b> at {f.label}
                  {f.last_error && <small title={f.last_error}>{f.last_error}</small>}
                </span>
                <button type="button" className={s.link} disabled={retry.isPending} onClick={() => doRetry(f.source_type)}>
                  Retry
                </button>
              </div>
            ))}
            {a.failed.length > 1 && (
              <button type="button" className={s.btn} disabled={retry.isPending} onClick={() => doRetry()}>
                Retry all {num(gaveUp)}
              </button>
            )}
          </>
        )}
      </div>
      <div className={s.stack}>
        <h4 className={s.h4}>Requests by source · 24h</h4>
        {a.requests == null ? (
          <p className={s.note}>Redis is unreachable, so request counts aren't available.</p>
        ) : a.requests.length === 0 ? (
          <p className={s.note}>No requests in the last 24 hours.</p>
        ) : (
          <div className={s.req}>
            {a.requests.map((r) => (
              <div key={r.source_type}>
                <span>{r.label}</span>
                <i style={{ width: `${(r.requests / max) * 100}%` }} />
                <em>{num(r.requests)}</em>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
