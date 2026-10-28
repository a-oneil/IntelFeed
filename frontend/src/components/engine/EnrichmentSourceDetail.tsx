/**
 * The expanded row of the Enrichment console: Limits, Outputs and Jobs for one
 * source. Detail loads only for the open row.
 */
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { ScheduleEditor } from "@/components/JobSchedules";
import {
  useDeleteUserOverride,
  useEnrichmentSourceDetail,
  useQueueBackfill,
  useTestEnrichmentSource,
  useUpdateEnrichmentSource,
  useUpsertUserOverride,
  useUserEnrichmentOverrides,
  type EnrichmentConsoleSource,
  type EnrichmentLane,
  type EnrichmentSourceDetail,
} from "@/hooks/useEnrichment";
import { useJobSchedules, useResetJobSchedule, useUpdateJobSchedule } from "@/hooks/useJobSchedules";
import type { EnrichmentSource } from "@/api/types";
import { getEntityPluralLabel } from "@/utils/entityTheme";

import s from "./EnrichmentConsole.module.css";

const num = (n: number) => n.toLocaleString("en-US");

function period(sec: number): string {
  if (sec === 1) return "second";
  if (sec === 60) return "minute";
  if (sec === 3600) return "hour";
  if (sec === 86400) return "day";
  if (sec % 3600 === 0) return `${sec / 3600}h`;
  if (sec % 60 === 0) return `${sec / 60}m`;
  return `${sec}s`;
}

function rateText(r: EnrichmentSourceDetail["limits"]["rate"]): string {
  return `${num(r.requests_per_period)} per ${period(r.period_seconds)}`;
}

function keyText(key: string): string {
  if (key === "global") return "global key set";
  if (key === "none") return "no key";
  const m = /^user_overrides:(\d+)$/.exec(key);
  if (m) return `${m[1]} personal key${m[1] === "1" ? "" : "s"}`;
  return key;
}

const LANES: EnrichmentLane[] = ["manual", "new", "refresh", "backfill"];

function queueText(q: EnrichmentSourceDetail["queue"]): string {
  const parts = LANES.filter((l) => (q.by_lane[l] ?? 0) > 0).map((l) => `${num(q.by_lane[l] ?? 0)} ${l}`);
  if (q.retrying > 0) parts.push(`${num(q.retrying)} retrying`);
  if (q.waiting === 0 && parts.length === 0) return "empty";
  return `${num(q.waiting)} waiting${parts.length ? `: ${parts.join(", ")}` : ""}`;
}

function Sparkline({ points }: { points: number[] }) {
  const total = points.reduce((a, b) => a + b, 0);
  const max = Math.max(1, ...points);
  const step = points.length > 1 ? 84 / (points.length - 1) : 0;
  const coords = points.map((v, i) => `${(i * step).toFixed(1)},${(18 - (v / max) * 16).toFixed(1)}`).join(" ");
  return (
    <svg className={s.spark} viewBox="0 0 84 20" role="img" aria-label={`${num(total)} requests in the last 24 hours`}>
      <polyline fill="none" stroke="currentColor" strokeWidth="1.4" points={coords} />
    </svg>
  );
}

export function SourceDetail({
  source,
  row,
  editing,
  onEdit,
}: {
  source: EnrichmentConsoleSource;
  /** The source's settings row (id, rate config, key flags) — needed to edit. */
  row: EnrichmentSource | undefined;
  editing: boolean;
  onEdit: (on: boolean) => void;
}) {
  const { data: detail, isLoading, isError } = useEnrichmentSourceDetail(source.source_type);

  if (isLoading) return <p className={s.note}>Loading {source.label}…</p>;
  if (isError || !detail) return <p className={s.note}>Couldn't load detail for {source.label}.</p>;

  return (
    <div className={s.detail}>
      {source.attention && <p className={s.bad}>{source.attention}</p>}
      <div className={s.grid}>
        <LimitsPanel detail={detail} row={row} editing={editing} onEdit={onEdit} />
        <OutputsPanel source={source} detail={detail} />
        <JobsPanel detail={detail} />
      </div>
    </div>
  );
}

function LimitsPanel({
  detail,
  row,
  editing,
  onEdit,
}: {
  detail: EnrichmentSourceDetail;
  row: EnrichmentSource | undefined;
  editing: boolean;
  onEdit: (on: boolean) => void;
}) {
  const l = detail.limits;
  return (
    <section className={s.panel} aria-label="Limits">
      <h4>Limits</h4>
      <dl className={s.kv}>
        <dt>Rate</dt>
        <dd>
          {rateText(l.effective_rate)}
          {l.rate_note && <span className={s.muted}> ({l.rate_note}; {rateText(l.rate)} without)</span>}
          {l.ceiling_per_period != null && <span className={s.muted}> (max {num(l.ceiling_per_period)})</span>}
        </dd>
        <dt>Today</dt>
        <dd>
          {l.daily_budget != null ? `${num(l.used_today)} of ${num(l.daily_budget)}` : `${num(l.used_today)}, no daily cap`}
          {row?.shared_key_group && <span className={s.muted}> (all of the {row.shared_key_group} group)</span>}
          {l.backfill_share != null && ` · backfill may use ${Math.round(l.backfill_share * 100)}%`}
        </dd>
        {l.scope && (
          <>
            <dt>Scope</dt>
            <dd>{l.scope}</dd>
          </>
        )}
        {l.refresh_days != null && (
          <>
            <dt>Refresh</dt>
            <dd>every {l.refresh_days} days</dd>
          </>
        )}
        <dt>Key</dt>
        <dd>{keyText(l.key)}</dd>
        <dt>Runs on</dt>
        <dd>{l.triggers.length ? l.triggers.join(", ") : "nothing"}</dd>
        <dt>24h</dt>
        <dd>
          <Sparkline points={detail.trend_24h} />
        </dd>
        <dt>Queue</dt>
        <dd>
          {queueText(detail.queue)}
          {detail.queue.failed > 0 && <span className={s.bad}> · {num(detail.queue.failed)} failed</span>}
        </dd>
      </dl>
      {editing && row ? (
        <LimitsEditor row={row} detail={detail} onDone={() => onEdit(false)} />
      ) : (
        <button type="button" className={s.link} disabled={!row} onClick={() => onEdit(true)}>
          Edit limits
        </button>
      )}
    </section>
  );
}

function LimitsEditor({
  row,
  detail,
  onDone,
}: {
  row: EnrichmentSource;
  detail: EnrichmentSourceDetail;
  onDone: () => void;
}) {
  const qc = useQueryClient();
  const update = useUpdateEnrichmentSource();
  const test = useTestEnrichmentSource();
  const { data: overrides } = useUserEnrichmentOverrides();
  const upsertMine = useUpsertUserOverride();
  const deleteMine = useDeleteUserOverride();
  const mine = overrides?.find((o) => o.source_id === row.id);

  const l = detail.limits;
  // The stored rate, not the effective one: saving a keyed rate into the row
  // would stop the source switching back to its keyless rate without a key.
  const [rate, setRate] = useState(String(l.rate.requests_per_period));
  const [per, setPer] = useState(String(l.rate.period_seconds));
  const [cap, setCap] = useState(l.daily_budget != null ? String(l.daily_budget) : "");
  const [trigger, setTrigger] = useState(row.trigger_mode === "manual" ? "manual" : "auto");
  const [apiKey, setApiKey] = useState("");
  const [myKey, setMyKey] = useState("");
  const [tested, setTested] = useState<string | null>(null);

  const rateN = Number(rate);
  const perN = Number(per);
  const overCeiling = l.ceiling_per_period != null && rateN > l.ceiling_per_period;
  const valid = rateN > 0 && perN > 0 && !overCeiling && (cap === "" || Number(cap) >= 0);

  const rateChanged = rateN !== l.rate.requests_per_period || perN !== l.rate.period_seconds;

  const save = () => {
    const capN = cap.trim() === "" ? 0 : Number(cap);
    update.mutate(
      {
        sourceId: row.id,
        ...(rateChanged
          ? { rate_limit_config: { ...row.rate_limit_config, requests_per_period: rateN, period_seconds: perN } }
          : {}),
        ...(capN > 0 ? { daily_budget: capN } : { clear_daily_budget: true }),
        trigger_mode: trigger,
        ...(apiKey ? { api_key: apiKey } : {}),
      },
      {
        onSuccess: () => {
          qc.invalidateQueries({ queryKey: ["enrichment-console"] });
          onDone();
        },
        onError: (e) => toast.error(`Couldn't save: ${(e as Error).message}`),
      },
    );
  };

  const runTest = async () => {
    try {
      const r = await test.mutateAsync(row.id);
      setTested(r.health_status);
    } catch {
      setTested("error");
    }
  };

  return (
    <div className={s.editor}>
      <label>
        Requests
        <input type="number" min={1} max={l.ceiling_per_period ?? undefined} value={rate} onChange={(e) => setRate(e.target.value)} />
      </label>
      <label>
        Per (seconds)
        <input type="number" min={1} value={per} onChange={(e) => setPer(e.target.value)} />
      </label>
      {overCeiling && <p className={s.bad}>The source allows at most {num(l.ceiling_per_period ?? 0)} per period.</p>}
      <label>
        Daily cap
        <input type="number" min={0} placeholder="none" value={cap} onChange={(e) => setCap(e.target.value)} />
      </label>
      <label>
        Runs
        <select value={trigger} onChange={(e) => setTrigger(e.target.value)}>
          <option value="auto">automatically</option>
          <option value="manual">only when asked</option>
        </select>
      </label>
      {(row.requires_api_key || row.has_api_key) && (
        <label>
          Global key
          <input
            type="password"
            autoComplete="off"
            placeholder={row.has_api_key ? "set; type to replace" : "paste API key"}
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
          />
        </label>
      )}
      {row.shared_key_group && <p className={s.note}>Shares its key with the {row.shared_key_group} group.</p>}
      <div className={s.editActions}>
        <button type="button" className={s.btn} disabled={!valid || update.isPending} onClick={save}>
          {update.isPending ? "Saving…" : "Save"}
        </button>
        <button type="button" className={s.link} onClick={onDone}>
          Cancel
        </button>
        <button type="button" className={s.link} disabled={test.isPending} onClick={runTest}>
          {test.isPending ? "Testing…" : "Test connection"}
        </button>
        {tested && <span className={tested === "healthy" ? s.muted : s.bad}>{tested}</span>}
      </div>
      {row.requires_api_key && (
        <div className={s.mine}>
          <label>
            My key
            <input
              type="password"
              autoComplete="off"
              placeholder={mine?.has_api_key ? "your key is set" : "uses the global key"}
              value={myKey}
              onChange={(e) => setMyKey(e.target.value)}
            />
          </label>
          <div className={s.editActions}>
            <button
              type="button"
              className={s.link}
              disabled={!myKey || upsertMine.isPending}
              onClick={() => upsertMine.mutate({ sourceId: row.id, api_key: myKey }, { onSuccess: () => setMyKey("") })}
            >
              Save my key
            </button>
            {mine?.has_api_key && (
              <button
                type="button"
                className={s.link}
                disabled={deleteMine.isPending}
                onClick={() => deleteMine.mutate(row.id)}
              >
                Remove my key
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function OutputsPanel({ source, detail }: { source: EnrichmentConsoleSource; detail: EnrichmentSourceDetail }) {
  const backfill = useQueueBackfill();
  const gap = detail.gap;

  const runBackfill = () => {
    if (!gap) return;
    backfill.mutate(
      { sourceType: source.source_type, entityType: gap.entity_type, limit: gap.in_scope },
      {
        onSuccess: (r) => toast.success(`Queued ${num(r.queued)} backfill lookups for ${source.label}`),
        onError: (e) => toast.error(`Backfill failed: ${(e as Error).message}`),
      },
    );
  };

  return (
    <section className={s.panel} aria-label="Outputs">
      <h4>Outputs</h4>
      {detail.outputs.length === 0 ? (
        <p className={s.note}>Writes nothing directly.</p>
      ) : (
        <table className={s.mini}>
          <thead>
            <tr>
              <th>Field</th>
              <th>Writes to</th>
              <th className={s.r}>Filled</th>
            </tr>
          </thead>
          <tbody>
            {detail.outputs.map((o) => (
              <tr key={`${o.field}-${o.target}`}>
                <td>{o.field}</td>
                <td>
                  {o.target}
                  {o.rank != null && ` (rank ${o.rank})`}
                </td>
                <td className={s.r}>
                  {o.kind === "relationship"
                    ? `${num(o.linked ?? 0)} linked · ${num(o.held ?? 0)} held`
                    : o.filled_pct != null
                      ? `${Math.round(o.filled_pct)}%`
                      : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {gap && (
        <>
          <p className={s.note}>
            {num(gap.missing)} {getEntityPluralLabel(gap.entity_type)} have no {gap.field.replace(/_/g, " ")}.{" "}
            {num(gap.in_scope)} are in scope.
          </p>
          {gap.in_scope > 0 && (
            <button type="button" className={s.link} disabled={backfill.isPending || !source.enabled} onClick={runBackfill}>
              Backfill {num(gap.in_scope)}
              {gap.eta_days != null && ` (about ${gap.eta_days} days at the cap)`}
            </button>
          )}
        </>
      )}
    </section>
  );
}

function JobsPanel({ detail }: { detail: EnrichmentSourceDetail }) {
  const [editing, setEditing] = useState(false);
  const failing = detail.jobs.filter((j) => j.last_status === "error" && j.last_error);
  return (
    <section className={s.panel} aria-label="Jobs">
      <h4>Jobs</h4>
      {detail.jobs.length === 0 ? (
        <p className={s.note}>No scheduled jobs.</p>
      ) : (
        <table className={s.mini}>
          <thead>
            <tr>
              <th>Job</th>
              <th>Schedule</th>
              <th className={s.r}>Last 30 days</th>
            </tr>
          </thead>
          <tbody>
            {detail.jobs.map((j) => (
              <tr key={j.key}>
                <td>{j.key}</td>
                <td>{j.schedule}</td>
                <td className={s.r}>
                  <span className={j.last_status === "error" ? s.bad : undefined}>
                    {j.runs_30d === 0 ? "no runs" : `${j.ok_30d} of ${j.runs_30d} ok`}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {failing.map((j) => (
        <p key={j.key} className={s.bad}>
          {j.key}: {j.last_error}
        </p>
      ))}
      {detail.jobs.length > 0 &&
        (editing ? (
          <ScheduleEditors keys={detail.jobs.map((j) => j.key)} onDone={() => setEditing(false)} />
        ) : (
          <button type="button" className={s.link} onClick={() => setEditing(true)}>
            Edit schedules
          </button>
        ))}
    </section>
  );
}

/** Schedule editing for this source's jobs, in place. Engine → Jobs lists them
 *  read-only and links back here, so the source owns its jobs. */
function ScheduleEditors({ keys, onDone }: { keys: string[]; onDone: () => void }) {
  const { data } = useJobSchedules();
  const update = useUpdateJobSchedule();
  const reset = useResetJobSchedule();
  const [open, setOpen] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  if (!data) return <p className={s.note}>Loading schedules…</p>;
  const jobs = keys.map((k) => data.jobs.find((j) => j.name === k)).filter((j) => j != null);

  return (
    <div className={s.schedules}>
      {jobs.map((job) => (
        <div key={job.name}>
          <button
            type="button"
            className={s.link}
            aria-expanded={open === job.name}
            onClick={() => setOpen(open === job.name ? null : job.name)}
          >
            {job.name}: {job.human_schedule}
          </button>
          {open === job.name && (
            <ScheduleEditor
              job={job}
              saving={update.isPending}
              onCancel={() => setOpen(null)}
              onSave={(schedule) =>
                update.mutate(
                  { name: job.name, schedule },
                  {
                    onSuccess: () => {
                      setOpen(null);
                      setSaved(true);
                    },
                  },
                )
              }
              onReset={
                job.is_customized
                  ? () =>
                      reset.mutate(job.name, {
                        onSuccess: () => {
                          setOpen(null);
                          setSaved(true);
                        },
                      })
                  : undefined
              }
            />
          )}
        </div>
      ))}
      {saved && (
        <p className={s.note}>
          Takes effect after <code>docker compose restart celery-beat</code>.
        </p>
      )}
      <button type="button" className={s.link} onClick={onDone}>
        Done
      </button>
    </div>
  );
}
