/**
 * One source, in the side panel: what it is and what it sends out, then
 * Overview (today against the cap, what's waiting), Limits, Fields (fill rates
 * and backfill) and Jobs (schedule and settings beside each job). Keys are
 * set in Keys; the panel only says which key it uses and links there.
 */
import { useState } from "react";
import { toast } from "sonner";

import { ScheduleEditor } from "@/components/JobSchedules";
import { Segmented } from "@/components/primitives";
import SystemSettings from "@/components/SystemSettings";
import {
  useEnrichmentSourceDetail,
  useQueueBackfill,
  useUpdateEnrichmentSource,
  type EnrichmentConsoleSource,
  type EnrichmentLane,
  type EnrichmentQueueReason,
  type EnrichmentSourceDetail,
} from "@/hooks/useEnrichment";
import { useJobSchedules, useResetJobSchedule, useRunJobNow, useUpdateJobSchedule } from "@/hooks/useJobSchedules";
import { getEntityPluralLabel } from "@/utils/entityTheme";

import { Sparkline } from "./Sparkline";
import { SourceSwitch, TONE_DOT, type PanelTab } from "./SourcesView";
import { KEY_STATUS, SENDS, aboutDays, num, period, refreshText, statusOf } from "./format";
import s from "../EnrichmentConsole.module.css";

const LANE_LABEL: Record<EnrichmentLane, string> = {
  manual: "Asked by a person",
  new: "New entities",
  refresh: "Refresh",
  backfill: "Backfill",
};

/** Why queued lookups wait again, in the console's words. */
const REASON_TEXT: Record<EnrichmentQueueReason, string> = {
  rate_limited: "retrying after the source said \"too many requests\"",
  breaker_open: "waiting out a back-off",
  budget_exhausted: "waiting for tomorrow's cap",
  backfill_share: "waiting for backfill room",
  paused: "held by the pause",
  auth_failed: "held after a rejected key",
  source_disabled: "waiting for the source to be on",
};

export function SourcePanel({
  x,
  tab,
  setTab,
  openKey,
}: {
  x: EnrichmentConsoleSource;
  tab: PanelTab;
  setTab: (t: PanelTab) => void;
  openKey: (key: string) => void;
}) {
  const { word, tone } = statusOf(x);
  const detailQ = useEnrichmentSourceDetail(x.source_type);
  const detail = detailQ.data;
  const tabs: Array<[PanelTab, string]> = [
    ["overview", "Overview"],
    ["limits", "Limits"],
    ["fields", "Fields"],
    ["jobs", x.jobs ? `Jobs · ${x.jobs}` : "Jobs"],
  ];
  const tabId = (t: PanelTab) => `enrichment-${x.source_type}-tab-${t}`;
  const panelId = `enrichment-${x.source_type}-section`;
  const needsKey = x.status === "needs_key" && x.needs === "key" && x.key;

  return (
    <aside className={s.panel} aria-label={x.label}>
      <div className={s.panelHead}>
        <div className={s.panelTop}>
          <h3>{x.label}</h3>
          <span className={`${s.rowStatus} ${s[`tone_${tone}`]}`}>
            <span className={`${s.dot} ${TONE_DOT[tone]}`} aria-hidden />
            {word}
          </span>
          <span className={s.spacer} />
          <SourceSwitch x={x} />
        </div>
        {x.about && <p className={s.about}>{x.about}</p>}
        <div className={s.facts}>
          <span className={x.egress === "shares_ioc" ? `${s.fact} ${s.factShare}` : s.fact}>
            <span>Sends out</span>
            {SENDS[x.egress]}
          </span>
          <span className={s.fact}>
            <span>License</span>
            {x.license}
            {!x.commercial_ok && " · hidden from public visitors"}
          </span>
          <span className={s.fact}>
            <span>Key</span>
            {x.key && x.key_status ? (
              <button type="button" className={s.link} onClick={() => openKey(x.key!)}>
                {KEY_STATUS[x.key_status]}
              </button>
            ) : (
              "none needed"
            )}
          </span>
        </div>
      </div>

      <Segmented<PanelTab>
        role="tablist"
        size="sm"
        label={`${x.label} sections`}
        className={s.panelTabs}
        value={tab}
        onChange={setTab}
        options={tabs.map(([id, label]) => ({ value: id, label, id: tabId(id), controls: panelId }))}
      />

      <div className={s.panelBody} role="tabpanel" id={panelId} aria-labelledby={tabId(tab)}>
        {needsKey ? (
          <div className={s.ghost}>
            <span>{x.label} needs an API key before it can run.</span>
            <button type="button" className={s.btn} onClick={() => openKey(x.key!)}>
              Add key
            </button>
          </div>
        ) : !detail ? (
          <p className={s.note}>{detailQ.isError ? `Couldn't load ${x.label}.` : "Loading…"}</p>
        ) : (
          <>
            {tab === "overview" && <Overview x={x} d={detail} setTab={setTab} openKey={openKey} />}
            {tab === "limits" && <Limits x={x} d={detail} />}
            {tab === "fields" && <Fields x={x} d={detail} />}
            {tab === "jobs" && <Jobs x={x} d={detail} />}
          </>
        )}
      </div>
    </aside>
  );
}

function Overview({
  x,
  d,
  setTab,
  openKey,
}: {
  x: EnrichmentConsoleSource;
  d: EnrichmentSourceDetail;
  setTab: (t: PanelTab) => void;
  openKey: (key: string) => void;
}) {
  const l = d.limits;
  const pct = l.daily_budget ? Math.min(100, Math.round((l.used_today / l.daily_budget) * 100)) : null;
  const lanes = (["manual", "new", "refresh", "backfill"] as const).map((lane) => [lane, d.queue.by_lane[lane] ?? 0] as const);
  const max = Math.max(1, ...lanes.map(([, n]) => n));
  const reasons = Object.entries(d.queue.by_reason ?? {}).filter(([, n]) => n) as Array<[EnrichmentQueueReason, number]>;
  const failing = d.jobs.find((j) => j.last_status === "error" && j.last_error);

  return (
    <div className={s.stack}>
      {x.status === "key_rejected" && (
        <p className={s.err}>
          {x.attention}{" "}
          {x.key && (
            <button type="button" className={s.link} onClick={() => openKey(x.key!)}>
              Replace key
            </button>
          )}
        </p>
      )}
      {failing && (
        <p className={s.err}>
          {failing.key}: {failing.last_error}{" "}
          <button type="button" className={s.link} onClick={() => setTab("jobs")}>
            See jobs
          </button>
        </p>
      )}
      <div>
        <h4 className={s.h4}>Today</h4>
        {pct != null ? (
          <div className={s.meter}>
            <div className={s.meterBar}>
              <i className={pct >= 90 ? s.barWarn : undefined} style={{ width: `${pct}%` }} />
              {l.backfill_share != null && <u style={{ left: `${l.backfill_share * 100}%` }} title="Backfill stops here" />}
            </div>
            <div className={s.meterLabel}>
              <span>
                <b>{num(l.used_today)}</b> of {num(l.daily_budget!)} requests
              </span>
              {l.backfill_share != null && <span>backfill stops at {Math.round(l.backfill_share * 100)}%</span>}
              <span>resets 00:00 UTC</span>
            </div>
          </div>
        ) : (
          <p className={s.note}>{num(l.used_today)} requests today; no daily cap.</p>
        )}
      </div>
      <div>
        <h4 className={s.h4}>Requests · 24h</h4>
        <Sparkline points={d.trend_24h} label={`${num(d.trend_24h.reduce((a, b) => a + b, 0))} requests in the last 24 hours`} />
      </div>
      {x.kind === "lookup" && (
        <div>
          <h4 className={s.h4}>Waiting · {num(d.queue.waiting)}</h4>
          <div className={s.lanes}>
            {lanes.map(([lane, n]) => (
              <div key={lane} className={s.lane}>
                <span>{LANE_LABEL[lane]}</span>
                <i style={{ width: `${Math.max(2, (n / max) * 100)}%` }} />
                <em>{num(n)}</em>
              </div>
            ))}
          </div>
          {reasons.map(([r, n]) => (
            <p key={r} className={s.note}>
              {num(n)} {REASON_TEXT[r]}.
            </p>
          ))}
          {d.queue.failed > 0 && (
            <p className={s.note}>{num(d.queue.failed)} gave up after repeated errors; retry them from Activity.</p>
          )}
        </div>
      )}
    </div>
  );
}

function Limits({ x, d }: { x: EnrichmentConsoleSource; d: EnrichmentSourceDetail }) {
  const update = useUpdateEnrichmentSource();
  const l = d.limits;
  // The stored rate, not the effective one: saving a keyed rate into the row
  // would stop the source switching back to its keyless rate without a key.
  const [rate, setRate] = useState(String(l.rate.requests_per_period));
  const [per, setPer] = useState(String(l.rate.period_seconds));
  const [cap, setCap] = useState(l.daily_budget != null ? String(l.daily_budget) : "");
  const [mode, setMode] = useState(x.trigger_mode ?? "manual");

  const rateN = Number(rate);
  const perN = Number(per);
  const overCeiling = l.ceiling_per_period != null && rateN > l.ceiling_per_period;
  const valid = rateN > 0 && perN > 0 && !overCeiling && (cap === "" || Number(cap) >= 0);
  const rateChanged = rateN !== l.rate.requests_per_period || perN !== l.rate.period_seconds;

  const save = () => {
    const capN = cap.trim() === "" ? 0 : Number(cap);
    update.mutate(
      {
        sourceId: x.id,
        ...(rateChanged
          ? { rate_limit_config: { ...(d.settings?.rate_limit_config ?? {}), requests_per_period: rateN, period_seconds: perN } }
          : {}),
        ...(capN > 0 ? { daily_budget: capN } : { clear_daily_budget: true }),
        ...(x.trigger_mode ? { trigger_mode: mode } : {}),
      },
      {
        onSuccess: () => toast.success(`Saved ${x.label}'s limits`),
        onError: (e) => toast.error(`Couldn't save: ${(e as Error).message}`),
      },
    );
  };

  return (
    <div className={s.stack}>
      <div className={s.form}>
        <label htmlFor="enr-rate">Rate</label>
        <span className={s.in}>
          <input id="enr-rate" type="number" min={1} value={rate} onChange={(e) => setRate(e.target.value)} />
          requests per
          <input id="enr-per" aria-label="Seconds" type="number" min={1} value={per} onChange={(e) => setPer(e.target.value)} />
          seconds
        </span>
        {(l.rate_note || l.ceiling_per_period != null) && (
          <span className={overCeiling ? `${s.hint} ${s.badWord}` : s.hint}>
            {l.rate_note && `Enforced now: ${num(l.effective_rate.requests_per_period)} per ${period(l.effective_rate.period_seconds)} (${l.rate_note}). `}
            {l.ceiling_per_period != null && `${x.label} allows at most ${num(l.ceiling_per_period)} per period.`}
          </span>
        )}
        <label htmlFor="enr-cap">Daily cap</label>
        <span className={s.in}>
          <input id="enr-cap" type="number" min={0} placeholder="none" value={cap} onChange={(e) => setCap(e.target.value)} />
          requests{l.backfill_share != null && `; backfill may use ${Math.round(l.backfill_share * 100)}%`}
        </span>
        {x.trigger_mode && (
          <>
            <label htmlFor="enr-mode">Runs</label>
            <span className={s.in}>
              <select id="enr-mode" value={mode} onChange={(e) => setMode(e.target.value as "auto" | "manual")}>
                <option value="auto">On its own and when asked</option>
                <option value="manual">Only when someone asks</option>
              </select>
            </span>
            {x.egress === "shares_ioc" && (
              <span className={s.hint}>Sends your indicators to {x.label}. "On its own" sends every new one in scope.</span>
            )}
          </>
        )}
        {l.scope && (
          <>
            <span className={s.formLabel}>Looks up</span>
            <span className={s.in}>{l.scope}</span>
          </>
        )}
        {l.refresh_days != null && (
          <>
            <span className={s.formLabel}>Asks again</span>
            <span className={s.in}>{refreshText(l.refresh_days)}</span>
          </>
        )}
        {l.concurrency != null && (
          <>
            <span className={s.formLabel}>At a time</span>
            <span className={s.in}>{num(l.concurrency)} requests</span>
          </>
        )}
      </div>
      <div className={s.actions}>
        <button type="button" className={`${s.btn} ${s.primary}`} disabled={!valid || update.isPending} onClick={save}>
          {update.isPending ? "Saving…" : "Save"}
        </button>
        <span className={s.muted}>Changes apply to the next request.</span>
      </div>
      {x.source_settings.length > 0 && <SystemSettings filterKeys={x.source_settings} flat />}
    </div>
  );
}

function Fields({ x, d }: { x: EnrichmentConsoleSource; d: EnrichmentSourceDetail }) {
  const backfill = useQueueBackfill();
  const gap = d.gap;
  const run = () => {
    if (!gap) return;
    backfill.mutate(
      { sourceType: x.source_type, entityType: gap.entity_type, limit: gap.in_scope },
      {
        onSuccess: (r) => toast.success(`Queued ${num(r.queued)} backfill lookups for ${x.label}`),
        onError: (e) => toast.error(`Backfill failed: ${(e as Error).message}`),
      },
    );
  };

  return (
    <div className={s.stack}>
      {d.outputs.length === 0 ? (
        <p className={s.note}>Writes nothing onto entities directly.</p>
      ) : (
        <div className={s.fields}>
          {d.outputs.map((o) => (
            <div key={`${o.field}-${o.target}`} className={s.field}>
              <span>{o.field.replace(/_/g, " ")}</span>
              <span className={s.to}>
                → <b>{o.target}</b>
                {o.rank != null && ` · rank ${o.rank}`}
              </span>
              {o.kind === "relationship" ? (
                <span className={s.muted}>
                  {num(o.linked ?? 0)} linked · {num(o.held ?? 0)} held for review
                </span>
              ) : o.filled_pct == null ? (
                <span className={s.muted}>shown on profiles</span>
              ) : (
                <Bar pct={o.filled_pct} />
              )}
            </div>
          ))}
        </div>
      )}
      {gap && gap.missing > 0 && (
        <>
          <p className={s.note}>
            {num(gap.missing)} {getEntityPluralLabel(gap.entity_type)} have no {gap.field.replace(/_/g, " ")}.{" "}
            {gap.in_scope > 0
              ? `${num(gap.in_scope)} can be looked up now; the rest are already queued or outside what ${x.label} covers.`
              : `None can be looked up now: they're already queued or outside what ${x.label} covers.`}
          </p>
          {gap.in_scope > 0 && (
            <div className={s.actions}>
              <button type="button" className={s.btn} disabled={backfill.isPending || !x.enabled} onClick={run}>
                Backfill {num(gap.in_scope)}
              </button>
              {gap.eta_days != null && <span className={s.muted}>{aboutDays(gap.eta_days)} at the daily cap</span>}
            </div>
          )}
        </>
      )}
      <p className={s.note}>Each value is saved with its source, so profiles can show who said what.</p>
    </div>
  );
}

/** A fill rate. Neutral: some fields are sparse by nature (a KEV date). */
export function Bar({ pct }: { pct: number }) {
  return (
    <span className={s.bar}>
      <i style={{ width: `${pct}%` }} />
      <em>{Math.round(pct)}%</em>
    </span>
  );
}

function Jobs({ x, d }: { x: EnrichmentConsoleSource; d: EnrichmentSourceDetail }) {
  const schedules = useJobSchedules();
  const update = useUpdateJobSchedule();
  const reset = useResetJobSchedule();
  const runNow = useRunJobNow();
  const [editing, setEditing] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  if (d.jobs.length === 0) {
    return <p className={s.note}>No scheduled jobs. {x.label} only answers lookups.</p>;
  }
  const done = () => {
    setEditing(null);
    setSaved(true);
  };

  return (
    <div className={s.stack}>
      {d.jobs.map((j) => {
        const job = schedules.data?.jobs.find((sj) => sj.name === j.key);
        const counts = j.last_detail && ["fetched", "changed", "written"].every((k) => typeof j.last_detail![k] === "number")
          ? (j.last_detail as Record<string, number>)
          : null;
        return (
          <div key={j.key} className={s.job}>
            <div className={s.jobHead}>
              <b>{j.key}</b>
              <span className={j.last_status === "error" ? s.badWord : s.muted}>
                {j.runs_30d === 0 ? "no runs in 30 days" : `${j.ok_30d} of ${j.runs_30d} ok in 30 days`}
              </span>
            </div>
            <p className={s.note}>{j.description}</p>
            <div className={s.form}>
              <span className={s.formLabel}>Schedule</span>
              <span className={s.in}>
                {j.schedule}
                {job && (
                  <button type="button" className={s.link} onClick={() => setEditing(editing === j.key ? null : j.key)}>
                    {editing === j.key ? "Close" : "Change"}
                  </button>
                )}
                <button
                  type="button"
                  className={s.link}
                  disabled={!x.enabled || runNow.isPending}
                  onClick={() =>
                    runNow.mutate(j.key, {
                      onSuccess: () => toast.success(`${j.key} queued`),
                      onError: (e) => toast.error(`Couldn't run ${j.key}: ${(e as Error).message}`),
                    })
                  }
                >
                  Run now
                </button>
              </span>
              {counts && (
                <>
                  <span className={s.formLabel}>Last run</span>
                  <span className={s.in}>
                    {num(counts.fetched)} fetched · {num(counts.changed)} changed · {num(counts.written)} written
                  </span>
                </>
              )}
            </div>
            {editing === j.key && job && (
              <ScheduleEditor
                job={job}
                saving={update.isPending || reset.isPending}
                onCancel={() => setEditing(null)}
                onSave={(schedule) =>
                  update.mutate(
                    { name: j.key, schedule },
                    { onSuccess: done, onError: (e) => toast.error(`Couldn't save the schedule: ${(e as Error).message}`) },
                  )
                }
                onReset={
                  job.is_customized
                    ? () =>
                        reset.mutate(j.key, {
                          onSuccess: done,
                          onError: (e) => toast.error(`Couldn't reset the schedule: ${(e as Error).message}`),
                        })
                    : undefined
                }
              />
            )}
            {j.settings_keys.length > 0 && <SystemSettings filterKeys={j.settings_keys} flat />}
            {j.last_status === "error" && j.last_error && <p className={s.err}>{j.last_error}</p>}
          </div>
        );
      })}
      {saved && (
        <p className={s.note}>
          A new schedule takes effect after <code>docker compose restart celery-beat</code>.
        </p>
      )}
      <p className={s.note}>Turning {x.label} off pauses its jobs.</p>
    </div>
  );
}
