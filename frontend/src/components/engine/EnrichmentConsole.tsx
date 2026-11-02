/**
 * Settings → Engine → Enrichment. Everything has one home: sources and their
 * limits, fields and jobs in Sources (a list with a side panel), fill rates
 * and AI research in Coverage, every API key in Keys, the queue and requests
 * in Activity. Problems sit on top, each with the one button that fixes it.
 * Color only marks what needs action.
 */
import { useContext, useEffect, useState } from "react";
import { toast } from "sonner";

import { AsyncStateLoading } from "@/components/AsyncState";
import { SettingsHighlightContext } from "@/components/SystemSettings";
import { Hint, Segmented } from "@/components/primitives";
import {
  useEnrichmentConsole,
  useEnrichmentKeys,
  usePauseEnrichment,
  useRetryFailedLookups,
  type EnrichmentAction,
  type EnrichmentConsole as ConsoleData,
} from "@/hooks/useEnrichment";

import { ActivityView } from "./enrichment/ActivityView";
import { CoverageView } from "./enrichment/CoverageView";
import { KeysView } from "./enrichment/KeysView";
import { SourcesView, type Selection } from "./enrichment/SourcesView";
import { Sparkline } from "./enrichment/Sparkline";
import { num } from "./enrichment/format";
import s from "./EnrichmentConsole.module.css";

type View = "sources" | "coverage" | "keys" | "activity";

export function EnrichmentConsole({
  initialSource,
  initialKeyFor,
}: {
  /** Open this source on its Jobs tab (from Engine → Jobs). */
  initialSource?: string | null;
  /** Open the Keys view at this source's key (from a profile's "Add key"). */
  initialKeyFor?: string | null;
}) {
  const [view, setView] = useState<View>("sources");
  // Opened from a job (Engine → Jobs): that source, on its Jobs tab.
  const [sel, setSel] = useState<Selection>({ source: initialSource ?? null, tab: initialSource ? "jobs" : "overview" });
  const [editingKey, setEditingKey] = useState<string | null>(null);

  const consoleQ = useEnrichmentConsole();
  const keysQ = useEnrichmentKeys();
  const highlight = useContext(SettingsHighlightContext);
  const data = consoleQ.data;

  // A profile's "Add key": that source's key in Keys, or the source itself
  // when what it lacks isn't a key.
  const [keyForDone, setKeyForDone] = useState(false);
  useEffect(() => {
    if (!initialKeyFor || keyForDone || !data) return;
    setKeyForDone(true);
    const src = data.sources.find((x) => x.source_type === initialKeyFor);
    if (src?.key) {
      setView("keys");
      setEditingKey(src.key);
    } else if (src) {
      setSel({ source: src.source_type, tab: "overview" });
    }
  }, [initialKeyFor, keyForDone, data]);

  // A settings search that jumped here opens the setting's home: a key in
  // Keys, a job setting on its source's Jobs tab. Each jump (nonce) is
  // followed once, so a refetch doesn't pull the user back there.
  const [followedNonce, setFollowedNonce] = useState<number | null>(null);
  useEffect(() => {
    if (!highlight || !data || followedNonce === highlight.nonce) return;
    setFollowedNonce(highlight.nonce);
    const key = keysQ.data?.find((k) => k.id === highlight.key);
    if (key) {
      setView("keys");
      setEditingKey(key.id);
      return;
    }
    const own = data.sources.find((x) => x.source_settings.includes(highlight.key));
    const job = data.sources.find((x) => x.settings_keys.includes(highlight.key));
    if (own || job) {
      setView("sources");
      setSel({ source: (own ?? job)!.source_type, tab: own ? "limits" : "jobs" });
    }
  }, [highlight, data, keysQ.data, followedNonce]);

  if (!data) {
    return consoleQ.isError ? (
      <p className={s.note}>Couldn't load the enrichment console.</p>
    ) : (
      <AsyncStateLoading label="Loading enrichment…" />
    );
  }

  const go = (action: EnrichmentAction) => {
    if (action.kind === "key") {
      setView("keys");
      setEditingKey(action.key);
    } else if (action.kind === "source") {
      setView("sources");
      setSel({ source: action.source, tab: action.tab });
    }
  };
  const openKey = (key: string) => go({ kind: "key", key, label: "" });

  // A missing key only counts when a source that needs it is on.
  const on = new Set(data.sources.filter((x) => x.enabled).map((x) => x.source_type));
  const keyProblems = (keysQ.data ?? []).filter(
    (k) =>
      k.sources.some((x) => on.has(x.source_type)) && (k.status === "rejected" || (k.status === "missing" && k.required)),
  );

  return (
    <div className={s.page}>
      <Header data={data} />
      <Strip data={data} />
      <Attention data={data} go={go} />

      <Segmented<View>
        role="tablist"
        label="Enrichment views"
        className={s.viewSwitch}
        value={view}
        onChange={setView}
        options={(
          [
            ["sources", "Sources", `${data.summary.sources_on} on`],
            ["coverage", "Coverage", null],
            ["keys", "Keys", keyProblems.length || null],
            ["activity", "Activity", null],
          ] as const
        ).map(([id, label, extra]) => ({
          value: id,
          id: `enrichment-view-${id}`,
          controls: `enrichment-panel-${id}`,
          label: (
            <>
              {label}
              {extra != null &&
                (typeof extra === "number" ? (
                  <span className={s.badge} aria-label={`${extra} need a look`}>
                    {extra}
                  </span>
                ) : (
                  <span className={s.viewCount}>{extra}</span>
                ))}
            </>
          ),
        }))}
      />

      <div role="tabpanel" id={`enrichment-panel-${view}`} aria-labelledby={`enrichment-view-${view}`}>
        {view === "sources" && <SourcesView data={data} sel={sel} setSel={setSel} openKey={openKey} />}
        {view === "coverage" && <CoverageView openSource={(source) => go({ kind: "source", source, tab: "fields", label: "" })} />}
        {view === "keys" && <KeysView editing={editingKey} setEditing={setEditingKey} />}
        {view === "activity" && <ActivityView />}
      </div>
    </div>
  );
}

function Header({ data }: { data: ConsoleData }) {
  const pause = usePauseEnrichment();
  const { paused } = data.summary;
  const toggle = () =>
    pause.mutate(!paused, {
      onError: (e) => toast.error(`Couldn't ${paused ? "resume" : "pause"}: ${(e as Error).message}`),
    });
  return (
    <div className={s.head}>
      <span className={paused ? `${s.state} ${s.statePaused}` : s.state}>
        <span className={paused ? `${s.dot} ${s.dotWarn}` : `${s.dot} ${s.dotOk}`} aria-hidden />
        {paused ? "Paused · nothing leaves the box" : "Running"}
      </span>
      <span className={s.spacer} />
      <Hint
        title={paused ? "Resume all sources" : "Pause all sources"}
        body="Stops every request to outside sources at once. Queued lookups wait and resume when you resume. Per-source settings don't change."
      >
        <button type="button" className={s.btn} onClick={toggle} disabled={pause.isPending}>
          {paused ? "Resume all sources" : "Pause all sources"}
        </button>
      </Hint>
    </div>
  );
}

function Strip({ data }: { data: ConsoleData }) {
  const a = data.summary.activity_24h;
  return (
    <div className={s.strip} aria-label="Last 24 hours">
      <div>
        <span>Requests · 24h</span>
        <b>{num(a.requests)}</b>
        <Sparkline points={a.trend} label={`${num(a.requests)} requests in the last 24 hours`} />
      </div>
      <div>
        <span>Waiting in queue</span>
        <b>{num(a.waiting)}</b>
        <em>{a.waiting_backfill ? `${num(a.waiting_backfill)} are backfill` : "none are backfill"}</em>
      </div>
      <div>
        <span>Put off · 24h</span>
        <b>{num(a.deferred)}</b>
        <em>rate limit or daily cap</em>
      </div>
      <div>
        <span>Indicators sent out · 24h</span>
        <b>{a.iocs_sent == null ? "—" : num(a.iocs_sent)}</b>
        <em>{a.ioc_sources.length ? `to ${a.ioc_sources.join(", ")}` : "no source that receives them is on"}</em>
      </div>
      <div>
        <span>Limiter</span>
        <b className={data.summary.redis_ok ? s.okWord : s.badWord}>{data.summary.redis_ok ? "Healthy" : "Down"}</b>
        <em>{data.summary.redis_ok ? "refuses requests if Redis is down" : "every request is refused"}</em>
      </div>
    </div>
  );
}

function Attention({ data, go }: { data: ConsoleData; go: (a: EnrichmentAction) => void }) {
  const retry = useRetryFailedLookups();
  if (data.attention.length === 0) return null;
  const run = (action: EnrichmentAction) => {
    if (action.kind !== "retry") return go(action);
    retry.mutate(action.source, {
      onSuccess: (r) => toast.success(`Queued ${num(r.queued)} lookups again`),
      onError: (e) => toast.error(`Couldn't retry: ${(e as Error).message}`),
    });
  };
  return (
    <section className={s.attn} aria-label="Needs attention">
      <h3 className={s.attnHead}>
        Needs attention <span>{data.attention.length}</span>
      </h3>
      {data.attention.map((item, i) => (
        <div key={`${item.source_type}-${i}`} className={s.attnRow}>
          <span className={item.severity === "bad" ? `${s.dot} ${s.dotBad}` : `${s.dot} ${s.dotWarn}`} aria-hidden />
          <p>
            <b>{item.label}</b>
            {item.sources && <span className={s.muted}> ({item.sources.join(", ")})</span>}: {item.text}
          </p>
          {item.action && (
            <button
              type="button"
              className={s.btn}
              disabled={item.action.kind === "retry" && retry.isPending}
              onClick={() => run(item.action!)}
            >
              {item.action.label}
            </button>
          )}
        </div>
      ))}
    </section>
  );
}
