/**
 * Hunts, one line per hunt: number, title, tactic and any telemetry it needs that isn't collected, with Copy and ATHF file buttons on the line. A line expands in place to show the hypothesis, its techniques (linked to their profiles), the query, and the why / adapt / false-positive notes behind one link.
 * The same list appears in two places, both backed by hooks/useHuntPacks: the entity profile's Hunts row (`HuntRowBody`, drafted from everything reported on the entity; the row line carries Draft more / Draft again through `HuntDraftLinks`) and the Threats board drawer (`HuntPackPanel`, drafted from the board's time window).
 * A pack is a starting point for a hunt that is run in the SIEM and recorded in the ATHF workspace; IntelFeed tracks nothing past the draft.
 */
import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import {
  downloadHuntFile,
  useDraftHuntPack,
  useHuntPack,
  type HuntHypothesis,
  type HuntPack,
} from "@/hooks/useHuntPacks";
import { queryLanguageShort } from "@/utils/queryLanguage";
import styles from "./HuntPackPanel.module.css";

export function huntApiMessage(err: unknown, fallback: string): string {
  const data = (err as { response?: { data?: { error?: { message?: string }; message?: string; detail?: string } } })
    ?.response?.data;
  return data?.error?.message ?? data?.message ?? data?.detail ?? fallback;
}

/** "0:42" since an ISO timestamp, ticking once a second. */
export function useElapsed(since: string | null | undefined): string | null {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!since) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [since]);
  if (!since) return null;
  const secs = Math.max(0, Math.round((now - new Date(since).getTime()) / 1000));
  return `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")}`;
}

/** "all 3 run on your telemetry" / "4 of 5 run on your telemetry". */
export function runsPhrase(pack: HuntPack): string {
  const total = pack.hypotheses.length;
  const runs = pack.hypotheses.filter((h) => h.runnable).length;
  return runs === total ? `all ${total} run on your telemetry` : `${runs} of ${total} run on your telemetry`;
}

/** "4 run on the telemetry you collect; 1 needs auth.failure." — the Next steps line. */
/** What one hunt needs that isn't collected: the log it reads first, then log types. */
export function missingFor(h: HuntHypothesis): string[] {
  return [
    ...(h.log_source && h.source_have === false ? [h.log_source] : []),
    ...h.telemetry.filter((t) => !t.have).map((t) => t.source),
  ];
}

export function runnableSummary(pack: HuntPack): string {
  const runs = pack.hypotheses.filter((h) => h.runnable).length;
  const blockedHunts = pack.hypotheses.filter((h) => !h.runnable);
  // A missing log source is a whole sentence ("vCenter VCSA SSO logs forwarded via syslog to…"), too long to list here, and each hunt's own line names it; so when any hunt lacks its log source, fall back to "logs you don't collect".
  const missing = blockedHunts.some((h) => h.log_source && h.source_have === false)
    ? []
    : [...new Set(blockedHunts.flatMap(missingFor))];
  const blocked = pack.hypotheses.length - runs;
  if (blocked === 0) return `${runs === 1 ? "It runs" : `All ${runs} run`} on the telemetry you collect.`;
  const needs = missing.length ? ` ${missing.join(", ")}` : " logs you don't collect";
  return `${runs} run on the telemetry you collect; ${blocked} need${blocked === 1 ? "s" : ""}${needs}.`;
}

/** "Nov 23". */
export function shortDate(iso: string | null | undefined): string | null {
  return iso ? new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric" }) : null;
}

/** Draft, draft again (replace) and draft more (append) for one pack. */
export function useHuntDraft(entityType: string, entityKey: string, scope: string, label: string, enabled = true) {
  const query = useHuntPack(entityType, entityKey, scope, enabled);
  const draft = useDraftHuntPack();
  const data = query.data;
  const drafting = data?.status === "drafting" || draft.isPending;
  const run = (more = false) =>
    draft.mutate(
      { entityType, entityKey, scope, more },
      { onError: (err) => toast.error(huntApiMessage(err, `Could not draft hunts for ${label}`)) },
    );
  return { data, isLoading: query.isLoading, drafting, run };
}

/** Draft more · Draft again, for a line that already holds a pack. */
export function HuntDraftLinks({ drafting, onRun }: { drafting: boolean; onRun: (more: boolean) => void }) {
  if (drafting) return <span className={styles.muted}>Drafting…</span>;
  return (
    <>
      <button type="button" className={styles.link} onClick={() => onRun(true)}>
        Draft more
      </button>
      <button type="button" className={styles.link} onClick={() => onRun(false)}>
        Draft again
      </button>
    </>
  );
}

function HuntLine({
  h,
  dialect,
  open,
  onToggle,
  onDownload,
}: {
  h: HuntHypothesis;
  dialect: string;
  open: boolean;
  onToggle: () => void;
  onDownload: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [details, setDetails] = useState(false);
  // missingFor lists the uncollected log source first: it is why the hunt can't run, even when its log types show as collected from some other source.
  const missing = missingFor(h);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(h.query);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error("Clipboard unavailable. Select the query and copy it.");
    }
  };
  return (
    <div className={styles.hunt}>
      <div className={styles.line}>
        <button type="button" className={styles.lineToggle} onClick={onToggle} aria-expanded={open}>
          <span className={styles.caret} aria-hidden="true">
            {open ? "▾" : "▸"}
          </span>
          <span className={styles.hid}>{h.id}</span>
          <span className={styles.title}>{h.title}</span>
          {h.tactic && <span className={styles.tactic}>{h.tactic}</span>}
          {missing.length > 0 && <span className={styles.needs}>needs {missing.join(", ")}</span>}
        </button>
        <button type="button" className={styles.lineBtn} onClick={copy} aria-label={`Copy ${dialect} for ${h.id}`}>
          {copied ? "Copied" : `Copy ${dialect}`}
        </button>
        <button
          type="button"
          className={styles.lineBtn}
          onClick={onDownload}
          aria-label={`Download ${h.id} as an ATHF hunt file`}
        >
          ATHF file
        </button>
      </div>
      {open && (
        <div className={styles.body}>
          <p className={styles.hypothesis}>{h.hypothesis}</p>
          {(h.technique_refs?.length ?? 0) > 0 && (
            <div className={styles.techniques}>
              {h.technique_refs!.map((t) => {
                const label = t.name ? `${t.technique_id} ${t.name}` : t.technique_id;
                return t.id ? (
                  <Link key={t.technique_id} className={styles.techLink} to={`/workbench/ttp/${t.id}`}>
                    {label}
                  </Link>
                ) : (
                  <span key={t.technique_id}>{label}</span>
                );
              })}
            </div>
          )}
          {h.log_source && (
            <div className={styles.reads}>
              Reads {h.log_source}
              {h.source_have === false && <span className={styles.readsMissing}> — not in your telemetry inventory</span>}
            </div>
          )}
          <pre className={styles.query}>{h.query}</pre>
          <div>
            <button type="button" className={styles.link} onClick={() => setDetails((d) => !d)} aria-expanded={details}>
              {details ? "Hide why, adapt, false positives" : "Why, adapt, false positives"}
            </button>
          </div>
          {details && (
            <div className={styles.details}>
              {h.evidence && (
                <>
                  <span className={styles.k}>Why</span>
                  <span>{h.evidence}</span>
                </>
              )}
              {h.query_notes && (
                <>
                  <span className={styles.k}>Adapt</span>
                  <span>{h.query_notes}</span>
                </>
              )}
              {h.false_positives && (
                <>
                  <span className={styles.k}>False positives</span>
                  <span>{h.false_positives}</span>
                </>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** The hunts, one line each; the first opens by default, one open at a time. */
export function HuntList({
  pack,
  entityType,
  entityKey,
  scope,
}: {
  pack: HuntPack;
  entityType: string;
  entityKey: string;
  scope: string;
}) {
  const [open, setOpen] = useState<string | null>(pack.hypotheses[0]?.id ?? null);
  const dialect = queryLanguageShort(pack.language);
  const download = async (h: HuntHypothesis) => {
    try {
      await downloadHuntFile(entityType, entityKey, scope, h.id);
    } catch (err) {
      toast.error(huntApiMessage(err, "Could not download the hunt file"));
    }
  };
  return (
    <div className={styles.list}>
      {pack.hypotheses.map((h) => (
        <HuntLine
          key={h.id}
          h={h}
          dialect={dialect}
          open={open === h.id}
          onToggle={() => setOpen(open === h.id ? null : h.id)}
          onDownload={() => download(h)}
        />
      ))}
    </div>
  );
}

/** Drafting / failed / before-the-first-draft lines shared by the profile row and the board drawer. */
function HuntStatus({
  draftState,
  emptyText,
  asLink = false,
}: {
  draftState: ReturnType<typeof useHuntDraft>;
  emptyText: string;
  /** Draft hunts as a text link (the profile) rather than a button (the board). */
  asLink?: boolean;
}) {
  const { data, isLoading, drafting, run } = draftState;
  const elapsed = useElapsed(data?.status === "drafting" ? data.started_at : null);
  if (isLoading) return <div className={styles.muted}>…</div>;
  if (drafting) {
    return (
      <div className={styles.muted}>
        Drafting hunts{elapsed ? ` · ${elapsed}` : ""}. You can leave this page; they're saved when the model finishes.
      </div>
    );
  }
  return (
    <>
      {data?.status === "failed" && <div className={styles.error}>The last draft failed: {data.error}</div>}
      {!data?.pack && (
        <div className={styles.empty}>
          <span>{emptyText}</span>
          <div>
            <button type="button" className={asLink ? styles.link : styles.btn} onClick={() => run(false)}>
              Draft hunts
            </button>
          </div>
        </div>
      )}
    </>
  );
}

/** The profile's Hunts row body. Its line carries HuntDraftLinks. */
export function HuntRowBody({
  draftState,
  entityType,
  entityKey,
  label,
}: {
  draftState: ReturnType<typeof useHuntDraft>;
  entityType: string;
  entityKey: string;
  label: string;
}) {
  const pack = draftState.data?.pack ?? null;
  const dialect = queryLanguageShort(draftState.data?.language);
  return (
    <div className={styles.panel}>
      <HuntStatus
        draftState={draftState}
        asLink
        emptyText={`Up to five ${dialect} hunts from everything reported on ${label}: claimed techniques and tools first, techniques with no rule first. Takes about a minute.`}
      />
      {pack && <HuntList pack={pack} entityType={entityType} entityKey={entityKey} scope={pack.window} />}
    </div>
  );
}

/** The Threats board drawer's hunts: header line, list, and a footer slot. */
export function HuntPackPanel({
  entityType,
  entityKey,
  label,
  scope,
  scopeLabel,
  actions,
  footer,
}: {
  entityType: string;
  entityKey: string;
  label: string;
  scope: string;
  /** "last 14 days". */
  scopeLabel: string;
  /** Extra controls at the end of the header line (Download hunt package). */
  actions?: ReactNode;
  footer?: ReactNode;
}) {
  const draftState = useHuntDraft(entityType, entityKey, scope, label);
  const { data, drafting, run } = draftState;
  const pack = data?.pack ?? null;
  const dialect = queryLanguageShort(data?.language);
  return (
    <div className={styles.panel}>
      <div className={styles.head}>
        <span className={styles.headLabel}>
          Hunt{pack ? ` · ${pack.hypotheses.length}` : ""}
          <span className={styles.headNote}>
            {[dialect, scopeLabel, pack ? runsPhrase(pack) : null].filter(Boolean).join(" · ")}
          </span>
        </span>
        {pack && <HuntDraftLinks drafting={drafting} onRun={run} />}
        {actions}
      </div>
      <HuntStatus
        draftState={draftState}
        emptyText={`Up to three ${dialect} hunts from this window's articles and techniques.`}
      />
      {pack && <HuntList pack={pack} entityType={entityType} entityKey={entityKey} scope={scope} />}
      {footer && <div className={styles.footer}>{footer}</div>}
    </div>
  );
}
