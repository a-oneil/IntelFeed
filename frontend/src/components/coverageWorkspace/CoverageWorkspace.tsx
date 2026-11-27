/**
 * Coverage Workspace: the Detection tab on an entity profile, shown as one verdict sentence and one list of behaviors.
 *
 * The tab answers "am I covered for this threat?". It states the answer first, in a sentence computed from the same counts as the ribbon under it, so the two cannot disagree. Showing articles, behaviors and candidate rules side by side in columns left the reader to work out the answer.
 *
 * Below the verdict is one list (the "ladder") of behaviors, ordered by the next action to take. Opening a row shows that behavior's evidence, candidate rules and actions in the row itself. Source articles and behaviors with no log source are supporting detail, so they sit in collapsed sections.
 *
 * A behavior whose required channels match nothing in the telemetry inventory is a collection gap, never a detection gap: a rule for it would not fire, so it is not counted as a missing rule.
 */
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import api from "@/api/client";
import { useIntelStore } from "@/stores/intelStore";
import { useUIStore } from "@/stores/uiStore";
import { Chip, Segmented } from "@/components/primitives";
import { AsyncStateLoading } from "@/components/AsyncState";
import {
  useBehaviorRules,
  useCoverageWorkspace,
  useDeleteCoverageSet,
  useSaveCoverageSet,
  useSavedSets,
  type CoverageWorkspace as WorkspaceData,
  type PriorRuleItem,
  type SetItem,
  type SetOp,
  type WorkspaceBehavior,
} from "@/hooks/useCoverageWorkspace";
import styles from "./coverageWorkspace.module.css";

const WINDOWS = [
  { value: "7d", label: "7d" },
  { value: "14d", label: "14d" },
  { value: "30d", label: "30d" },
  { value: "90d", label: "90d" },
  { value: "all", label: "All" },
] as const;

const OP_TINT: Record<SetOp, string> = {
  adopt: "var(--entity-rule, #22c55e)",
  extend: "var(--accent)",
  new: "var(--entity-ttp, #3b82f6)",
  skip: "var(--text-muted)",
};

/** sessionStorage keys for the handoff to the rule editor (the bench). The seed is written before navigating there; the return is written by the editor after a save. This is temporary working state; the set itself is saved through the sets endpoint. */
const BENCH_SEED_KEY = "intelfeed-bench-seed";
const BENCH_RETURN_KEY = "intelfeed-bench-return";

/** entity_ids buckets the report generator reads. A campaign has no bucket, so its set attaches the articles and the rules without the entity itself. */
const ENTITY_ID_BUCKETS: Record<string, string> = {
  threat_actor: "actors",
  malware: "malware",
  cve: "cves",
  ttp: "ttps",
};

/** Ladder rows rendered per page. An all-time ladder on a long-lived actor can reach 200 rows; the ordering already puts the actionable rows at the top, so the rest is paged instead of rendered at once. */
const LADDER_PAGE = 40;

/** Candidates shown inside an open row before the rest collapse to one line. The ranking is only as good as the signals behind it, so this stays small: three rows to read, not a page to scroll. */
const CANDIDATES_SHOWN = 3;

type VerdictKey = "ok" | "warn" | "bad" | "inert";

interface Verdict {
  key: VerdictKey;
  /** Right-edge label — the verdict in words, before anything is opened. */
  label: string;
  color: string;
}

/**
 * The next action for this behavior, computed from stored fields only.
 *
 * Order matters: the below-line test comes first because it outranks every other result. A behavior with 46 candidate rules and no log source is not "well covered", because none of those rules can fire here.
 *
 * The tier test uses `tier` alone, on purpose. `tier` is the strongest match any of the technique's channels reached, and a technique lists every data source ATT&CK knows of. No real inventory has all of them, so `missing_channels` is non-empty for almost every behavior; including it put zero behaviors in the adoptable bucket on every entity tested. Partial coverage of a technique's channels is the normal case.
 */
function verdictFor(b: WorkspaceBehavior): Verdict {
  if (b.below_line) return { key: "inert", label: "No log source", color: "var(--text-muted)" };
  if (b.prior_rules === 0) return { key: "bad", label: "Nothing to adopt", color: "var(--danger, #f85149)" };
  if (b.tier !== "source") return { key: "warn", label: "Tune first", color: "var(--warning, #d29922)" };
  return { key: "ok", label: `Adopt ${Math.min(b.prior_rules, CANDIDATES_SHOWN)}`, color: "var(--success, #3fb950)" };
}

const VERDICT_RANK: Record<VerdictKey, number> = { ok: 0, warn: 1, bad: 2, inert: 3 };

/** Categories are stored as slugs; prose reads better in words. */
function humanCategory(slug: string): string {
  return slug.replace(/_/g, " ");
}

function formatDate(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? "" : d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** "3w", "7mo" — how long since anyone touched the rule upstream. */
function shortAge(iso: string | null | undefined): string {
  if (!iso) return "";
  const then = new Date(iso).getTime();
  if (isNaN(then)) return "";
  const days = Math.max(0, Math.round((Date.now() - then) / 86_400_000));
  if (days < 1) return "today";
  if (days < 14) return `${days}d`;
  if (days < 60) return `${Math.round(days / 7)}w`;
  if (days < 730) return `${Math.round(days / 30)}mo`;
  return `${Math.round(days / 365)}y`;
}

/** Human phrase for the window, used inside the verdict sentence. */
function windowPhrase(window: string): string {
  return window === "all" ? "on record" : "in this window";
}

function tierNote(rule: PriorRuleItem): string {
  if (!rule.tier) return "no matching source, cannot fire here";
  if (rule.missing.length > 0) return `needs ${rule.missing.slice(0, 2).join(", ")}`;
  return "fires against your telemetry";
}

/** The headline sentence, assembled from the same counts the ribbon renders. */
function VerdictLine({
  data,
  counts,
  candidateTotal,
}: {
  data: WorkspaceData;
  counts: Record<VerdictKey, number>;
  candidateTotal: number;
}) {
  const total = data.behaviours.length;
  const firable = total - counts.inert;
  const cats = data.missing_categories.map(humanCategory).join(" or ");

  if (total === 0) {
    return (
      <p className={styles.verdictLine}>
        No techniques were extracted for <b>{data.label}</b> {windowPhrase(data.window)}, so there is nothing to
        judge coverage against yet.
      </p>
    );
  }

  return (
    <p className={styles.verdictLine}>
      <b className={styles.numOk}>{firable}</b> of {data.label}&rsquo;s <b>{total}</b>{" "}
      {total === 1 ? "behavior" : "behaviors"} {windowPhrase(data.window)} could fire against your telemetry.
      {counts.inert > 0 && (
        <>
          {" "}
          <b className={styles.numInert}>{counts.inert}</b> {counts.inert === 1 ? "cannot" : "cannot"}: you collect
          no {cats || "matching"} source for {counts.inert === 1 ? "it" : "them"}.
        </>
      )}
      {candidateTotal > 0 && (
        <>
          {" "}
          Of the <b>{candidateTotal.toLocaleString()}</b> library{" "}
          {candidateTotal === 1 ? "rule" : "rules"} matching these techniques,{" "}
          {data.threat_prior_rules > 0 ? (
            <>
              <b className={styles.numOk}>{data.threat_prior_rules}</b>{" "}
              {data.threat_prior_rules === 1 ? "names" : "name"} {data.label} directly.
            </>
          ) : (
            <>
              <b className={styles.numWarn}>none</b> were written for {data.label}.
            </>
          )}
        </>
      )}
    </p>
  );
}

/** One behavior: the verdict on the closed row, everything else inside it. */
function LadderRow({
  behaviour,
  open,
  onToggle,
  children,
}: {
  behaviour: WorkspaceBehavior;
  open: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}) {
  const v = verdictFor(behaviour);
  return (
    <div className={styles.row} data-open={open || undefined}>
      <button type="button" className={styles.rowBtn} onClick={onToggle} aria-expanded={open}>
        <span className={styles.rowStripe} style={{ background: v.color }} />
        <Chip size="sm" tone="toned" tint="var(--entity-ttp, #3b82f6)">
          {behaviour.technique_id}
        </Chip>
        <span className={styles.rowText}>
          <span className={styles.rowName}>{behaviour.technique_name}</span>
          <span className={styles.rowSub}>
            {behaviour.tactic ? humanCategory(behaviour.tactic).replace(/-/g, " ") : "no tactic"}
            {behaviour.entry_count > 0 &&
              ` · ${behaviour.entry_count} ${behaviour.entry_count === 1 ? "article" : "articles"}`}
          </span>
        </span>
        <span className={styles.rowRight}>
          {behaviour.is_new && (
            <Chip size="sm" tone="quiet" tint="var(--accent)">
              new
            </Chip>
          )}
          <span className={styles.rowVerdict} style={{ color: v.color }}>
            {v.label}
          </span>
          <span className={`${styles.rowCaret} caret-glyph`} aria-hidden="true" />
        </span>
      </button>
      {open && <div className={styles.drawer}>{children}</div>}
    </div>
  );
}

export function CoverageWorkspace({
  entityType,
  entityKey,
  label,
  onNavigateRule,
}: {
  entityType: string;
  entityKey: string;
  label: string;
  onNavigateRule: (ruleId: string) => void;
}) {
  const [window, setWindow] = useState<string>("14d");
  const [openId, setOpenId] = useState<string | null>(null);
  const [items, setItems] = useState<SetItem[]>([]);
  const [summaryId, setSummaryId] = useState<string | null>(null);
  const [shown, setShown] = useState(LADDER_PAGE);
  const [showAllCandidates, setShowAllCandidates] = useState(false);
  const navigate = useNavigate();

  // Articles open in the workbench's docked reader, so the tab stays in place and works as the entry list, the same list-plus-reader pairing used elsewhere in the app.
  const onOpenArticle = (entryId: string) => {
    useIntelStore.getState().openWorkbenchReader(entryId);
  };

  // A skip is stored as a set item (op "skip"), so it is saved with the set and exported as a known gap. Skipped rules are removed from the candidate list.
  const skipped = useMemo(
    () => items.filter((i) => i.op === "skip" && i.rule_id).map((i) => i.rule_id as string),
    [items]
  );

  // Returning from the rule editor: a rule drafted or extended there is added to the set once (the return key is removed after it is read, and a rule already in the set is not added again).
  useEffect(() => {
    const raw = sessionStorage.getItem(BENCH_RETURN_KEY);
    if (!raw) return;
    try {
      const ret = JSON.parse(raw);
      if (ret.entityType !== entityType || ret.entityKey !== entityKey) return;
      sessionStorage.removeItem(BENCH_RETURN_KEY);
      setItems((prev) =>
        prev.some((i) => i.rule_id === ret.ruleId)
          ? prev
          : [
              ...prev,
              {
                op: (ret.op ?? "new") as SetOp,
                rule_id: ret.ruleId,
                technique_id: ret.techniqueId ?? null,
                title: ret.title ?? "New rule",
                rule_type: ret.ruleType ?? null,
              },
            ]
      );
      toast.success(`Added "${ret.title ?? "new rule"}" to the set`);
    } catch {
      sessionStorage.removeItem(BENCH_RETURN_KEY);
    }
  }, [entityType, entityKey]);

  const { data, isLoading } = useCoverageWorkspace(entityType, entityKey, window, true);
  const { data: sets } = useSavedSets(entityType, entityKey, true);
  // Only the open row fetches candidates: one query for the row being read instead of a query for every row.
  const { data: rules, isLoading: rulesLoading } = useBehaviorRules(entityType, entityKey, openId);
  const saveSet = useSaveCoverageSet(entityType, entityKey);
  const deleteSet = useDeleteCoverageSet(entityType, entityKey);

  const behaviours = useMemo(() => data?.behaviours ?? [], [data]);

  // Ordered by next action (verdict rank), not by technique number. Within a verdict, the behavior with the most articles in the window comes first.
  const ladder = useMemo(
    () =>
      behaviours
        .filter((b) => !b.below_line)
        .slice()
        .sort((a, b) => {
          const d = VERDICT_RANK[verdictFor(a).key] - VERDICT_RANK[verdictFor(b).key];
          return d || b.entry_count - a.entry_count || a.technique_id.localeCompare(b.technique_id);
        }),
    [behaviours]
  );
  const belowLine = useMemo(() => behaviours.filter((b) => b.below_line), [behaviours]);

  const counts = useMemo(() => {
    const out: Record<VerdictKey, number> = { ok: 0, warn: 0, bad: 0, inert: 0 };
    for (const b of behaviours) out[verdictFor(b).key] += 1;
    return out;
  }, [behaviours]);

  const candidateTotal = useMemo(
    () => behaviours.reduce((sum, b) => sum + b.prior_rules, 0),
    [behaviours]
  );

  const contributed = data?.article_contributed_total ?? 0;
  const articleTotal = data?.article_total ?? 0;

  const addItem = (op: SetOp, rule: PriorRuleItem | null, techniqueId: string | null, reason?: string) => {
    const key = rule ? `${op}:${rule.rule_id}` : `${op}:${techniqueId}:${items.length}`;
    setItems((prev) => [
      ...prev.filter((i) => `${i.op}:${i.rule_id}` !== key),
      {
        op,
        rule_id: rule?.rule_id ?? null,
        technique_id: techniqueId,
        title: rule?.title ?? `New rule for ${techniqueId ?? label}`,
        rule_type: rule?.rule_type ?? null,
        repo: rule?.repo ?? null,
        license: rule?.license ?? null,
        reason: reason ?? null,
      },
    ]);
  };

  /** Store the behavior's evidence for the rule editor: technique, quotes with their typed observables, a suggested rule format, and the entity link to attach on save. */
  const stashSeed = (techniqueId: string | null) => {
    const behaviour = behaviours.find((b) => b.technique_id === techniqueId);
    const channels = behaviour?.channels.map((c) => c.source.toLowerCase()) ?? [];
    const suggestedType =
      entityType === "cve"
        ? "nuclei"
        : channels.some((c) => c.startsWith("azure") || c.startsWith("m365") || c.startsWith("entra"))
          ? "kql"
          : "sigma";
    sessionStorage.setItem(
      BENCH_SEED_KEY,
      JSON.stringify({
        entityType,
        entityKey,
        label,
        window,
        techniqueId,
        techniqueName: behaviour?.technique_name ?? null,
        suggestedType,
        quotes: (behaviour?.quotes ?? []).slice(0, 3),
        entryIds: (behaviour?.quotes ?? []).map((q) => q.entry_id),
      })
    );
  };

  /** Draft new: open the rule editor preloaded with the technique, the quotes as a cited header, and a format suggested from the entity type and the behavior's log-source channels. Saving returns here and adds the rule to the set. */
  const draftNew = (techniqueId: string | null) => {
    stashSeed(techniqueId);
    const params = new URLSearchParams({ from_set: "1", entity_type: entityType, entity_key: entityKey });
    if (techniqueId) params.set("technique", techniqueId);
    navigate(`/workbench/rule/new?${params.toString()}`);
  };

  const [extending, setExtending] = useState<string | null>(null);
  /** Extend: create the derived_from draft child server-side, add it to the set, and open the rule editor on the child with the upstream rule beside it. */
  const extendRule = async (rule: PriorRuleItem) => {
    if (extending) return;
    setExtending(rule.rule_id);
    try {
      const { data: child } = await api.post(`/detection-rules/${rule.rule_id}/extend`);
      addItem("extend", { ...rule, rule_id: child.id, title: child.title }, openId);
      stashSeed(openId);
      const params = new URLSearchParams({
        from_set: "1",
        extend: "1",
        entity_type: entityType,
        entity_key: entityKey,
      });
      navigate(`/workbench/rule/${child.id}?${params.toString()}`);
    } catch {
      toast.error("Could not create the extension draft");
    } finally {
      setExtending(null);
    }
  };

  const handleSave = () => {
    if (items.length === 0) return;
    saveSet.mutate(
      {
        title: `${label} (${window})`,
        window,
        items: items.map((i) => ({
          op: i.op,
          rule_id: i.rule_id,
          technique_id: i.technique_id,
          title: i.title,
          rule_type: i.rule_type,
          note: i.note ?? null,
          reason: i.reason ?? null,
        })),
        entryIds: (data?.articles ?? []).filter((a) => a.contributed).map((a) => a.entry_id),
        summaryId,
      },
      {
        onSuccess: (saved) => {
          setSummaryId(saved.id);
          toast.success(`Saved ${saved.item_count} item${saved.item_count === 1 ? "" : "s"}`);
        },
        onError: () => toast.error("Could not save the set"),
      }
    );
  };

  const requireSaved = (): string | null => {
    if (!summaryId) {
      toast.info("Save the set first. Export reads the saved set.");
      return null;
    }
    return summaryId;
  };

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  /** Download the saved set as a zip: one file per rule grouped by format, with attribution headers, and the research report as MANIFEST.md. */
  const handleExportZip = async () => {
    const sid = requireSaved();
    if (!sid) return;
    try {
      const res = await api.get(`/coverage-workspace/sets/${sid}/export.zip`, { responseType: "blob" });
      downloadBlob(res.data as Blob, `${label.replace(/[^a-z0-9 _-]/gi, "").trim() || "coverage-set"}.zip`);
    } catch {
      toast.error("Export failed");
    }
  };

  /** Send to report: the one way from this tab into the reporting system, through the same modal every other page opens.

      The set sends three things: the articles the behaviors were read from, the entity itself, and the set's rules (adopted, extended or new), which land as a Detections section with repo and license intact. The skips go in the note, because a gap you decided not to close is a finding too.

      There is no markdown download or clipboard copy, because those produced something that looked like a report but never reached an IntelReport you could version, publish or send. */
  const sendToReport = () => {
    const adopted = items.filter((i) => i.op !== "skip" && i.rule_id).map((i) => i.rule_id as string);
    const skipped = items.filter((i) => i.op === "skip");
    const bucket = ENTITY_ID_BUCKETS[entityType];

    const entityIds: Record<string, string[]> = {};
    if (adopted.length > 0) entityIds.detection_rules = adopted;
    if (bucket) entityIds[bucket] = [entityKey];

    const gaps = skipped.length
      ? `Known gaps: ${skipped.length} rule${skipped.length === 1 ? "" : "s"} considered and not adopted:\n\n` +
        skipped.map((i) => `- ${i.title}${i.reason ? `: ${i.reason}` : ""}`).join("\n")
      : undefined;

    const entryIds = (data?.articles ?? []).filter((a) => a.contributed).map((a) => a.entry_id);

    useUIStore.getState().openSendToReport({
      entryIds,
      entityIds: Object.keys(entityIds).length > 0 ? entityIds : undefined,
      note: gaps,
      label: `${label}: ${adopted.length} rule${adopted.length === 1 ? "" : "s"}`,
      // The new-report wizard starts from entries and carries no entity evidence, so a report started this way does not get the set's rules; sending again once the draft exists attaches them. The wizard is still offered because without it the modal has no next step for someone with no open drafts.
      wizardState: entryIds.length > 0 ? { sourceType: "entries", entryIds, entryTitle: label } : undefined,
    });
  };

  const loadSaved = (id: string) => {
    const found = sets?.items.find((s) => s.id === id);
    if (!found) return;
    setItems(found.content.items ?? []);
    setSummaryId(found.id);
  };

  const toggleRow = (techniqueId: string) => {
    setShowAllCandidates(false);
    setOpenId((prev) => (prev === techniqueId ? null : techniqueId));
  };

  if (isLoading) return <AsyncStateLoading label="Loading coverage" />;
  if (!data) return <div className={styles.empty}>No workspace for this entity.</div>;

  const ribbon = (["ok", "warn", "bad", "inert"] as VerdictKey[])
    .filter((k) => counts[k] > 0)
    .map((k) => ({
      key: k,
      flex: counts[k],
      color:
        k === "ok"
          ? "var(--success, #3fb950)"
          : k === "warn"
            ? "var(--warning, #d29922)"
            : k === "bad"
              ? "var(--danger, #f85149)"
              : "var(--text-muted)",
    }));

  /** The candidate list for the open row, with skips removed. */
  const candidates = (rules?.items ?? []).filter((r) => !skipped.includes(r.rule_id));
  const visibleCandidates = showAllCandidates ? candidates : candidates.slice(0, CANDIDATES_SHOWN);

  return (
    <div className={styles.tab}>
      <div className={styles.verdict}>
        <VerdictLine data={data} counts={counts} candidateTotal={candidateTotal} />
        {behaviours.length > 0 && (
          <>
            <div className={styles.ribbon}>
              {ribbon.map((seg) => (
                <span key={seg.key} style={{ flex: seg.flex, background: seg.color }} />
              ))}
            </div>
            <div className={styles.key}>
              {counts.ok > 0 && (
                <span>
                  <i style={{ background: "var(--success, #3fb950)" }} />
                  {counts.ok} adoptable
                </span>
              )}
              {counts.warn > 0 && (
                <span>
                  <i style={{ background: "var(--warning, #d29922)" }} />
                  {counts.warn} need tuning first
                </span>
              )}
              {counts.bad > 0 && (
                <span>
                  <i style={{ background: "var(--danger, #f85149)" }} />
                  {counts.bad} no library rule
                </span>
              )}
              {counts.inert > 0 && (
                <span>
                  <i style={{ background: "var(--text-muted)" }} />
                  {counts.inert} no log source
                </span>
              )}
            </div>
          </>
        )}
      </div>

      {data.cve && (
        <div className={styles.cveStrip}>
          {data.cve.severity && (
            <Chip size="sm" tone="toned" tint="var(--entity-cve, #ef4444)">
              {data.cve.severity}
            </Chip>
          )}
          {data.cve.cvss_score != null && <span className={styles.cveFact}>CVSS {data.cve.cvss_score.toFixed(1)}</span>}
          {data.cve.is_kev && (
            <Chip
              size="sm"
              tone="toned"
              tint="var(--danger, #f85149)"
              title={data.cve.kev_date_added ? `KEV since ${data.cve.kev_date_added}` : undefined}
            >
              KEV
            </Chip>
          )}
          {data.cve.epss_score != null && (
            <span className={styles.cveFact}>EPSS {Math.round(data.cve.epss_score * 100)}%</span>
          )}
          {data.cve.exploit_availability && data.cve.exploit_availability !== "none" && (
            <span className={styles.cveFact}>{data.cve.exploit_availability.replace(/_/g, " ")}</span>
          )}
          {data.cve.github_poc_count > 0 && <span className={styles.cveFact}>{data.cve.github_poc_count} PoC</span>}
          {data.cve.metasploit_module && <span className={styles.cveFact}>metasploit</span>}
          {data.cve.affected.length > 0 && (
            <span className={styles.cveAffected}>
              affects {data.cve.affected.slice(0, 5).join(", ")}
              {data.cve.affected.length > 5 ? ` +${data.cve.affected.length - 5}` : ""}
            </span>
          )}
        </div>
      )}

      <div className={styles.controls}>
        <Segmented
          options={[...WINDOWS]}
          value={window}
          onChange={(next) => {
            setWindow(next);
            setOpenId(null);
            setShown(LADDER_PAGE);
          }}
          label="Coverage window"
          size="sm"
        />
        <span className={styles.controlsNote}>
          ordered by next action
          {belowLine.length > 0 && ` · ${belowLine.length} without a log source`}
        </span>
      </div>

      <div className={styles.ladder}>
        {ladder.length === 0 && (
          <div className={styles.empty}>
            No techniques were extracted for {label} {windowPhrase(window)}.
          </div>
        )}
        {ladder.slice(0, shown).map((behaviour) => {
          const open = openId === behaviour.technique_id;
          const quote = behaviour.quotes[0];
          const hidden = Math.max(0, (rules?.total_candidates ?? 0) - visibleCandidates.length);
          return (
            <LadderRow
              key={behaviour.technique_id}
              behaviour={behaviour}
              open={open}
              onToggle={() => toggleRow(behaviour.technique_id)}
            >
              {quote ? (
                <div className={styles.evidence}>
                  <q>{quote.text}</q>
                  {quote.observable_value && (
                    <code className={styles.observable} title={quote.observable_type ?? undefined}>
                      {quote.observable_value}
                    </code>
                  )}
                  <cite>
                    <button type="button" className={styles.linkBtn} onClick={() => onOpenArticle(quote.entry_id)}>
                      {quote.entry_title}
                    </button>
                    {quote.paragraph_indices.length > 0 ? ` · ¶${quote.paragraph_indices[0]}` : ""}
                    {quote.telemetry ? ` · ${quote.telemetry}` : ""}
                  </cite>
                </div>
              ) : (
                <div className={styles.evidenceNone}>
                  No sentence was captured for {behaviour.technique_id}. It came from a tag, not article text.
                </div>
              )}

              {rulesLoading && <AsyncStateLoading label="Loading candidate rules" />}

              {!rulesLoading && candidates.length === 0 && (
                <div className={styles.evidenceNone}>
                  No library rule matches this technique. Write a new one.
                </div>
              )}

              {!rulesLoading && candidates.length > 0 && (
                <div className={styles.candidates}>
                  {visibleCandidates.map((rule) => (
                    <div key={rule.rule_id} className={styles.candidate}>
                      <span className={styles.candidateText}>
                        <span className={styles.candidateTitle}>{rule.title}</span>
                        <span className={styles.candidateMeta}>
                          <Chip size="sm" tone="toned" tint="var(--entity-rule, #22c55e)">
                            {rule.rule_type}
                          </Chip>
                          {rule.repo}
                          {rule.license ? ` · ${rule.license}` : ""}
                          {rule.maintained_at ? ` · updated ${shortAge(rule.maintained_at)} ago` : ""}
                          {rule.is_draft && (
                            <Chip size="sm" tone="quiet">
                              draft
                            </Chip>
                          )}
                        </span>
                        <span className={styles.candidateWhy}>
                          {tierNote(rule)}
                          {rule.scope === "threat" ? ` · names ${label}` : ""}
                          {rule.confidence === "low" && (
                            <Chip size="sm" tone="quiet" tint="var(--severity-medium, #d29922)">
                              partial match
                            </Chip>
                          )}
                        </span>
                      </span>
                      <span className={styles.candidateActions}>
                        <button
                          type="button"
                          className={`${styles.btn} ${rule.tier ? styles.btnPrimary : ""}`}
                          onClick={() => addItem("adopt", rule, behaviour.technique_id)}
                        >
                          Adopt
                        </button>
                        <button
                          type="button"
                          className={styles.btn}
                          disabled={extending !== null}
                          onClick={() => extendRule(rule)}
                        >
                          {extending === rule.rule_id ? "Extending…" : "Extend"}
                        </button>
                        <button type="button" className={styles.btnQuiet} onClick={() => onNavigateRule(rule.rule_id)}>
                          Open
                        </button>
                        <button
                          type="button"
                          className={styles.btnQuiet}
                          title="Saved with the set. Exports list skipped rules as known gaps."
                          onClick={() =>
                            addItem(
                              "skip",
                              rule,
                              behaviour.technique_id,
                              rule.tier ? "not needed" : "cannot fire here"
                            )
                          }
                        >
                          Skip
                        </button>
                      </span>
                    </div>
                  ))}
                  {hidden > 0 && (
                    <div className={styles.candidateRest}>
                      <span className={styles.mono}>{hidden}</span> more tagged {behaviour.technique_id}
                      {rules?.threat_scope === 0 ? `, none naming ${label}` : ""}
                      <button
                        type="button"
                        className={styles.linkBtn}
                        onClick={() => setShowAllCandidates((v) => !v)}
                      >
                        {showAllCandidates ? "show fewer" : `show all ${rules?.total_candidates ?? 0}`}
                      </button>
                    </div>
                  )}
                </div>
              )}

              <button type="button" className={styles.btn} onClick={() => draftNew(behaviour.technique_id)}>
                Draft a {label} rule for {behaviour.technique_id}
              </button>
            </LadderRow>
          );
        })}
        {ladder.length > shown && (
          <button type="button" className={styles.moreBtn} onClick={() => setShown((n) => n + LADDER_PAGE)}>
            Show {Math.min(LADDER_PAGE, ladder.length - shown)} more of {ladder.length}
          </button>
        )}
      </div>

      {belowLine.length > 0 && (
        <details className={styles.fold}>
          <summary>
            <span className={`${styles.foldCaret} caret-glyph`} aria-hidden="true" />
            <Chip size="sm" tone="quiet">
              {belowLine.length}
            </Chip>
            <b>No log source</b>: no matching source in your inventory
          </summary>
          <div className={styles.foldBody}>
            <p>
              {belowLine.length === 1 ? "This behavior has" : "These behaviors have"} no{" "}
              {data.missing_categories.map(humanCategory).join(" or ") || "matching"} source ticked, so a rule for{" "}
              {belowLine.length === 1 ? "it" : "them"} could not fire here. That is a collection job, not a detection
              gap.
            </p>
            <div className={styles.mini}>
              {belowLine.map((b) => (
                <button
                  key={b.technique_id}
                  type="button"
                  className={styles.miniItem}
                  title={b.missing_channels.join(", ")}
                  onClick={() => toggleRow(b.technique_id)}
                >
                  {b.technique_id} · {b.technique_name}
                  {b.prior_rules > 0 && ` · ${b.prior_rules} rules exist, none can fire`}
                </button>
              ))}
            </div>
          </div>
        </details>
      )}

      {articleTotal > 0 && (
        <details className={styles.fold}>
          <summary>
            <span className={`${styles.foldCaret} caret-glyph`} aria-hidden="true" />
            <Chip size="sm" tone="quiet">
              {articleTotal}
            </Chip>
            <b>Source articles</b>: {contributed} carried a technique
          </summary>
          <div className={styles.foldBody}>
            <p>
              {contributed} of {articleTotal} {articleTotal === 1 ? "article" : "articles"} {windowPhrase(window)}{" "}
              carried a technique. The rest are recaps and leak-site notices with no techniques. They are counted,
              not listed.
            </p>
            <div className={styles.articles}>
              {(data.articles ?? [])
                .filter((a) => a.contributed)
                .slice(0, 12)
                .map((article) => (
                  <button
                    key={article.entry_id}
                    type="button"
                    className={styles.article}
                    title="Open in the reader"
                    onClick={() => onOpenArticle(article.entry_id)}
                  >
                    <span className={styles.articleDate}>{formatDate(article.published_at)}</span>
                    <span className={styles.articleTitle}>{article.title}</span>
                    <span className={styles.articleMeta}>
                      {article.source} · {article.technique_count}{" "}
                      {article.technique_count === 1 ? "technique" : "techniques"}
                      {article.new_technique_count > 0 ? ` · ${article.new_technique_count} new` : ""}
                    </span>
                  </button>
                ))}
            </div>
          </div>
        </details>
      )}

      {(sets?.items.length ?? 0) > 0 && (
        <details className={styles.fold}>
          <summary>
            <span className={`${styles.foldCaret} caret-glyph`} aria-hidden="true" />
            <Chip size="sm" tone="quiet">
              {sets?.items.length}
            </Chip>
            <b>Saved sets</b>
          </summary>
          <div className={styles.foldBody}>
            {sets?.items.map((saved) => (
              <div key={saved.id} className={styles.savedRow}>
                <Chip size="sm" tone="quiet">
                  {saved.item_count}
                </Chip>
                <span className={styles.savedTitle}>{saved.title}</span>
                {saved.upstream_moved.length > 0 && (
                  <Chip
                    size="sm"
                    tone="toned"
                    tint="var(--warning, #d29922)"
                    title={`${saved.upstream_moved.length} adopted rule${
                      saved.upstream_moved.length === 1 ? "" : "s"
                    } changed upstream since this set was saved. Review them.`}
                  >
                    upstream moved
                  </Chip>
                )}
                <button type="button" className={styles.linkBtn} onClick={() => loadSaved(saved.id)}>
                  open
                </button>
                <button
                  type="button"
                  className={styles.linkBtn}
                  onClick={() =>
                    deleteSet.mutate(saved.id, {
                      onSuccess: () => {
                        if (summaryId === saved.id) setSummaryId(null);
                      },
                    })
                  }
                >
                  delete
                </button>
              </div>
            ))}
          </div>
        </details>
      )}

      <div className={styles.tray}>
        <span className={styles.trayLabel}>Set</span>
        <div className={styles.trayItems}>
          {items.length === 0 ? (
            <span className={styles.trayEmpty}>Empty. Adopt, extend or draft a rule from a technique to start one.</span>
          ) : (
            items.map((item, index) => (
              <span key={`${item.op}-${item.rule_id ?? item.technique_id}-${index}`} className={styles.trayChip}>
                <span className={styles.trayOp} style={{ color: OP_TINT[item.op] }}>
                  {item.op}
                </span>
                <span className={item.op === "skip" ? styles.trayTitleSkipped : undefined}>{item.title}</span>
                <span className={styles.trayMeta}>
                  {item.rule_type || "draft"}
                  {item.repo ? ` · ${item.repo}` : ""}
                  {item.license ? ` · ${item.license}` : ""}
                </span>
                <button
                  type="button"
                  className={styles.trayRemove}
                  aria-label={`Remove ${item.title}`}
                  onClick={() => setItems((prev) => prev.filter((_, i) => i !== index))}
                >
                  ×
                </button>
              </span>
            ))
          )}
        </div>
        <button
          type="button"
          className={`${styles.btn} ${styles.btnPrimary}`}
          onClick={handleSave}
          disabled={items.length === 0 || saveSet.isPending}
        >
          {saveSet.isPending ? "Saving…" : summaryId ? "Update set" : "Save set"}
        </button>
        <button type="button" className={styles.btn} onClick={handleExportZip}>
          Bundle .zip
        </button>
        <button type="button" className={styles.btn} onClick={sendToReport} disabled={items.length === 0}>
          Send to report
        </button>
      </div>
    </div>
  );
}
