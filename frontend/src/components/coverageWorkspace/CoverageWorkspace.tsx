/**
 * Coverage Workspace — the Detection tab, as one answer and one list.
 *
 * The question a profile's Detection tab exists to answer is "am I covered for
 * this threat?". The previous layout rendered the inputs to that question in
 * three columns — articles, behaviours, candidate rules — and never stated the
 * answer. This states it first, in a sentence computed from the same fields the
 * ribbon under it uses, so the two cannot disagree.
 *
 * Everything else is one ladder of behaviours ordered by what you would do next.
 * A row opens onto its own evidence, its own candidates and its own actions;
 * nothing sits in a parallel column waiting to be correlated by eye. Articles
 * and the behaviours with no log source are provenance, so they fold away.
 *
 * The rule the UI still has to keep: a behaviour whose required channels match
 * nothing in the telemetry inventory is a sourcing item, never a detection gap.
 * A rule for it would not fire, so it cannot be counted as something you failed
 * to write.
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
  useBehaviourRules,
  useCoverageWorkspace,
  useDeleteCoverageSet,
  useSaveCoverageSet,
  useSavedSets,
  type CoverageWorkspace as WorkspaceData,
  type PriorRuleItem,
  type SetItem,
  type SetOp,
  type WorkspaceBehaviour,
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

/** sessionStorage keys for the bench handoff. The seed rides out with the
    navigation; the return rides back after a save. Working state, not truth —
    the set itself persists through the sets endpoint. */
const BENCH_SEED_KEY = "intelfeed-bench-seed";
const BENCH_RETURN_KEY = "intelfeed-bench-return";

/** entity_ids buckets the report generator reads. A campaign has no bucket, so
    its set attaches the articles and the rules without the entity itself. */
const ENTITY_ID_BUCKETS: Record<string, string> = {
  threat_actor: "actors",
  malware: "malware",
  cve: "cves",
  ttp: "ttps",
};

/** An all-time ladder on a long-lived actor runs to 200 rows. The ordering
    already puts the work at the top, so the tail is paged rather than rendered. */
const LADDER_PAGE = 40;

/** Candidates shown inside an open row before the rest collapse to one line.
    The ranking is only as good as the signals behind it, so this stays small:
    three rows you are expected to read, not a page to scroll. */
const CANDIDATES_SHOWN = 3;

type VerdictKey = "ok" | "warn" | "bad" | "inert";

interface Verdict {
  key: VerdictKey;
  /** Right-edge label — the verdict in words, before anything is opened. */
  label: string;
  color: string;
}

/** What you would do about this behaviour, from stored fields only.
 *
 * Order matters: the below-line test comes first because it outranks every
 * other reading. A behaviour with 46 candidate rules and no log source is not
 * "well covered" — none of those rules can fire here.
 *
 * The test is `tier` alone, deliberately. `tier` is the STRONGEST match any of
 * the technique's channels reached, and a technique lists every data source
 * ATT&CK knows of — no real inventory carries all of them, so `missing_channels`
 * is non-empty for essentially every behaviour. Folding it in collapsed the
 * adoptable bucket to zero on every entity we tried. Partial coverage of a
 * technique's channels is the normal case, not a caveat. */
function verdictFor(b: WorkspaceBehaviour): Verdict {
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
  if (!rule.tier) return "no matching source — cannot fire here";
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
      {total === 1 ? "behaviour" : "behaviours"} {windowPhrase(data.window)} could fire against your telemetry.
      {counts.inert > 0 && (
        <>
          {" "}
          <b className={styles.numInert}>{counts.inert}</b> {counts.inert === 1 ? "cannot" : "cannot"} — you collect
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

/** One behaviour: the verdict on the closed row, everything else inside it. */
function LadderRow({
  behaviour,
  open,
  onToggle,
  children,
}: {
  behaviour: WorkspaceBehaviour;
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

  // Articles open in the workbench's docked reader — the tab stays put and acts
  // as the entry list, the way the rest of the app pairs a list with the reader.
  const onOpenArticle = (entryId: string) => {
    useIntelStore.getState().openWorkbenchReader(entryId);
  };

  // A skip is a set item, not component state — it survives remounts and
  // exports as a known gap. Skipped rules disappear from the candidate list.
  const skipped = useMemo(
    () => items.filter((i) => i.op === "skip" && i.rule_id).map((i) => i.rule_id as string),
    [items]
  );

  // Returning from the bench: a rule drafted or extended over there joins the
  // set here, exactly once.
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
  // Only the open row fetches candidates: one query for the row you are reading
  // instead of a standing query for a column nobody asked about.
  const { data: rules, isLoading: rulesLoading } = useBehaviourRules(entityType, entityKey, openId);
  const saveSet = useSaveCoverageSet(entityType, entityKey);
  const deleteSet = useDeleteCoverageSet(entityType, entityKey);

  const behaviours = useMemo(() => data?.behaviours ?? [], [data]);

  // Ordered by what you would do next, not by technique number. Inside a
  // verdict, the behaviour the window reported most leads.
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

  /** Stash the behaviour's evidence for the bench: technique, quotes with their
      typed observables, and the entity link to attach on save. */
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

  /** Draft new: land in the bench, loaded — technique, quotes as a cited
      header, format from the telemetry tier. Saving returns here with the rule
      joining the set. */
  const draftNew = (techniqueId: string | null) => {
    stashSeed(techniqueId);
    const params = new URLSearchParams({ from_set: "1", entity_type: entityType, entity_key: entityKey });
    if (techniqueId) params.set("technique", techniqueId);
    navigate(`/workbench/rule/new?${params.toString()}`);
  };

  const [extending, setExtending] = useState<string | null>(null);
  /** Extend: create the derived_from draft child server-side, record the item,
      open the bench on the child with the upstream beside it. */
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
        title: `${label} — ${window}`,
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
      toast.info("Save the set first — export reads the stored set");
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

  /** The ruleset: one file per rule grouped by format, attribution headers,
      the research report as MANIFEST.md. */
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

  /** Send to report — the one way into the reporting system, the same modal
      every other surface opens.

      The set carries three things: the articles the behaviours were read from,
      the entity itself, and the adopted rules, which land as a Detections
      section with repo and licence intact. The skips ride along as the section
      body, because a gap you decided not to close is a finding too.

      This replaced a markdown download and a clipboard copy. Both produced
      something that looked like a report and was not one — neither ever reached
      an IntelReport you could version, publish or send. */
  const sendToReport = () => {
    const adopted = items.filter((i) => i.op !== "skip" && i.rule_id).map((i) => i.rule_id as string);
    const skipped = items.filter((i) => i.op === "skip");
    const bucket = ENTITY_ID_BUCKETS[entityType];

    const entityIds: Record<string, string[]> = {};
    if (adopted.length > 0) entityIds.detection_rules = adopted;
    if (bucket) entityIds[bucket] = [entityKey];

    const gaps = skipped.length
      ? `Known gaps — ${skipped.length} rule${skipped.length === 1 ? "" : "s"} considered and not adopted:\n\n` +
        skipped.map((i) => `- ${i.title}${i.reason ? ` — ${i.reason}` : ""}`).join("\n")
      : undefined;

    const entryIds = (data?.articles ?? []).filter((a) => a.contributed).map((a) => a.entry_id);

    useUIStore.getState().openSendToReport({
      entryIds,
      entityIds: Object.keys(entityIds).length > 0 ? entityIds : undefined,
      note: gaps,
      label: `${label} — ${adopted.length} rule${adopted.length === 1 ? "" : "s"}`,
      // The wizard is entry-seeded and carries no entity evidence, so a set
      // started this way arrives without its rules; sending again once the
      // draft exists attaches them. Offered anyway because without it the modal
      // is a dead end for anyone with no open drafts.
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

  if (isLoading) return <AsyncStateLoading label="Reading coverage" />;
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
                  {counts.ok} adoptable today
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
                  {counts.bad} nothing in the library
                </span>
              )}
              {counts.inert > 0 && (
                <span>
                  <i style={{ background: "var(--text-muted)" }} />
                  {counts.inert} no log source — a collection job
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
          ordered by what to do next
          {belowLine.length > 0 && ` · ${belowLine.length} held below`}
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
                  No sentence was captured for {behaviour.technique_id} — it was carried by a tag, not by prose.
                </div>
              )}

              {rulesLoading && <AsyncStateLoading label="Reading the library" />}

              {!rulesLoading && candidates.length === 0 && (
                <div className={styles.evidenceNone}>
                  Nothing in the library resolves to this behaviour — this is one to write.
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
                              weak match
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
                          title="Persisted with the set — exports render skips as known gaps"
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
            <b>Below the line</b> — no matching source in your inventory
          </summary>
          <div className={styles.foldBody}>
            <p>
              {belowLine.length === 1 ? "This behaviour has" : "These behaviours have"} no{" "}
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
            <b>Where this came from</b> — {contributed} carried a technique
          </summary>
          <div className={styles.foldBody}>
            <p>
              {contributed} of {articleTotal} {articleTotal === 1 ? "article" : "articles"} {windowPhrase(window)}{" "}
              carried a technique. The rest are recaps and leak-site notices — real activity, no tradecraft. They are
              counted, not listed.
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
                    } changed upstream since this set was saved — worth a re-read`}
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
            <span className={styles.trayEmpty}>Empty — adopt, extend or draft from a behaviour to start one.</span>
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
