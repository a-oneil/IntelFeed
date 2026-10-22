/**
 * ProposalsQueue — the Engine console's Review tab: everything the AI wants a
 * person to approve, in one queue over both proposal logs. The adjudicate
 * stage's verdicts and the on-demand scans' suggestions land here with a
 * Domain facet (what applying them changes: links, entities, relationships,
 * observables), an Origin facet (who proposed it), inline Apply / Dismiss,
 * one background Apply all, and a History lens of everything that ran
 * (with Restore).
 */

import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

import api from "@/api/client";
import {
  PROPOSAL_DOMAINS,
  invalidateAfterBulkApply,
  useBulkApplyProgress,
  useDismissProposals,
  useHygieneFeed,
  useHygieneStats,
  useRunNameNormalization,
  useScanAliasHygiene,
  useScanIdHygiene,
  useScanVendorAutolink,
  useStartBulkApply,
  type FeedLink,
  type FeedRow,
  type ProposalDomain,
} from "@/hooks/useHygiene";
import { useHygieneRowAction } from "@/hooks/useHygieneRowAction";
import { formatDateTime } from "@/utils/formatDate";
import { getEntityCssVar, getEntityLabel } from "@/utils/entityTheme";
import { useQueryClient } from "@tanstack/react-query";

import styles from "./ProposalsQueue.module.css";
import { confirmDialog } from "@/utils/dialog";

export type ReviewLens = "queue" | "history";
export type ProposalOrigin = "adjudicator" | "legacy";

const CHANGE_META: Record<string, { label: string; cls: string }> = {
  // pending proposals
  shadow_remove: { label: "Remove link", cls: styles.tRemove },
  needs_reclassification: { label: "Reclassify", cls: styles.tRecl },
  vendor_autolink: { label: "Vendor link", cls: styles.tVlink },
  normalize_name: { label: "Name fix", cls: styles.tName },
  alias_collision: { label: "Alias trim", cls: styles.tName },
  ttp_malformed_id: { label: "ID fix", cls: styles.tName },
  cve_malformed_id: { label: "ID fix", cls: styles.tName },
  cve_withdrawn: { label: "CVE withdrawn", cls: styles.tRemove },
  // adjudicate stage (post-analysis review)
  adjudication_veto: { label: "Veto entity", cls: styles.tRemove },
  adjudication_merge: { label: "Merge", cls: styles.tMerge },
  adjudication_unlink: { label: "Unlink", cls: styles.tRemove },
  adjudication_reclassify: { label: "Reclassify (review)", cls: styles.tRecl },
  adjudication_edge_demote: { label: "Demote edge", cls: styles.tRecl },
  adjudication_ioc_drop: { label: "Drop observable", cls: styles.tRecl },
  adjudication_assessment: { label: "Assessment", cls: styles.tStale },
  adjudication_restored: { label: "Verdict restored", cls: styles.tVlink },
  // applied history
  removed: { label: "Link removed", cls: styles.tRemove },
  restored: { label: "Link restored", cls: styles.tVlink },
  merge: { label: "Merged", cls: styles.tMerge },
  reclassify: { label: "Reclassified", cls: styles.tRecl },
  orphan_prune: { label: "Orphan pruned", cls: styles.tName },
  update_description: { label: "Profile update", cls: styles.tName },
  update_aliases: { label: "Alias update", cls: styles.tName },
  ai_enrich_filled: { label: "AI enriched", cls: styles.tVlink },
  ai_enrich_unknown: { label: "AI unknown", cls: styles.tName },
  no_op: { label: "No change", cls: styles.tName },
};

const DOMAIN_LABELS: Record<ProposalDomain, string> = {
  links: "Links",
  entities: "Entities",
  relationships: "Relationships",
  observables: "Observables",
};

// Action filter: one dropdown over both logs. Values may be comma-lists —
// the backend feed matches any of the listed action codes.
const QUEUE_FILTERS = [
  { value: "", label: "Any change" },
  { value: "adjudication_unlink,shadow_remove", label: "Unlink / remove link" },
  { value: "adjudication_edge_demote", label: "Demote edge" },
  { value: "needs_reclassification,adjudication_reclassify", label: "Reclassify" },
  { value: "adjudication_veto", label: "Veto entity" },
  { value: "adjudication_merge", label: "Merge" },
  { value: "adjudication_ioc_drop", label: "Drop observable" },
  { value: "normalize_name", label: "Name fix" },
  { value: "alias_collision", label: "Alias trim" },
  { value: "vendor_autolink", label: "Vendor link" },
  { value: "ttp_malformed_id,cve_malformed_id,cve_withdrawn", label: "ID fix" },
];
const HISTORY_FILTERS = [
  { value: "", label: "Any change" },
  { value: "removed", label: "Link removed" },
  { value: "restored", label: "Link restored" },
  { value: "merge", label: "Merged" },
  { value: "reclassify", label: "Reclassified" },
  { value: "orphan_prune", label: "Orphans pruned" },
  { value: "update_description,update_aliases", label: "Profile" },
  { value: "ai_enrich_filled,ai_enrich_unknown", label: "AI enrich" },
  { value: "adjudication_restored", label: "Verdict restored" },
];
type OriginFacet = "" | ProposalOrigin | "orphaned";
const ORIGINS: { value: OriginFacet; label: string; title: string; queueOnly?: boolean }[] = [
  { value: "", label: "All", title: "Every proposal" },
  { value: "adjudicator", label: "Adjudicator", title: "Filed by the post-analysis review, with the article in hand" },
  { value: "legacy", label: "Scans", title: "Filed by the on-demand scans and the retired nightly jobs" },
  {
    value: "orphaned",
    label: "Orphaned",
    title: "Legacy proposals no entry can carry to the adjudicate stage — yours to dismiss or apply by hand",
    queueOnly: true,
  },
];
const ORPHANED_NOTE =
  "Left by the retired jobs with no entry to re-judge them against. Dismiss or apply by hand; nothing automatic touches them.";

// Row-action code → button label + tone.
const ACTION_BTN: Record<string, { label: string; cls: string }> = {
  apply: { label: "Apply", cls: styles.bGood },
  apply_reclassify: { label: "Apply", cls: styles.bGood },
  promote_to_remove: { label: "Remove", cls: styles.bWarn },
  restore: { label: "Restore", cls: styles.bWarn },
  dismiss: { label: "Dismiss", cls: styles.bGhost },
};
const ACTION_ORDER = ["apply", "apply_reclassify", "promote_to_remove", "restore", "dismiss"];

/** Pending proposals only — exclude applied history (restore-only / no-action rows). */
function isPending(row: FeedRow): boolean {
  return row.actions.some((a) => a === "apply" || a === "apply_reclassify" || a === "promote_to_remove" || a === "dismiss");
}

function feedLinkHref(link: FeedLink): string | null {
  if (link.kind === "entry") return typeof link.entity_id === "string" ? `/?entry=${link.entity_id}` : null;
  if (link.kind === "external") return typeof link.entity_id === "string" ? link.entity_id : null;
  const slug = link.entity_type;
  return slug && link.entity_id ? `/workbench/${slug}/${link.entity_id}` : null;
}

export function ProposalsQueue({
  lens,
  initialAction,
  initialOrigin,
  initialDomain,
}: {
  /** queue: pending proposals with Apply / Dismiss. history: what ran, with Restore. */
  lens: ReviewLens;
  initialAction?: string;
  initialOrigin?: ProposalOrigin;
  initialDomain?: ProposalDomain;
}) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const hist = lens === "history";
  const [actionFilter, setActionFilter] = useState(initialAction ?? "");
  const [originFilter, setOriginFilter] = useState<OriginFacet>(initialOrigin ?? "");
  const [domainFilter, setDomainFilter] = useState<ProposalDomain | "">(initialDomain ?? "");
  const [modePending, setModePending] = useState(false);
  const [busyRow, setBusyRow] = useState<string | null>(null);

  // "Orphaned" is its own feed switch, not an origin value.
  const orphaned = !hist && originFilter === "orphaned";
  const origin = orphaned || !originFilter ? undefined : (originFilter as ProposalOrigin);
  const domain = domainFilter || undefined;
  const stats = useHygieneStats();
  const feed = useHygieneFeed(
    hist
      ? { mode: "apply", action: actionFilter || undefined, origin, domain, limit: 100 }
      : {
          pending: true,
          action: actionFilter || undefined,
          origin,
          domain,
          orphaned: orphaned || undefined,
          limit: 100,
        },
  );

  const runRowAction = useHygieneRowAction();
  const dismissProposals = useDismissProposals();
  // "Apply all" runs in the background: start a job, poll it, then refresh.
  const startBulkApply = useStartBulkApply();
  const [bulkJobId, setBulkJobId] = useState<string | null>(null);
  const { data: bulkProgress } = useBulkApplyProgress(bulkJobId);
  const bulkRunning =
    startBulkApply.isPending || (!!bulkJobId && bulkProgress?.status !== "done" && bulkProgress?.status !== "error");
  useEffect(() => {
    if (!bulkJobId || !bulkProgress) return;
    if (bulkProgress.status === "done") {
      const errs = bulkProgress.error_count;
      const msg = `Applied ${bulkProgress.applied.toLocaleString()}, skipped ${bulkProgress.skipped.toLocaleString()}${
        errs ? `, ${errs.toLocaleString()} error${errs === 1 ? "" : "s"}` : ""
      }`;
      if (errs) toast.warning(msg, { description: bulkProgress.errors[0]?.error });
      else toast.success(msg);
      invalidateAfterBulkApply(qc);
      setBulkJobId(null);
    } else if (bulkProgress.status === "error") {
      toast.error(`Apply all stopped: ${bulkProgress.message ?? "unknown error"}`);
      invalidateAfterBulkApply(qc);
      setBulkJobId(null);
    }
  }, [bulkJobId, bulkProgress, qc]);
  // While a job runs, keep the table moving with it.
  useEffect(() => {
    if (bulkJobId && bulkProgress?.status === "running") feed.refetch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bulkProgress?.processed]);

  const scanNames = useRunNameNormalization();
  const scanAliases = useScanAliasHygiene();
  const scanIds = useScanIdHygiene();
  const scanVendors = useScanVendorAutolink();

  // Scans that mint fresh entity proposals into the queue (link verdicts
  // come from the adjudicate stage at ingest, so there is nothing to scan for).
  const scans =
    hist || (domainFilter && domainFilter !== "entities")
      ? []
      : [
          {
            label: "Propose name fixes",
            busy: scanNames.isPending,
            run: () =>
              scanNames
                .mutateAsync({})
                .then((r) => toast.success(`Proposed ${r.proposed ?? 0} name fixes`))
                .catch((e) => toast.error(`Scan failed: ${(e as Error).message}`)),
          },
          {
            label: "Scan aliases",
            busy: scanAliases.isPending,
            run: () =>
              scanAliases
                .mutateAsync()
                .then((r) => toast.success(`Proposed ${r.proposed ?? 0} alias trims`))
                .catch((e) => toast.error(`Scan failed: ${(e as Error).message}`)),
          },
          {
            label: "Auto-link vendors",
            busy: scanVendors.isPending,
            run: () =>
              scanVendors
                .mutateAsync()
                .then((r) => toast.success(`Proposed ${r.proposed ?? 0} vendor links`))
                .catch((e) => toast.error(`Scan failed: ${(e as Error).message}`)),
          },
          {
            label: "Scan TTP/CVE ids",
            busy: scanIds.isPending,
            run: () =>
              scanIds
                .mutateAsync()
                .then((r) => toast.success(`Proposed ${r.ttp_malformed + r.cve_malformed + r.cve_withdrawn} id fixes`))
                .catch((e) => toast.error(`Scan failed: ${(e as Error).message}`)),
          },
        ];

  const rows = useMemo(() => {
    const all = feed.data?.rows ?? [];
    return hist ? all : all.filter(isPending);
  }, [feed.data, hist]);

  // The Proposed / Applied switch is the adjudicate stage's mode: shadow files
  // proposals, apply acts on high-confidence verdicts at ingest.
  const statsField = "adjudication_mode";
  const mode: "off" | "shadow" | "apply" =
    stats.data?.adjudication_mode === "apply" ? "apply" : stats.data?.adjudication_mode === "shadow" ? "shadow" : "off";
  const modeKey = "adjudication_mode";
  const setMode = async (next: "shadow" | "apply") => {
    if (next === mode || modePending) return;
    setModePending(true);
    // Optimistically patch cached stats and DON'T refetch them right away — the
    // per-worker settings cache can return the stale value for a moment, which
    // would otherwise snap the toggle back and read as "the button does nothing".
    qc.setQueryData(["hygiene", "stats"], (prev: unknown) =>
      prev && typeof prev === "object" ? { ...(prev as Record<string, unknown>), [statsField]: next } : prev,
    );
    try {
      await api.patch("/system-settings", { settings: { [modeKey]: next } });
      toast.success(
        next === "apply"
          ? "Applied mode — the review now applies high-confidence verdicts at ingest"
          : "Proposed mode — verdicts filed as suggestions for review",
      );
    } catch (e) {
      qc.setQueryData(["hygiene", "stats"], (prev: unknown) =>
        prev && typeof prev === "object" ? { ...(prev as Record<string, unknown>), [statsField]: mode } : prev,
      );
      toast.error(`Failed to change mode: ${(e as Error).message}`);
    } finally {
      setModePending(false);
    }
  };

  const FILTERS = hist ? HISTORY_FILTERS : QUEUE_FILTERS;
  const scopeLabel = () => {
    const what = actionFilter
      ? (FILTERS.find((f) => f.value === actionFilter)?.label ?? "these").toLowerCase()
      : "every pending";
    const where = domainFilter ? ` ${DOMAIN_LABELS[domainFilter].toLowerCase()}` : "";
    const who = origin === "adjudicator" ? " adjudicator" : origin === "legacy" ? " scan" : "";
    return `${what}${who}${where}`;
  };

  const doRow = async (row: FeedRow, action: string) => {
    setBusyRow(row.id);
    try {
      await runRowAction(row, action);
    } finally {
      setBusyRow(null);
    }
  };

  // Scoped to what the table shows: the action filter, the origin and the domain.
  const clearAll = async () => {
    if (
      !(await confirmDialog({
        title: "Dismiss proposals",
        message: `Dismiss ${scopeLabel()} proposals without applying them? The suggestions are deleted; entities and links are untouched.`,
        confirmLabel: "Dismiss",
        destructive: true,
      }))
    )
      return;
    try {
      const r = await dismissProposals.mutateAsync({ action: actionFilter || undefined, origin, domain });
      toast.success(`Dismissed ${r.dismissed} proposal${r.dismissed === 1 ? "" : "s"}`);
    } catch (e) {
      toast.error(`Dismiss failed: ${(e as Error).message}`);
    }
  };

  // Every pending proposal the table shows, through the same code the per-row
  // Apply uses, as a background job. The adjudicator's rows go first, then the
  // scans' reclassify advisories when the filters allow them.
  const applyAll = async () => {
    if (
      !(await confirmDialog({
        title: "Apply proposals",
        message: `Apply ${scopeLabel()} proposals now? Each one is applied the way the stage would in apply mode, and each stays undoable from History. This runs in the background; the queue updates as it goes.`,
        confirmLabel: "Apply all",
        destructive: true,
      }))
    )
      return;
    try {
      const job = await startBulkApply.mutateAsync({
        kind: origin === "adjudicator" ? "adjudication" : "all",
        action: actionFilter || undefined,
        domain,
      });
      setBulkJobId(job.job_id);
      toast.info(`Applying ${job.total.toLocaleString()} proposal${job.total === 1 ? "" : "s"} in the background`);
    } catch (e) {
      toast.error(`Apply failed: ${(e as Error).message}`);
    }
  };

  const bulkLabel = bulkRunning
    ? bulkProgress && bulkProgress.total > 0
      ? `Applying ${bulkProgress.processed.toLocaleString()} / ${bulkProgress.total.toLocaleString()}…`
      : "Applying…"
    : "Apply all";
  const byDomain = stats.data?.pending_by_domain ?? {};

  return (
    <div className={styles.wrap}>
      {/* toolbar */}
      <div className={styles.toolbar}>
        <span className={styles.system}>Adjudicator</span>
        <div
          className={styles.modeSeg}
          title={
            mode === "off"
              ? "The adjudicate stage is off — pick a mode here, or turn it on from the Adjudicate stage panel (Engine → Entries → adjudicate column)"
              : "Proposed: the review files suggestions · Applied: high-confidence verdicts applied at ingest"
          }
        >
          <button className={mode === "shadow" ? styles.modeOn : ""} disabled={modePending} onClick={() => setMode("shadow")}>
            Proposed
          </button>
          <button className={mode === "apply" ? styles.modeOn : ""} disabled={modePending} onClick={() => setMode("apply")}>
            Applied
          </button>
        </div>

        <span className={styles.facetLabel}>Domain</span>
        <div className={styles.seg} title="What applying the proposal changes">
          <button className={domainFilter === "" ? styles.segOn : ""} onClick={() => setDomainFilter("")}>
            All
          </button>
          {PROPOSAL_DOMAINS.map((d) => (
            <button key={d} className={domainFilter === d ? styles.segOn : ""} onClick={() => setDomainFilter(d)}>
              {DOMAIN_LABELS[d]}
              {!hist && byDomain[d] ? <span className={styles.segCnt}>{byDomain[d]?.toLocaleString()}</span> : null}
            </button>
          ))}
        </div>

        <span className={styles.facetLabel}>Origin</span>
        <div className={styles.seg} title="Who proposed it">
          {ORIGINS.filter((o) => !hist || !o.queueOnly).map((o) => (
            <button
              key={o.value || "all"}
              className={originFilter === o.value ? styles.segOn : ""}
              title={o.title}
              onClick={() => setOriginFilter(o.value)}
            >
              {o.label}
            </button>
          ))}
        </div>

        <label className={styles.facetLabel}>
          Action
          <select className={styles.sel} value={actionFilter} onChange={(e) => setActionFilter(e.target.value)}>
            {FILTERS.map((f) => (
              <option key={f.value || "all"} value={f.value}>
                {f.label}
              </option>
            ))}
          </select>
        </label>

        <span className={styles.grow} />

        {!hist && !orphaned && (
          <>
            <button
              className={styles.btn}
              disabled={bulkRunning || rows.length === 0}
              title="Apply every proposal the table shows, in the background, through the same code the per-row Apply uses"
              onClick={applyAll}
            >
              {bulkLabel}
            </button>
            <button className={styles.btnDanger} disabled={dismissProposals.isPending || bulkRunning} onClick={clearAll}>
              {dismissProposals.isPending ? "Clearing…" : "Dismiss all"}
            </button>
          </>
        )}
      </div>

      {orphaned && <p className={styles.note}>{ORPHANED_NOTE}</p>}

      {/* table */}
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>{hist ? "Change" : "Proposed change"}</th>
              <th>Domain</th>
              <th>Entity</th>
              <th>Detail</th>
              <th>When</th>
              <th className={styles.actCol} />
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const meta = CHANGE_META[row.action] ?? { label: row.action, cls: styles.tName };
              const slug = row.entity_type;
              const acts = [...row.actions].sort((a, b) => ACTION_ORDER.indexOf(a) - ACTION_ORDER.indexOf(b));
              const extraLinks = (row.links ?? []).filter((l) => l.kind !== "entity");
              return (
                <tr key={row.id}>
                  <td>
                    <span className={`${styles.tag} ${meta.cls}`}>{meta.label}</span>
                    {row.origin === "adjudicator" && (
                      <span className={styles.originTag} title="Filed by the post-analysis review, with the article in hand">
                        adjudicator
                      </span>
                    )}
                  </td>
                  <td className={styles.muted}>{DOMAIN_LABELS[row.domain] ?? row.domain}</td>
                  <td>
                    {row.entity_name ? (
                      <button
                        className={styles.ent}
                        disabled={!slug || !row.entity_id}
                        onClick={() => slug && row.entity_id && navigate(`/workbench/${slug}/${row.entity_id}`)}
                        title={row.entity_type ? getEntityLabel(row.entity_type) : ""}
                      >
                        <span className={styles.entDot} style={{ background: row.entity_type ? getEntityCssVar(row.entity_type) : "var(--border)" }} />
                        {row.entity_name}
                      </button>
                    ) : (
                      <span className={styles.muted}>—</span>
                    )}
                  </td>
                  <td className={styles.detail}>
                    <span className={styles.subject}>{row.subject ?? "—"}</span>
                    {row.reason && <span className={styles.reason}>{row.reason}</span>}
                    {extraLinks.length > 0 && (
                      <span className={styles.linkChips}>
                        {extraLinks.map((l, i) => {
                          const href = feedLinkHref(l);
                          if (!href) return null;
                          const external = l.kind === "external";
                          return (
                            <a
                              key={`${l.kind}-${i}`}
                              className={styles.linkChip}
                              href={href}
                              target={external ? "_blank" : undefined}
                              rel={external ? "noopener noreferrer" : undefined}
                            >
                              {l.role ? `${l.role}: ` : ""}
                              {l.label}
                            </a>
                          );
                        })}
                      </span>
                    )}
                  </td>
                  <td className={styles.when}>{formatDateTime(row.when)}</td>
                  <td>
                    <div className={styles.acts}>
                      {acts.map((a) => {
                        const b = ACTION_BTN[a];
                        if (!b) return null;
                        return (
                          <button key={a} className={`${styles.rowBtn} ${b.cls}`} disabled={busyRow === row.id} onClick={() => doRow(row, a)}>
                            {b.label}
                          </button>
                        );
                      })}
                    </div>
                  </td>
                </tr>
              );
            })}
            {!feed.isLoading && rows.length === 0 && (
              <tr>
                <td colSpan={6} className={styles.empty}>
                  {hist
                    ? "No applied changes match — nothing has run yet."
                    : orphaned
                      ? "No orphaned proposals — every pending legacy proposal has an entry the stage can re-judge it against."
                      : `No pending proposals match — nothing waiting for review.${scans.length ? " Run a scan below to generate some." : ""}`}
                </td>
              </tr>
            )}
            {feed.isLoading && (
              <tr>
                <td colSpan={6} className={styles.empty}>
                  Loading {hist ? "history" : "proposals"}…
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* scans that generate proposals into this queue */}
      {scans.length > 0 && (
        <div className={styles.genRow}>
          <span className={styles.genLabel}>Generate proposals</span>
          {scans.map((s) => (
            <button key={s.label} className={styles.genBtn} disabled={s.busy} onClick={s.run}>
              {s.busy ? "Scanning…" : s.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
