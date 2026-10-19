/**
 * ProposalsQueue — the "Proposals" lens for the Engine console's Links and
 * AI-entities tabs. The complete hygiene surface for its domain (this replaced
 * the old standalone WorkbenchHygiene page): a Queue view of what the
 * adjudicate stage and the on-demand scans proposed, with inline Apply /
 * Dismiss, and a History view of everything that ran (with Restore).
 */
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

import api from "@/api/client";
import {
  useApplyAdjudicationAll,
  useApplyAdvisories,
  useDismissProposals,
  useHygieneFeed,
  useHygieneStats,
  useRunNameNormalization,
  useScanAliasHygiene,
  useScanIdHygiene,
  useScanVendorAutolink,
  type FeedLink,
  type FeedRow,
} from "@/hooks/useHygiene";
import { useHygieneRowAction } from "@/hooks/useHygieneRowAction";
import { formatDateTime } from "@/utils/formatDate";
import { getEntityCssVar, getEntityLabel } from "@/utils/entityTheme";
import { useQueryClient } from "@tanstack/react-query";

import styles from "./ProposalsQueue.module.css";
import { confirmDialog } from "@/utils/dialog";

type Domain = "links" | "entities";

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

// Per-domain quick filters over the action column. Values may be comma-lists —
// the backend feed matches any of the listed action codes.
const LINK_FILTERS = [
  { value: "", label: "All" },
  { value: "needs_reclassification", label: "Reclassify" },
  { value: "shadow_remove", label: "Remove" },
];
const ENTITY_FILTERS = [
  { value: "", label: "All" },
  { value: "normalize_name", label: "Name fix" },
  { value: "alias_collision", label: "Alias trim" },
  { value: "vendor_autolink", label: "Vendor link" },
  { value: "ttp_malformed_id,cve_malformed_id,cve_withdrawn", label: "ID fix" },
  { value: "adjudication_veto", label: "Veto" },
  { value: "adjudication_merge", label: "Merge (review)" },
  { value: "adjudication_reclassify", label: "Reclassify (review)" },
  { value: "adjudication_edge_demote", label: "Demote" },
  { value: "adjudication_ioc_drop,adjudication_unlink", label: "Drop / unlink" },
];
type OriginFacet = "" | "adjudicator" | "legacy" | "orphaned";
const ORIGINS: { value: OriginFacet; label: string; title: string; queueOnly?: boolean }[] = [
  { value: "", label: "All", title: "Every proposal" },
  { value: "adjudicator", label: "Adjudicator", title: "Filed by the post-analysis review, with the article in hand" },
  { value: "legacy", label: "Legacy", title: "Filed by the retired nightly jobs and on-demand scans" },
  {
    value: "orphaned",
    label: "Orphaned",
    title: "Legacy proposals no entry can carry to the adjudicate stage — yours to dismiss or apply by hand",
    queueOnly: true,
  },
];
const ORPHANED_NOTE =
  "Left by the retired jobs with no entry to re-judge them against. Dismiss or apply by hand; nothing automatic touches them.";
const LINK_HISTORY_FILTERS = [
  { value: "", label: "All" },
  { value: "removed", label: "Removed" },
  { value: "restored", label: "Restored" },
];
const ENTITY_HISTORY_FILTERS = [
  { value: "", label: "All" },
  { value: "merge", label: "Merged" },
  { value: "reclassify", label: "Reclassified" },
  { value: "orphan_prune", label: "Orphans" },
  { value: "update_description,update_aliases", label: "Profile" },
  { value: "ai_enrich_filled,ai_enrich_unknown", label: "AI enrich" },
  { value: "adjudication_restored", label: "Restored" },
];


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
  domain,
  initialAction,
  initialOrigin,
}: {
  domain: Domain;
  initialAction?: string;
  initialOrigin?: "adjudicator" | "legacy";
}) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [hist, setHist] = useState(false);
  const [actionFilter, setActionFilter] = useState(initialAction ?? "");
  const [originFilter, setOriginFilter] = useState<OriginFacet>(initialOrigin ?? "");
  const [modePending, setModePending] = useState(false);
  const [busyRow, setBusyRow] = useState<string | null>(null);

  const source = domain === "links" ? "link_validator" : "entity_maintenance";
  // "Orphaned" is its own feed switch, not an origin value.
  const orphaned = originFilter === "orphaned";
  const origin = orphaned || !originFilter ? undefined : originFilter;
  const stats = useHygieneStats();
  const feed = useHygieneFeed(
    hist
      ? { source, mode: "apply", action: actionFilter || undefined, origin, limit: 100 }
      : {
          source,
          pending: true,
          action: actionFilter || undefined,
          origin,
          orphaned: orphaned || undefined,
          limit: 100,
        },
  );

  const runRowAction = useHygieneRowAction();
  const dismissProposals = useDismissProposals();
  const applyAdvisories = useApplyAdvisories();
  const applyAdjudication = useApplyAdjudicationAll();
  const scanNames = useRunNameNormalization();
  const scanAliases = useScanAliasHygiene();
  const scanIds = useScanIdHygiene();
  const scanVendors = useScanVendorAutolink();

  // Scans that mint fresh proposals into this domain's queue (entities only —
  // link verdicts come from the adjudicate stage at ingest).
  const scans =
    domain === "links"
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

  const FILTERS = hist
    ? domain === "links"
      ? LINK_HISTORY_FILTERS
      : ENTITY_HISTORY_FILTERS
    : domain === "links"
      ? LINK_FILTERS
      : ENTITY_FILTERS;

  const switchHist = (next: boolean) => {
    if (next === hist) return;
    setHist(next);
    setActionFilter("");
    // Orphaned is a queue-only lens — history has no notion of it.
    if (next && orphaned) setOriginFilter("");
  };

  const doRow = async (row: FeedRow, action: string) => {
    setBusyRow(row.id);
    try {
      await runRowAction(row, action);
    } finally {
      setBusyRow(null);
    }
  };

  // Scoped to what the table shows: the action filter AND the origin facet.
  const clearAll = async () => {
    const label = actionFilter
      ? (FILTERS.find((f) => f.value === actionFilter)?.label ?? "these").toLowerCase()
      : "all pending";
    const who = origin ? ` ${origin}` : "";
    if (
      !(await confirmDialog({
        title: "Dismiss proposals",
        message: `Dismiss ${label}${who} proposals without applying them? The suggestions are deleted; entities and links are untouched.`,
        confirmLabel: "Dismiss",
        destructive: true,
      }))
    )
      return;
    try {
      const r = await dismissProposals.mutateAsync({ source, action: actionFilter || undefined, origin });
      toast.success(`Dismissed ${r.dismissed} proposal${r.dismissed === 1 ? "" : "s"}`);
    } catch (e) {
      toast.error(`Dismiss failed: ${(e as Error).message}`);
    }
  };

  // Every pending adjudicator proposal, both logs, through the stage's own
  // apply path — the bulk form of the per-row Apply.
  const applyAllAdjudicator = async () => {
    const label = actionFilter
      ? (FILTERS.find((f) => f.value === actionFilter)?.label ?? "these").toLowerCase()
      : "every pending";
    if (
      !(await confirmDialog({
        title: "Apply adjudicator proposals",
        message: `Apply ${label} adjudicator proposals now? Each one is applied the way the stage would in apply mode, and each stays undoable from History.`,
        confirmLabel: "Apply all",
        destructive: true,
      }))
    )
      return;
    try {
      const r = await applyAdjudication.mutateAsync({ action: actionFilter || undefined, limit: 500 });
      const errs = r.errors.length;
      const msg = `Applied ${r.applied}, skipped ${r.skipped}${errs ? `, ${errs} error${errs === 1 ? "" : "s"}` : ""}`;
      if (errs) toast.warning(msg, { description: r.errors[0]?.error });
      else toast.success(msg);
    } catch (e) {
      toast.error(`Apply failed: ${(e as Error).message}`);
    }
  };

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

        <div className={styles.seg} title="Queue: pending suggestions awaiting review · History: everything that ran">
          <button className={!hist ? styles.segOn : ""} onClick={() => switchHist(false)}>
            Queue
          </button>
          <button className={hist ? styles.segOn : ""} onClick={() => switchHist(true)}>
            History
          </button>
        </div>

        <div className={styles.seg}>
          {FILTERS.map((f) => (
            <button key={f.value || "all"} className={actionFilter === f.value ? styles.segOn : ""} onClick={() => setActionFilter(f.value)}>
              {f.label}
            </button>
          ))}
        </div>

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


        <span className={styles.grow} />

        {!hist && !orphaned && (
          <>
            {origin === "adjudicator" ? (
              <button
                className={styles.btn}
                disabled={applyAdjudication.isPending || rows.length === 0}
                title="Apply every pending adjudicator proposal (both logs) through the stage's own apply path"
                onClick={applyAllAdjudicator}
              >
                {applyAdjudication.isPending ? "Applying…" : "Apply all"}
              </button>
            ) : (
              domain === "links" && (
                <button
                  className={styles.btn}
                  disabled={applyAdvisories.isPending || rows.length === 0}
                  title="Apply every proposed reclassification"
                  onClick={() =>
                    applyAdvisories
                      .mutateAsync({ mode: "apply", limit: 500 })
                      .then((r) => toast.success(`Applied ${r.applied} reclassifications`))
                      .catch((e) => toast.error(`Apply failed: ${(e as Error).message}`))
                  }
                >
                  Apply all
                </button>
              )
            )}

            <button className={styles.btnDanger} disabled={dismissProposals.isPending} onClick={clearAll}>
              {dismissProposals.isPending ? "Clearing…" : "Dismiss all"}
            </button>
          </>
        )}
      </div>

      {orphaned && !hist && <p className={styles.note}>{ORPHANED_NOTE}</p>}

      {/* table */}
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>{hist ? "Change" : "Proposed change"}</th>
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
                <td colSpan={5} className={styles.empty}>
                  {hist
                    ? `No applied ${domain === "links" ? "link" : "entity"} changes match — nothing has run yet.`
                    : orphaned
                      ? "No orphaned proposals — every pending legacy proposal has an entry the stage can re-judge it against."
                      : `No pending ${domain === "links" ? "link" : "entity"} proposals — nothing waiting for review.${
                          scans.length ? " Run a scan below to generate some." : ""
                        }`}
                </td>
              </tr>
            )}
            {feed.isLoading && (
              <tr>
                <td colSpan={5} className={styles.empty}>
                  Loading {hist ? "history" : "proposals"}…
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* scans that generate proposals into this queue */}
      {!hist && scans.length > 0 && (
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
