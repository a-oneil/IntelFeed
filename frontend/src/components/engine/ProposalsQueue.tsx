/**
 * ProposalsQueue — the Engine console's Review tab: everything the AI wants a
 * person to approve, in one queue over both proposal logs.
 *
 * The queue lens shows one row per entity (the backend files a proposal per
 * article, so "Linux" collects 600 remove-link proposals and "Qilin" a
 * reclassify per mention): the row says what each kind of proposal wants,
 * its buttons settle every article's copy at once, and it expands to the
 * articles behind it. Rows about something that is not a catalogue entity
 * (an edge, an article's assessment) stand alone. A Domain facet (what
 * applying changes: links, entities, relationships), an Origin facet (who
 * proposed it), inline Apply / Dismiss, one background Apply all, the
 * adjudicator's mode switch with its tuning knobs beside it, and a History
 * lens of everything that ran (with Restore).
 */

import { Fragment, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

import api from "@/api/client";
import SystemSettings from "@/components/SystemSettings";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import {
  PROPOSAL_DOMAINS,
  invalidateAfterBulkApply,
  useApplyReclassifyGroups,
  useBulkApplyProgress,
  useDismissProposals,
  useDismissReviewGroups,
  useHygieneFeed,
  useHygieneStats,
  useReviewGroups,
  useRunNameNormalization,
  useScanAliasHygiene,
  useScanDuplicates,
  useScanIdHygiene,
  useScanVendorAutolink,
  useStartBulkApply,
  useUnlinkAction,
  type FeedLink,
  type FeedResponse,
  type FeedRow,
  type ProposalDomain,
  type ProposalOrigin,
  type ReviewGroup,
} from "@/hooks/useHygiene";
import { useHygieneRowAction } from "@/hooks/useHygieneRowAction";
import { formatDateTime } from "@/utils/formatDate";
import { getEntityCssVar, getEntityLabel } from "@/utils/entityTheme";
import { useQueryClient } from "@tanstack/react-query";

import { EntityRowActions } from "./EntityRowActions";
import styles from "./ProposalsQueue.module.css";
import cg from "./CleanupGroups.module.css";
import { confirmDialog } from "@/utils/dialog";

export type ReviewLens = "queue" | "history";
export type { ProposalOrigin };

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
  merge_review_distinct: { label: "Not duplicates", cls: styles.tName },
  no_op: { label: "No change", cls: styles.tName },
};

const DOMAIN_LABELS: Record<ProposalDomain, string> = {
  links: "Links",
  entities: "Entities",
  relationships: "Relationships",
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
  { value: "merge_review_distinct", label: "Not duplicates" },
  { value: "orphan_prune", label: "Orphans pruned" },
  { value: "update_description,update_aliases", label: "Profile" },
  { value: "ai_enrich_filled,ai_enrich_unknown", label: "AI enrich" },
  { value: "adjudication_restored", label: "Verdict restored" },
];
type OriginFacet = "" | ProposalOrigin | "orphaned";
const ORIGINS: { value: OriginFacet; label: string; title: string; queueOnly?: boolean }[] = [
  { value: "", label: "All", title: "Every proposal" },
  { value: "adjudicator", label: "Adjudicator", title: "Filed by the post-analysis review, with the article in hand" },
  {
    value: "merge_review",
    label: "Duplicate review",
    title: "Filed by the catalogue-wide duplicate review, from the two profiles side by side",
  },
  { value: "scan", label: "Scans", title: "Filed by the on-demand scans and analysts" },
  {
    value: "orphaned",
    label: "Orphaned",
    title: "Scan proposals no entry can carry to the adjudicate stage — yours to dismiss or apply by hand",
    queueOnly: true,
  },
];
const ORPHANED_NOTE =
  "Left by the retired jobs with no entry to re-judge them against. Dismiss or apply by hand; nothing automatic touches them.";

// The adjudicator's knobs that decide what becomes a proposal instead of
// being applied — shown beside the mode switch, where the question comes up.
const TUNING_KEYS = [
  "adjudication_apply_min_confidence",
  "adjudication_reclassify_consensus",
  "adjudication_circuit_breaker_pct",
  "adjudication_scope",
  "merge_review_batch_size",
  "merge_review_min_confidence",
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

const UNLINK_KINDS = new Set(["shadow_remove", "adjudication_unlink"]);
// Rows about something the entity menu cannot act on (an edge, an article, a ledger row).
const NO_ENTITY_MENU = new Set(["relationship", "entry", "observable"]);
const RECLASSIFY_KINDS = new Set(["needs_reclassification", "adjudication_reclassify"]);

function feedLinkHref(link: FeedLink): string | null {
  if (link.kind === "entry") return typeof link.entity_id === "string" ? `/?entry=${link.entity_id}` : null;
  if (link.kind === "external") return typeof link.entity_id === "string" ? link.entity_id : null;
  const slug = link.entity_type;
  return slug && link.entity_id ? `/workbench/${slug}/${link.entity_id}` : null;
}

function LinkChips({ links }: { links: FeedLink[] }) {
  const extra = links.filter((l) => l.kind !== "entity" || l.role === "target" || l.role === "b");
  if (extra.length === 0) return null;
  return (
    <span className={styles.linkChips}>
      {extra.map((l, i) => {
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
  );
}

/** One proposal: the History lens's rows and an entity row's expanded articles. */
function ProposalRow({
  row,
  hist,
  busy,
  onAction,
  sub,
}: {
  row: FeedRow;
  hist: boolean;
  busy: boolean;
  onAction: (row: FeedRow, action: string) => void;
  sub?: boolean;
}) {
  const navigate = useNavigate();
  const meta = CHANGE_META[row.action] ?? { label: row.action, cls: styles.tName };
  const slug = row.entity_type;
  const acts = [...row.actions].sort((a, b) => ACTION_ORDER.indexOf(a) - ACTION_ORDER.indexOf(b));
  return (
    <tr className={sub ? cg.subRow : undefined}>
      <td>
        <span className={`${styles.tag} ${meta.cls}`}>{meta.label}</span>
        {row.origin === "adjudicator" && !sub && (
          <span className={styles.originTag} title="Filed by the post-analysis review, with the article in hand">
            adjudicator
          </span>
        )}
        {row.origin === "merge_review" && !sub && (
          <span className={styles.originTag} title="Filed by the catalogue-wide duplicate review, from the two profiles side by side">
            duplicate review
          </span>
        )}
      </td>
      <td className={styles.muted}>{sub ? "" : (DOMAIN_LABELS[row.domain] ?? row.domain)}</td>
      <td>
        {row.entity_name && !sub ? (
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
          <span className={styles.muted}>{sub ? "" : "—"}</span>
        )}
      </td>
      <td className={styles.detail}>
        <span className={styles.subject}>{row.subject ?? "—"}</span>
        {row.reason && <span className={styles.reason}>{row.reason}</span>}
        {row.context && <span className={styles.reason}>“{row.context}”</span>}
        <LinkChips links={row.links ?? []} />
      </td>
      <td className={styles.when}>{formatDateTime(row.when)}</td>
      <td>
        <div className={styles.acts}>
          {acts.map((a) => {
            const b = ACTION_BTN[a];
            if (!b) return null;
            return (
              <button key={a} className={`${styles.rowBtn} ${b.cls}`} disabled={busy} onClick={() => onAction(row, a)}>
                {b.label}
              </button>
            );
          })}
          {!hist && !sub && row.entity_type && row.entity_id && (
            <EntityRowActions
              entityType={row.entity_type}
              entityId={row.entity_id}
              name={row.entity_name ?? row.subject ?? "entity"}
              disabled={busy}
            />
          )}
        </div>
      </td>
    </tr>
  );
}

/** The articles behind one entity's row. */
function GroupRows({ group, busy, onAction }: { group: ReviewGroup; busy: boolean; onAction: (row: FeedRow, action: string) => void }) {
  const feed = useHygieneFeed({
    pending: true,
    entity_type: group.entity_type,
    entity_id: group.entity_id ?? undefined,
    limit: 200,
  });
  if (feed.isLoading)
    return (
      <tr className={cg.subRow}>
        <td colSpan={6} className={styles.muted}>
          Loading articles…
        </td>
      </tr>
    );
  const rows = feed.data?.rows ?? [];
  return (
    <>
      {rows.map((r) => (
        <ProposalRow key={r.id} row={r} hist={false} busy={busy} onAction={onAction} sub />
      ))}
      {feed.data?.has_more && (
        <tr className={cg.subRow}>
          <td colSpan={6} className={styles.muted}>
            Showing the newest {rows.length} of {group.proposals.toLocaleString()} — the row's buttons settle all of them.
          </td>
        </tr>
      )}
    </>
  );
}

const keyOf = (g: ReviewGroup) => g.key;

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
  const [search, setSearch] = useState("");
  const q = useDebouncedValue(search, 250);
  const [offset, setOffset] = useState(0);
  const [modePending, setModePending] = useState(false);
  const [showTuning, setShowTuning] = useState(false);
  const [busyRow, setBusyRow] = useState<string | null>(null);
  const [open, setOpen] = useState<Set<string>>(new Set());

  // "Orphaned" is its own feed switch, not an origin value.
  const orphaned = !hist && originFilter === "orphaned";
  const origin = orphaned || !originFilter ? undefined : (originFilter as ProposalOrigin);
  const domain = domainFilter || undefined;
  const stats = useHygieneStats();
  // History and the orphaned switch are flat rows; the queue is per entity,
  // so the flat query only runs when one of those is showing.
  const flat = hist || orphaned;
  const feed = useHygieneFeed(
    hist
      ? { mode: "apply", action: actionFilter || undefined, origin, domain, limit: 100 }
      : { pending: true, action: actionFilter || undefined, origin, domain, orphaned: true, limit: 100 },
    { enabled: flat },
  );
  const PAGE = 100;
  const groups = useReviewGroups({
    q: q || undefined,
    action: actionFilter || undefined,
    origin,
    domain,
    limit: PAGE,
    offset,
  });
  useEffect(() => setOffset(0), [q, actionFilter, origin, domain]);

  const runRowAction = useHygieneRowAction();
  const dismissProposals = useDismissProposals();
  const dismissGroups = useDismissReviewGroups();
  const unlinkAction = useUnlinkAction();
  const applyReclassify = useApplyReclassifyGroups();
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
    if (bulkJobId && bulkProgress?.status === "running") {
      if (flat) feed.refetch();
      else groups.refetch();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bulkProgress?.processed]);

  const scanNames = useRunNameNormalization();
  const scanAliases = useScanAliasHygiene();
  const scanIds = useScanIdHygiene();
  const scanVendors = useScanVendorAutolink();
  const scanDupes = useScanDuplicates();

  // Scans that mint fresh entity proposals into the queue (link verdicts
  // come from the adjudicate stage at ingest, so there is nothing to scan for).
  const scans =
    hist || (domainFilter && domainFilter !== "entities")
      ? []
      : [
          {
            label: "Review duplicates (AI)",
            title:
              "Put the most likely duplicate pairs of actors, malware and tools in front of the model on the AI worker; each pair it calls the same thing lands here as a Merge proposal. Runs daily on its own too.",
            busy: scanDupes.isPending,
            run: () =>
              scanDupes
                .mutateAsync()
                .then((r) =>
                  r.dispatched
                    ? toast.success("Duplicate review started on the AI worker — Merge rows appear as it finishes")
                    : toast.message("The duplicate review is already running"),
                )
                .catch((e) => toast.error(`Review failed: ${(e as Error).message}`)),
          },
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

  const rows = useMemo(() => feed.data?.rows ?? [], [feed.data]);
  const groupRows = useMemo(() => groups.data?.groups ?? [], [groups.data]);
  const total = groups.data?.total ?? 0;

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
    const who =
      origin === "adjudicator" ? " adjudicator" : origin === "merge_review" ? " duplicate-review" : origin === "scan" ? " scan" : "";
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

  const refreshGroups = () => {
    qc.invalidateQueries({ queryKey: ["hygiene"] });
    qc.invalidateQueries({ queryKey: ["extraction"] });
    qc.invalidateQueries({ queryKey: ["entity-links"] });
    qc.invalidateQueries({ queryKey: ["engine"] });
  };

  /** Apply everything in an entity's row except its reclassify proposals
   *  (those need a target type: the chips). Links go through the grouped
   *  unlink path; the rest row by row through the same code the per-row
   *  Apply uses. */
  const applyGroup = async (g: ReviewGroup) => {
    setBusyRow(g.key);
    try {
      let done = 0;
      let failed = 0;
      if (g.entity_id && g.kinds.some((k) => UNLINK_KINDS.has(k.action))) {
        const r = await unlinkAction.mutateAsync({
          action: "apply",
          target: { items: [{ entity_type: g.entity_type, entity_id: g.entity_id }] },
        });
        done += r.done;
        failed += r.failed;
      }
      const others = g.kinds.filter((k) => !UNLINK_KINDS.has(k.action) && !RECLASSIFY_KINDS.has(k.action));
      if (others.length > 0) {
        let targets: FeedRow[];
        if (g.entity_id) {
          const { data } = await api.get<FeedResponse>("/admin/hygiene/feed", {
            params: { pending: "true", entity_type: g.entity_type, entity_id: g.entity_id, limit: 200 },
          });
          targets = data.rows.filter((r) => !UNLINK_KINDS.has(r.action) && !RECLASSIFY_KINDS.has(r.action));
          // One entity merges once: the most-proposed target's row, applied
          // last. The merge removes the entity, which settles every other
          // proposal about it, so a second target would only fail.
          const merges = targets.filter((r) => r.action === "adjudication_merge");
          if (merges.length > 0) {
            // merge_into arrives most-proposed first.
            const top = g.merge_into[0]?.target_id;
            const pick =
              merges.find((r) => (r.payload.after as { target_id?: string } | undefined)?.target_id === top) ?? merges[0];
            targets = [...targets.filter((r) => r.action !== "adjudication_merge"), pick];
          }
        } else {
          // A row with no entity is its own group: enough of a FeedRow for the
          // per-row endpoints (they key on source, id and action).
          targets = g.row_ids.map((id) => ({
            id,
            source: id.startsWith("link_validator:") ? "link_validator" : "entity_maintenance",
            action: g.kinds[0]?.action ?? "",
            when: g.latest_at,
            mode: "shadow",
            applied: false,
            entity_type: g.entity_type,
            entity_id: null,
            entity_name: null,
            subject: g.subject,
            reason: g.reason,
            payload: {},
            actions: ["apply", "dismiss"],
            links: g.links,
            origin: g.origin === "mixed" ? null : g.origin,
            domain: g.domains[0] ?? "entities",
          }));
        }
        for (const row of targets) {
          if (!row.actions.includes("apply")) continue;
          await runRowAction(row, "apply");
          done += 1;
        }
      }
      if (failed) toast.warning(`Applied ${done}, ${failed} failed`);
      refreshGroups();
    } catch (e) {
      toast.error(`Apply failed: ${(e as Error).message}`);
    } finally {
      setBusyRow(null);
    }
  };

  const reclassifyGroup = async (g: ReviewGroup, target: string) => {
    if (!g.entity_id) return;
    setBusyRow(g.key);
    try {
      const r = await applyReclassify.mutateAsync([{ entity_type: g.entity_type, entity_id: g.entity_id, target_type: target }]);
      if (r.failed) toast.error(`Apply failed: ${r.errors[0]?.error ?? "unknown error"}`);
      else toast.success(`Reclassified ${g.name} → ${getEntityLabel(target).toLowerCase()} · ${r.cleared_rows.toLocaleString()} proposals cleared`);
    } catch (e) {
      toast.error(`Apply failed: ${(e as Error).message}`);
    } finally {
      setBusyRow(null);
    }
  };

  const dismissGroup = async (g: ReviewGroup) => {
    setBusyRow(g.key);
    try {
      const r = await dismissGroups.mutateAsync([{ entity_type: g.entity_type, entity_id: g.entity_id, row_ids: g.row_ids }]);
      toast.success(
        g.entity_id
          ? `Dismissed — ${r.cleared_rows.toLocaleString()} proposal${r.cleared_rows === 1 ? "" : "s"} about ${g.name} cleared; it won't be re-proposed`
          : "Dismissed",
      );
    } catch (e) {
      toast.error(`Dismiss failed: ${(e as Error).message}`);
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
  const pendingTotal = groups.data?.proposals ?? stats.data?.pending_total ?? 0;

  const applyLabel = (g: ReviewGroup) => {
    const kinds = g.kinds.filter((k) => !RECLASSIFY_KINDS.has(k.action)).map((k) => k.action);
    if (kinds.length === 0) return null;
    if (kinds.every((k) => UNLINK_KINDS.has(k))) return "Remove links";
    if (kinds.length === 1 && kinds[0] === "adjudication_merge") return "Merge";
    if (kinds.length === 1 && kinds[0] === "adjudication_veto") return "Delete";
    return "Apply";
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
        <button
          className={`${styles.rowBtn} ${showTuning ? styles.segOn : styles.bGhost}`}
          title="The knobs that decide what is applied at ingest and what lands here instead"
          onClick={() => setShowTuning((v) => !v)}
        >
          ⚙ Tuning
        </button>

        {!hist && (
          <input
            className={cg.search}
            placeholder="Find an entity…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        )}

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
              disabled={bulkRunning || pendingTotal === 0}
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

      {showTuning && (
        <div className={styles.tuning}>
          <p className={styles.note}>
            In <strong>Applied</strong> mode a verdict still lands here instead of being applied when it is under the
            confidence floor, when it is a type change that has not reached consensus yet, when the article tripped the
            circuit breaker (too many destructive verdicts in one review), or when it is an assessment (those are only ever
            notes). The duplicate review always files its merges here. The full stage panel is under Entries → AI review.
          </p>
          <SystemSettings filterKeys={TUNING_KEYS} flat hideGroupTitle />
        </div>
      )}

      {orphaned && <p className={styles.note}>{ORPHANED_NOTE}</p>}

      {/* table */}
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            {flat ? (
              <tr>
                <th>{hist ? "Change" : "Proposed change"}</th>
                <th>Domain</th>
                <th>Entity</th>
                <th>Detail</th>
                <th>When</th>
                <th className={styles.actCol} />
              </tr>
            ) : (
              <tr>
                <th>Entity</th>
                <th>Proposed</th>
                <th>Why</th>
                <th>Latest</th>
                <th className={styles.actCol} />
              </tr>
            )}
          </thead>
          <tbody>
            {flat &&
              rows.map((row) => <ProposalRow key={row.id} row={row} hist={hist} busy={busyRow === row.id} onAction={doRow} />)}
            {!flat &&
              groupRows.map((g) => {
                const k = keyOf(g);
                const busy = busyRow === k;
                const isOpen = open.has(k);
                const label = applyLabel(g);
                const kindChips = g.kinds.filter((kd) => !RECLASSIFY_KINDS.has(kd.action));
                const reclassifyN = g.kinds.filter((kd) => RECLASSIFY_KINDS.has(kd.action)).reduce((n, kd) => n + kd.count, 0);
                const expandable = g.entity_id !== null && g.proposals > 1;
                return (
                  <Fragment key={k}>
                    <tr>
                      <td>
                        {g.entity_id && !NO_ENTITY_MENU.has(g.entity_type) ? (
                          <button
                            className={styles.ent}
                            disabled={!g.exists}
                            onClick={() => navigate(`/workbench/${g.entity_type}/${g.entity_id}`)}
                            title={g.exists ? getEntityLabel(g.entity_type) : "Already deleted or converted"}
                          >
                            <span className={styles.entDot} style={{ background: getEntityCssVar(g.entity_type) }} />
                            {g.name}
                            {!g.exists && <span className={cg.gone}>gone</span>}
                          </button>
                        ) : (
                          <span className={styles.muted}>{g.entity_type === "relationship" ? "relationship" : g.name || g.entity_type}</span>
                        )}
                        <span className={cg.meta}>
                          {g.entity_id ? getEntityLabel(g.entity_type) : ""}
                          {g.linked !== null && g.linked !== undefined ? ` · ${g.linked.toLocaleString()} article${g.linked === 1 ? "" : "s"}` : ""}
                        </span>
                      </td>
                      <td>
                        <div className={cg.chips}>
                          {kindChips.map((kd) => {
                            const meta = CHANGE_META[kd.action] ?? { label: kd.action, cls: styles.tName };
                            return (
                              <span key={kd.action} className={`${styles.tag} ${meta.cls}`}>
                                {meta.label}
                                {kd.count > 1 && <span className={cg.cnt}>{kd.count.toLocaleString()}</span>}
                              </span>
                            );
                          })}
                          {g.merge_into.map((m) => (
                            <a key={m.target_id} className={styles.linkChip} href={`/workbench/${m.target_type}/${m.target_id}`}>
                              into {m.name ?? "?"}
                            </a>
                          ))}
                          {g.reclassify_to.map((s) => (
                            <button
                              key={s.type}
                              className={cg.target}
                              disabled={busy || !g.exists}
                              onClick={() => reclassifyGroup(g, s.type)}
                              title={`Convert ${g.name} to a ${getEntityLabel(s.type).toLowerCase()} — proposed by ${s.count} article${s.count === 1 ? "" : "s"}`}
                            >
                              <span className={styles.entDot} style={{ background: getEntityCssVar(s.type) }} />
                              → {getEntityLabel(s.type)}
                              <span className={cg.cnt}>{s.count.toLocaleString()}</span>
                            </button>
                          ))}
                          {g.origin === "adjudicator" && (
                            <span className={styles.originTag} title="Filed by the post-analysis review, with the article in hand">
                              adjudicator
                            </span>
                          )}
                        </div>
                      </td>
                      <td className={styles.detail}>
                        {(g.entity_id === null || NO_ENTITY_MENU.has(g.entity_type)) && g.subject && (
                          <span className={styles.subject}>{g.subject}</span>
                        )}
                        {g.reason && <span className={styles.reason}>{g.reason}</span>}
                        <LinkChips links={g.links} />
                        <span className={cg.meta}>
                          {g.proposals.toLocaleString()} proposal{g.proposals === 1 ? "" : "s"}
                          {reclassifyN > 0 && kindChips.length > 0 ? ` (${reclassifyN.toLocaleString()} to reclassify)` : ""}
                          {g.matched_names.length > 0 && ` · matched as ${g.matched_names.map((f) => `“${f}”`).join(", ")}`}
                          {g.sample_entry_id && (
                            <>
                              {" · "}
                              <a className={styles.linkChip} href={`/?entry=${g.sample_entry_id}`}>
                                example article
                              </a>
                            </>
                          )}
                          {expandable && (
                            <>
                              {" · "}
                              <button
                                className={cg.expand}
                                onClick={() => {
                                  const next = new Set(open);
                                  if (next.has(k)) next.delete(k);
                                  else next.add(k);
                                  setOpen(next);
                                }}
                              >
                                {isOpen ? "▾ hide articles" : "▸ show articles"}
                              </button>
                            </>
                          )}
                        </span>
                      </td>
                      <td className={styles.when}>{formatDateTime(g.latest_at)}</td>
                      <td>
                        <div className={styles.acts}>
                          {label && (
                            <button
                              className={`${styles.rowBtn} ${label === "Remove links" || label === "Delete" ? styles.bWarn : styles.bGood}`}
                              disabled={busy || bulkRunning}
                              onClick={() => applyGroup(g)}
                              title="Apply every proposal in this row (type changes use the chips)"
                            >
                              {label}
                            </button>
                          )}
                          <button
                            className={`${styles.rowBtn} ${styles.bGhost}`}
                            disabled={busy || bulkRunning}
                            onClick={() => dismissGroup(g)}
                            title={
                              g.entity_id
                                ? "Leave it as it is — keep its links and type, clear every proposal about it, and don't propose these again"
                                : "Drop this proposal"
                            }
                          >
                            Dismiss
                          </button>
                          {g.entity_id && g.exists && !NO_ENTITY_MENU.has(g.entity_type) && (
                            <EntityRowActions entityType={g.entity_type} entityId={g.entity_id} name={g.name} disabled={busy} />
                          )}
                        </div>
                      </td>
                    </tr>
                    {isOpen && <GroupRows group={g} busy={busy} onAction={doRow} />}
                  </Fragment>
                );
              })}
            {!flat && !groups.isLoading && groupRows.length === 0 && (
              <tr>
                <td colSpan={5} className={styles.empty}>
                  {q
                    ? "No pending proposals match."
                    : `No pending proposals — nothing waiting for review.${scans.length ? " Run a scan below to generate some." : ""}`}
                </td>
              </tr>
            )}
            {flat && !feed.isLoading && rows.length === 0 && (
              <tr>
                <td colSpan={6} className={styles.empty}>
                  {hist
                    ? "No applied changes match — nothing has run yet."
                    : "No orphaned proposals — every pending scan proposal has an entry the stage can re-judge it against."}
                </td>
              </tr>
            )}
            {(flat ? feed.isLoading : groups.isLoading) && (
              <tr>
                <td colSpan={6} className={styles.empty}>
                  Loading {hist ? "history" : "proposals"}…
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {!flat && total > PAGE && (
        <div className={cg.pager}>
          <button className={styles.rowBtn} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
            ← Prev
          </button>
          <span className={styles.muted}>
            {offset + 1}–{Math.min(offset + PAGE, total)} of {total.toLocaleString()} entities
          </span>
          <button className={styles.rowBtn} disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)}>
            Next →
          </button>
        </div>
      )}

      {/* scans that generate proposals into this queue */}
      {scans.length > 0 && (
        <div className={styles.genRow}>
          <span className={styles.genLabel}>Generate proposals</span>
          {scans.map((s) => (
            <button key={s.label} className={styles.genBtn} disabled={s.busy} title={s.title} onClick={s.run}>
              {s.busy ? "Working…" : s.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
