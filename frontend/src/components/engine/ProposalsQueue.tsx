/**
 * ProposalsQueue — the Review tab's Queue and History lenses.
 *
 * Queue: everything the adjudicator, the duplicate review and the scans want changed, one row per entity (the backend files a proposal per article, so "Linux" collects 600 remove-link proposals and "Qilin" a reclassify per mention). The row says what is proposed, who proposed it (Source) and how sure they were (Confidence); its buttons settle every article's copy at once, and it expands to the evidence and the articles behind it. Rows about something that is not a catalog entity (an edge, an article's assessment) stand alone. One filter row: Domain (what applying changes), Action, Sort, search; Run scan adds more rows; Apply all and Dismiss all act on what the table shows.
 *
 * History: everything that was applied, by a person or by the stage in Applied mode, with Restore. Filters: Change, Applied by, a time window, search. Restore puts one thing back; nothing bulk.
 */

import { Fragment, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

import { DropdownItem, ToolbarDropdown } from "@/components/ToolbarDropdown";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import {
  PROPOSAL_DOMAINS,
  invalidateAfterReview,
  useApplyReclassifyGroups,
  useApplyReview,
  useBulkApplyProgress,
  useDismissReview,
  useHygieneFeed,
  useReviewGroups,
  useRunNameNormalization,
  useScanAliasHygiene,
  useScanDuplicates,
  useScanIdHygiene,
  useScanVendorAutolink,
  useStartBulkApply,
  type FeedLink,
  type FeedRow,
  type ProposalDomain,
  type ReviewGroup,
  type ReviewScope,
  type ReviewSort,
} from "@/hooks/useHygiene";
import { useHygieneRowAction } from "@/hooks/useHygieneRowAction";
import { formatDateTime, formatShortDateTime } from "@/utils/formatDate";
import { getEntityCssVar, getEntityLabel } from "@/utils/entityTheme";
import { useQueryClient } from "@tanstack/react-query";

import { EntityRowActions } from "./EntityRowActions";
import { RowEvidencePanel } from "./EvidencePanel";
import { RowMenu, type RowMenuItem } from "./RowMenu";
import styles from "./ProposalsQueue.module.css";
import cg from "./ProposalGroups.module.css";
import { confirmDialog } from "@/utils/dialog";

export type ProposalsLens = "queue" | "history";

/** What a pending proposal wants, in plain words. */
const CHANGE_LABEL: Record<string, string> = {
  shadow_remove: "Remove link",
  needs_reclassification: "Reclassify",
  vendor_autolink: "Link vendor",
  normalize_name: "Fix name",
  alias_collision: "Remove alias",
  ttp_malformed_id: "Fix ID",
  cve_malformed_id: "Fix ID",
  cve_withdrawn: "Delete withdrawn CVE",
  adjudication_veto: "Delete entity",
  adjudication_merge: "Merge",
  adjudication_unlink: "Remove link",
  adjudication_held_link: "Link held match",
  adjudication_reclassify: "Reclassify",
  adjudication_edge_demote: "Demote edge",
  adjudication_ioc_drop: "Drop observable",
  adjudication_ioc_capture: "Capture observable",
  adjudication_assessment: "Assessment note",
  adjudication_restored: "Verdict restored",
  // applied history, for rows whose code is only ever applied
  removed: "Link removed",
  restored: "Link restored",
  merge: "Merged",
  reclassify: "Reclassified",
  orphan_prune: "Orphan pruned",
  update_description: "Profile updated",
  update_aliases: "Aliases updated",
  ai_enrich_filled: "AI enriched",
  ai_enrich_unknown: "AI unknown",
  merge_review_distinct: "Not duplicates",
  no_op: "No change",
};
// History rows read in the past tense; the proposal codes keep their names after they run.
const APPLIED_LABEL: Record<string, string> = {
  shadow_remove: "Link removed",
  adjudication_unlink: "Link removed",
  adjudication_held_link: "Held match linked",
  adjudication_veto: "Entity deleted",
  adjudication_merge: "Merged",
  adjudication_reclassify: "Reclassified",
  needs_reclassification: "Reclassified",
  adjudication_edge_demote: "Edge demoted",
  adjudication_ioc_drop: "Observable dropped",
  adjudication_ioc_capture: "Observable captured",
  alias_collision: "Alias removed",
  normalize_name: "Name fixed",
  vendor_autolink: "Vendor linked",
  ttp_malformed_id: "ID fixed",
  cve_malformed_id: "ID fixed",
  cve_withdrawn: "CVE deleted",
};

const DOMAIN_LABELS: Record<ProposalDomain, string> = {
  links: "Links",
  entities: "Entities",
  relationships: "Relationships",
};

const SOURCE_LABEL: Record<string, string> = {
  adjudicator: "Adjudicator",
  merge_review: "Duplicate review",
  scan: "Scan",
  mixed: "Several",
};

// Action filter: one dropdown over both logs. Values may be comma-lists — the backend feed matches any of the listed action codes.
const QUEUE_FILTERS = [
  { value: "", label: "Any change" },
  { value: "adjudication_unlink,shadow_remove", label: "Remove link" },
  { value: "adjudication_held_link", label: "Link held match" },
  { value: "adjudication_edge_demote", label: "Demote edge" },
  { value: "needs_reclassification,adjudication_reclassify", label: "Reclassify" },
  { value: "adjudication_veto", label: "Delete entity" },
  { value: "adjudication_merge", label: "Merge" },
  { value: "adjudication_ioc_drop", label: "Drop observable" },
  { value: "adjudication_ioc_capture", label: "Capture observable" },
  { value: "adjudication_assessment", label: "Assessment note" },
  { value: "normalize_name", label: "Fix name" },
  { value: "alias_collision", label: "Remove alias" },
  { value: "vendor_autolink", label: "Link vendor" },
  { value: "ttp_malformed_id,cve_malformed_id,cve_withdrawn", label: "Fix ID" },
  { value: "orphan_prune", label: "Prune orphan" },
];
// What ran. The adjudicator's codes stay the same from proposal to apply (only `applied` flips), so they sit beside the older engines' own codes.
const HISTORY_FILTERS = [
  { value: "", label: "Any change" },
  { value: "removed,adjudication_unlink", label: "Link removed" },
  { value: "restored", label: "Link restored" },
  { value: "adjudication_held_link", label: "Held match linked" },
  { value: "merge,adjudication_merge", label: "Merged" },
  { value: "reclassify,adjudication_reclassify", label: "Reclassified" },
  { value: "adjudication_veto", label: "Entity deleted" },
  { value: "adjudication_edge_demote", label: "Edge demoted" },
  { value: "adjudication_ioc_capture", label: "Observable captured" },
  { value: "adjudication_ioc_drop", label: "Observable dropped" },
  { value: "alias_collision", label: "Alias removed" },
  { value: "normalize_name", label: "Name fixed" },
  { value: "vendor_autolink", label: "Vendor linked" },
  { value: "ttp_malformed_id,cve_malformed_id,cve_withdrawn", label: "ID fixed" },
  { value: "merge_review_distinct", label: "Not duplicates" },
  { value: "orphan_prune", label: "Orphans pruned" },
  { value: "update_description,update_aliases", label: "Profile" },
  { value: "ai_enrich_filled,ai_enrich_unknown", label: "AI enrich" },
  { value: "adjudication_restored", label: "Verdict restored" },
];
const SORTS: { value: ReviewSort; label: string }[] = [
  { value: "newest", label: "Newest" },
  { value: "count", label: "Most proposals" },
  { value: "oldest", label: "Oldest" },
  { value: "confidence", label: "Highest confidence" },
];
// History's time window.
const WINDOWS: { value: string; label: string; hours: number | null }[] = [
  { value: "24h", label: "Last 24 hours", hours: 24 },
  { value: "7d", label: "Last 7 days", hours: 24 * 7 },
  { value: "30d", label: "Last 30 days", hours: 24 * 30 },
  { value: "all", label: "All time", hours: null },
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
const MERGE_KINDS = new Set(["adjudication_merge"]);
const ALIAS_KINDS = new Set(["alias_collision"]);

function feedLinkHref(link: FeedLink): string | null {
  if (link.kind === "entry") return typeof link.entity_id === "string" ? `/?entry=${link.entity_id}` : null;
  if (link.kind === "external") return typeof link.entity_id === "string" ? link.entity_id : null;
  const slug = link.entity_type;
  return slug && link.entity_id ? `/workbench/${slug}/${link.entity_id}` : null;
}

/** What a History row names: the person, the stage, or the duplicate review. */
function appliedByLabel(row: FeedRow): string {
  if (row.applied_by === "adjudicator") return "Adjudicator";
  if (row.applied_by === "merge_review") return "Duplicate review";
  if (row.applied_by === "person") return row.applied_by_name ?? "Analyst";
  return "Unknown";
}

function whyMeta(origin: string | null | undefined, articles: number): string {
  if (origin === "merge_review") return "from both profiles side by side";
  return `from ${articles.toLocaleString()} article${articles === 1 ? "" : "s"}`;
}

/** The "⋯" menu of a row with no one entity: open either end, open the graph, open the article. */
function rowMenuItems(links: FeedLink[], navigate: (to: string) => void): RowMenuItem[] {
  const items: RowMenuItem[] = [];
  const ends = links.filter((l) => l.kind === "entity" && l.entity_type && l.entity_id);
  for (const l of ends) items.push({ label: `Open ${l.label}`, onClick: () => navigate(feedLinkHref(l) ?? "/") });
  if (ends[0]) {
    const first = ends[0];
    items.push({
      label: "Open in graph",
      onClick: () => navigate(`/workbench/${first.entity_type}/${first.entity_id}?tab=relationships`),
    });
  }
  const entry = links.find((l) => l.kind === "entry" && l.entity_id);
  if (entry) items.push({ label: "Open article", onClick: () => navigate(feedLinkHref(entry) ?? "/") });
  return items;
}

function EntityCell({
  entityType,
  entityId,
  name,
  meta,
}: {
  entityType: string | null;
  entityId: string | null;
  name: string;
  meta: string;
}) {
  const navigate = useNavigate();
  const linkable = !!entityType && !!entityId && !NO_ENTITY_MENU.has(entityType);
  return (
    <>
      {linkable ? (
        <button
          className={styles.ent}
          onClick={() => navigate(`/workbench/${entityType}/${entityId}`)}
          title={getEntityLabel(entityType)}
        >
          <span className={styles.entDot} style={{ background: getEntityCssVar(entityType) }} />
          {name}
        </button>
      ) : (
        <span className={styles.entPlain}>{name}</span>
      )}
      {meta && <span className={cg.entMeta}>{meta}</span>}
    </>
  );
}

function entityMeta(entityType: string | null, entityId: string | null, linked?: number | null): string {
  const kind =
    entityType === "relationship"
      ? "Relationship"
      : entityType === "entry"
        ? "Article"
        : entityId && entityType
          ? getEntityLabel(entityType)
          : "";
  const n = linked !== null && linked !== undefined ? ` · ${linked.toLocaleString()} article${linked === 1 ? "" : "s"}` : "";
  return `${kind}${n}`;
}

/** One proposal: a History row, or one of the articles behind an entity's queue row. */
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
  const [showEvidence, setShowEvidence] = useState(false);
  const label =
    hist && row.applied ? (APPLIED_LABEL[row.action] ?? CHANGE_LABEL[row.action] ?? row.action) : (CHANGE_LABEL[row.action] ?? row.action);
  const acts = [...row.actions].sort((a, b) => ACTION_ORDER.indexOf(a) - ACTION_ORDER.indexOf(b));
  const entityMenu = !sub && row.entity_type && row.entity_id && !NO_ENTITY_MENU.has(row.entity_type);
  const span = hist ? 6 : 7;
  const evidence = (
    <button className={cg.expand} onClick={() => setShowEvidence((v) => !v)}>
      {showEvidence ? "▾ hide evidence" : "▸ evidence"}
    </button>
  );
  const why = (
    <td className={styles.why}>
      <div className={styles.whyBox}>
        {(sub || !row.entity_name) && row.subject && <span className={styles.subject}>{row.subject}</span>}
        {row.reason && <span className={styles.reason}>{row.reason}</span>}
        {row.context && <span className={styles.reason}>“{row.context}”</span>}
        <span className={styles.whyMeta}>
          {whyMeta(row.origin, 1)} · {evidence}
        </span>
      </div>
    </td>
  );
  const actions = (
    <td>
      <div className={hist ? styles.actsHist : styles.acts}>
        {hist && <span />}
        {acts.map((a) => {
          const b = ACTION_BTN[a];
          if (!b) return null;
          return (
            <button key={a} className={`${styles.rowBtn} ${b.cls}`} disabled={busy} onClick={() => onAction(row, a)}>
              {b.label}
            </button>
          );
        })}
        {!sub && (
          entityMenu ? (
            <EntityRowActions
              entityType={row.entity_type as string}
              entityId={row.entity_id as string}
              name={row.entity_name ?? row.subject ?? "entity"}
              disabled={busy}
            />
          ) : (
            <RowMenu items={rowMenuItems(row.links ?? [], navigate)} name={row.subject ?? "this row"} disabled={busy} />
          )
        )}
      </div>
    </td>
  );
  return (
    <>
      <tr className={sub ? cg.subRow : undefined}>
        {hist ? (
          <>
            <td>
              <EntityCell
                entityType={row.entity_type}
                entityId={row.entity_id}
                name={row.entity_name ?? row.subject ?? "(unknown)"}
                meta={entityMeta(row.entity_type, row.entity_id)}
              />
            </td>
            <td className={styles.changeCol}>
              <span className={styles.tag}>{label}</span>
            </td>
            <td className={styles.plain}>{appliedByLabel(row)}</td>
            {why}
            <td className={styles.when} title={formatDateTime(row.when)}>{formatShortDateTime(row.when)}</td>
            {actions}
          </>
        ) : (
          <>
            <td />
            <td className={styles.proposedCol}>
              <span className={styles.tag}>{label}</span>
            </td>
            <td className={styles.plain}>{row.origin ? SOURCE_LABEL[row.origin] : "Unknown"}</td>
            <td className={styles.plain}>{row.confidence ?? "n/a"}</td>
            {why}
            <td className={styles.when} title={formatDateTime(row.when)}>{formatShortDateTime(row.when)}</td>
            {actions}
          </>
        )}
      </tr>
      {showEvidence && (
        <tr className={cg.subRow}>
          <td colSpan={span}>
            <RowEvidencePanel id={row.id} names={row.entity_name ? [row.entity_name] : []} />
          </td>
        </tr>
      )}
    </>
  );
}

/** The articles behind one entity's row: the proposals the filters show. */
function GroupRows({
  group,
  scope,
  busy,
  onAction,
}: {
  group: ReviewGroup;
  scope: ReviewScope;
  busy: boolean;
  onAction: (row: FeedRow, action: string) => void;
}) {
  const feed = useHygieneFeed({
    pending: true,
    action: scope.action,
    domain: scope.domain,
    entity_type: group.entity_type,
    entity_id: group.entity_id ?? undefined,
    limit: 200,
  });
  if (feed.isLoading)
    return (
      <tr className={cg.subRow}>
        <td colSpan={7} className={styles.muted}>
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
          <td colSpan={7} className={styles.muted}>
            Showing the newest {rows.length} of {group.proposals.toLocaleString()}. The row's buttons act on all of them.
          </td>
        </tr>
      )}
    </>
  );
}

/** Every change a queue row proposes, one plain label each. */
function proposedLabels(g: ReviewGroup): string[] {
  const out: string[] = [];
  for (const k of g.kinds) {
    if (RECLASSIFY_KINDS.has(k.action)) continue; // named by its targets below
    if (MERGE_KINDS.has(k.action) && g.merge_into.length) continue;
    if (ALIAS_KINDS.has(k.action) && g.trim_aliases.length) continue;
    out.push(CHANGE_LABEL[k.action] ?? k.action);
  }
  for (const t of g.reclassify_to) out.push(`Reclassify as ${getEntityLabel(t.type).toLowerCase()}`);
  if (g.reclassify_to.length === 0 && g.kinds.some((k) => RECLASSIFY_KINDS.has(k.action))) out.push("Reclassify");
  for (const m of g.merge_into) out.push(`Merge into ${m.name ?? "?"} (${getEntityLabel(m.target_type).toLowerCase()})`);
  if (g.trim_aliases.length) out.push(`Remove alias${g.trim_aliases.length > 1 ? "es" : ""} ${g.trim_aliases.map((a) => `“${a}”`).join(", ")}`);
  return [...new Set(out)];
}

export function ProposalsQueue({
  lens,
}: {
  /** queue: pending proposals with Apply / Dismiss. history: what ran, with Restore. */
  lens: ProposalsLens;
}) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const hist = lens === "history";
  const [actionFilter, setActionFilterRaw] = useState("");
  const [domainFilter, setDomainFilterRaw] = useState<ProposalDomain | "">("");
  const [sort, setSortRaw] = useState<ReviewSort>("newest");
  const [appliedBy, setAppliedByRaw] = useState("");
  const [window_, setWindowRaw] = useState("7d");
  const [search, setSearch] = useState("");
  const q = useDebouncedValue(search, 250);
  const [offset, setOffset] = useState(0);
  // A new filter starts at the first page.
  const setActionFilter = (v: string) => (setActionFilterRaw(v), setOffset(0));
  const setDomainFilter = (v: ProposalDomain | "") => (setDomainFilterRaw(v), setOffset(0));
  const setSort = (v: ReviewSort) => (setSortRaw(v), setOffset(0));
  const setAppliedBy = (v: string) => (setAppliedByRaw(v), setOffset(0));
  const setWindow = (v: string) => (setWindowRaw(v), setOffset(0));
  const [busyRow, setBusyRow] = useState<string | null>(null);
  const [open, setOpen] = useState<Set<string>>(new Set());

  const domain = domainFilter || undefined;
  // What the table shows, and so what every button here acts on.
  const scope: ReviewScope = { q: q || undefined, action: actionFilter || undefined, domain };
  // History's window, fixed per pick so the query key stays put between renders.
  const since = useMemo(() => {
    const hours = WINDOWS.find((w) => w.value === window_)?.hours ?? null;
    return hours === null ? undefined : new Date(Date.now() - hours * 3600 * 1000).toISOString();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [window_]);
  const PAGE = 100;
  const feed = useHygieneFeed(
    {
      mode: "apply",
      action: actionFilter || undefined,
      applied_by: appliedBy || undefined,
      since,
      q: q || undefined,
      limit: PAGE,
      offset,
    },
    { enabled: hist },
  );
  const groups = useReviewGroups({ ...scope, sort, limit: PAGE, offset }, { enabled: !hist });
  useEffect(() => setOffset(0), [q]);
  const total = groups.data?.total ?? 0;
  // A page emptied by its own actions steps back to the last page that has rows.
  useEffect(() => {
    if (!hist && groups.data && offset > 0 && offset >= total) setOffset(Math.max(0, Math.floor((total - 1) / PAGE) * PAGE));
  }, [hist, groups.data, offset, total]);

  const runRowAction = useHygieneRowAction();
  const dismissReview = useDismissReview();
  // A separate mutation instance, so a row's Dismiss doesn't show Dismiss all as busy
  const dismissAll = useDismissReview();
  const applyReview = useApplyReview();
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
      invalidateAfterReview(qc);
      setBulkJobId(null);
    } else if (bulkProgress.status === "error") {
      toast.error(`Apply all stopped: ${bulkProgress.message ?? "unknown error"}`);
      invalidateAfterReview(qc);
      setBulkJobId(null);
    }
  }, [bulkJobId, bulkProgress, qc]);
  // While a job runs, keep the table moving with it.
  useEffect(() => {
    if (bulkJobId && bulkProgress?.status === "running") groups.refetch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bulkProgress?.processed]);

  const scanNames = useRunNameNormalization();
  const scanAliases = useScanAliasHygiene();
  const scanIds = useScanIdHygiene();
  const scanVendors = useScanVendorAutolink();
  const scanDupes = useScanDuplicates();

  // Scans that add new entity proposals to the queue (link verdicts come from the adjudicate stage at ingest, so there is nothing to scan for).
  const scans = [
    {
      label: "Review duplicates (AI)",
      title:
        "Sends the most likely duplicate pairs of actors, malware and tools to the AI worker. Each pair the model judges to be the same entity is filed here as a Merge proposal. Also runs daily.",
      busy: scanDupes.isPending,
      run: () =>
        scanDupes
          .mutateAsync()
          .then((r) =>
            r.dispatched
              ? toast.success("Duplicate review started on the AI worker. Merge rows appear as it finishes.")
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
          .then((r) => toast.success(`Proposed ${r.proposed ?? 0} alias removals`))
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
  // The people History knows, kept from the last answer so the select doesn't flicker.
  const [people, setPeople] = useState<{ id: string; name: string }[]>([]);
  useEffect(() => {
    if (feed.data?.people) setPeople(feed.data.people);
  }, [feed.data?.people]);

  const FILTERS = hist ? HISTORY_FILTERS : QUEUE_FILTERS;
  const scopeLabel = () => {
    const what = actionFilter
      ? (FILTERS.find((f) => f.value === actionFilter)?.label ?? "these").toLowerCase()
      : "every pending";
    const where = domainFilter ? ` ${DOMAIN_LABELS[domainFilter].toLowerCase()}` : "";
    const named = q ? ` matching “${q}”` : "";
    return `${what}${where}${named}`;
  };

  const doRow = async (row: FeedRow, action: string) => {
    setBusyRow(row.id);
    try {
      await runRowAction(row, action);
    } finally {
      setBusyRow(null);
    }
  };

  const groupRef = (g: ReviewGroup) => ({ entity_type: g.entity_type, entity_id: g.entity_id, row_ids: g.row_ids });

  /** Apply what this row shows under the filters, except its type changes (those go through Convert). One server loop, one toast. */
  const applyGroup = async (g: ReviewGroup) => {
    setBusyRow(g.key);
    try {
      const r = await applyReview.mutateAsync({ ...scope, items: [groupRef(g)] });
      const parts = [`Applied ${r.applied.toLocaleString()}`];
      if (r.skipped) parts.push(`${r.skipped.toLocaleString()} skipped`);
      if (r.failed) parts.push(`${r.failed.toLocaleString()} failed`);
      if (r.failed) toast.warning(parts.join(", "), { description: r.errors[0]?.error });
      else toast.success(parts.join(", "));
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
      if (r.failed) toast.error(`Convert failed: ${r.errors[0]?.error ?? "unknown error"}`);
      else toast.success(`Converted ${g.name} to ${getEntityLabel(target).toLowerCase()} · ${r.cleared_rows.toLocaleString()} proposals settled`);
    } catch (e) {
      toast.error(`Convert failed: ${(e as Error).message}`);
    } finally {
      setBusyRow(null);
    }
  };

  const dismissGroup = async (g: ReviewGroup) => {
    setBusyRow(g.key);
    try {
      const r = await dismissReview.mutateAsync({ ...scope, items: [groupRef(g)] });
      toast.success(`Dismissed ${r.cleared_rows.toLocaleString()} proposal${r.cleared_rows === 1 ? "" : "s"}${g.entity_id ? ` about ${g.name}` : ""}`);
    } catch (e) {
      toast.error(`Dismiss failed: ${(e as Error).message}`);
    } finally {
      setBusyRow(null);
    }
  };

  // What the table shows: the action and domain filters and the search.
  const clearAll = async () => {
    if (
      !(await confirmDialog({
        title: "Dismiss proposals",
        message: `Dismiss ${scopeLabel()} proposals without applying them? Entities and links are untouched, and the adjudicator will not file these verdicts for these articles again.`,
        confirmLabel: "Dismiss",
        destructive: true,
      }))
    )
      return;
    try {
      const r = await dismissAll.mutateAsync(scope);
      toast.success(`Dismissed ${r.cleared_rows.toLocaleString()} proposal${r.cleared_rows === 1 ? "" : "s"}`);
    } catch (e) {
      toast.error(`Dismiss failed: ${(e as Error).message}`);
    }
  };

  // Every proposal the table shows, through the same code a row's Apply uses, as a background job. Type changes go to their proposed type; assessments are notes and never apply.
  const applyAll = async () => {
    if (
      !(await confirmDialog({
        title: "Apply proposals",
        message: `Apply ${scopeLabel()} proposals now? Each one is applied the way the stage would in Applied mode (type changes to their proposed type), and each can be undone from History. This runs in the background and the queue updates as it goes.`,
        confirmLabel: "Apply all",
        destructive: true,
      }))
    )
      return;
    try {
      const job = await startBulkApply.mutateAsync(scope);
      setBulkJobId(job.job_id);
      if (job.total === 0) toast.message("Nothing here can be applied: assessments are notes only");
      else toast.info(`Applying ${job.total.toLocaleString()} proposal${job.total === 1 ? "" : "s"} in the background`);
    } catch (e) {
      toast.error(`Apply failed: ${(e as Error).message}`);
    }
  };

  const bulkLabel = bulkRunning
    ? bulkProgress && bulkProgress.total > 0
      ? `Applying ${bulkProgress.processed.toLocaleString()} / ${bulkProgress.total.toLocaleString()}…`
      : "Applying…"
    : "Apply all";
  const byDomain = groups.data?.facets.domains ?? {};
  const pendingTotal = groups.data?.proposals ?? 0;
  const allCount = PROPOSAL_DOMAINS.reduce((n, d) => n + (byDomain[d] ?? 0), 0);

  /** The primary button of a queue row, from what its proposals want. */
  const primaryLabel = (g: ReviewGroup) => {
    const kinds = g.kinds.filter((k) => !RECLASSIFY_KINDS.has(k.action) && k.action !== "adjudication_assessment").map((k) => k.action);
    if (kinds.length === 0) return null;
    if (kinds.every((k) => UNLINK_KINDS.has(k))) return "Remove links";
    if (kinds.every((k) => k === "adjudication_held_link")) return "Link";
    if (kinds.every((k) => k === "adjudication_ioc_capture")) return "Capture";
    if (kinds.length === 1 && kinds[0] === "adjudication_merge") return "Merge";
    if (kinds.length === 1 && kinds[0] === "adjudication_veto") return "Delete";
    return "Apply";
  };

  return (
    <div className={styles.wrap}>
      {/* one filter row */}
      <div className={styles.toolbar}>
        {!hist && (
          <span className={styles.seg} title="What applying the proposal changes">
            <button className={domainFilter === "" ? styles.segOn : ""} onClick={() => setDomainFilter("")}>
              All{allCount ? <span className={styles.segCnt}>{allCount.toLocaleString()}</span> : null}
            </button>
            {PROPOSAL_DOMAINS.map((d) => (
              <button key={d} className={domainFilter === d ? styles.segOn : ""} onClick={() => setDomainFilter(d)}>
                {DOMAIN_LABELS[d]}
                {byDomain[d] ? <span className={styles.segCnt}>{byDomain[d]?.toLocaleString()}</span> : null}
              </button>
            ))}
          </span>
        )}

        <select className={styles.sel} aria-label="Change" value={actionFilter} onChange={(e) => setActionFilter(e.target.value)}>
          {FILTERS.map((f) => (
            <option key={f.value || "all"} value={f.value}>
              {f.label}
            </option>
          ))}
        </select>

        {hist ? (
          <>
            <select className={styles.sel} aria-label="Applied by" value={appliedBy} onChange={(e) => setAppliedBy(e.target.value)}>
              <option value="">Anyone</option>
              <option value="adjudicator">Adjudicator</option>
              <option value="merge_review">Duplicate review</option>
              {people.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
            <select className={styles.sel} aria-label="Time window" value={window_} onChange={(e) => setWindow(e.target.value)}>
              {WINDOWS.map((w) => (
                <option key={w.value} value={w.value}>
                  {w.label}
                </option>
              ))}
            </select>
          </>
        ) : (
          <select className={styles.sel} aria-label="Sort" value={sort} onChange={(e) => setSort(e.target.value as ReviewSort)}>
            {SORTS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        )}

        <label className={styles.search}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
            <circle cx="11" cy="11" r="7" />
            <path d="M20 20l-3.5-3.5" />
          </svg>
          <input aria-label="Find an entity" placeholder="Find an entity…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>

        <span className={styles.grow} />

        {!hist && (
          <>
            <ToolbarDropdown
              label="Run scan"
              triggerClassName={`${styles.btn} ${styles.btnGhost}`}
              title="Scans that file fresh proposals into this queue"
            >
              {scans.map((s) => (
                <DropdownItem
                  key={s.label}
                  label={s.busy ? `${s.label} (working…)` : s.label}
                  title={s.title}
                  disabled={s.busy}
                  onClick={s.run}
                />
              ))}
            </ToolbarDropdown>
            <button
              className={styles.btn}
              disabled={bulkRunning || pendingTotal === 0}
              title="Apply every proposal the table shows, in the background, the same way a row's Apply does"
              onClick={applyAll}
            >
              {bulkLabel}
            </button>
            <button
              className={styles.btnDanger}
              disabled={dismissAll.isPending || bulkRunning || pendingTotal === 0}
              title="Dismiss every proposal the table shows"
              onClick={clearAll}
            >
              {dismissAll.isPending ? "Clearing…" : "Dismiss all"}
            </button>
          </>
        )}
      </div>

      {/* table */}
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            {hist ? (
              <tr>
                <th>Entity</th>
                <th className={styles.changeCol}>Change</th>
                <th>Applied by</th>
                <th>Why</th>
                <th>When</th>
                <th className={styles.actCol} />
              </tr>
            ) : (
              <tr>
                <th>Entity</th>
                <th className={styles.proposedCol}>Proposed</th>
                <th>Source</th>
                <th>Confidence</th>
                <th>Why</th>
                <th>Latest</th>
                <th className={styles.actCol} />
              </tr>
            )}
          </thead>
          <tbody>
            {hist && rows.map((row) => <ProposalRow key={row.id} row={row} hist busy={busyRow === row.id} onAction={doRow} />)}
            {!hist &&
              groupRows.map((g) => {
                const k = g.key;
                const busy = busyRow === k;
                const isOpen = open.has(k);
                const label = primaryLabel(g);
                // Every row opens to its newest proposal's evidence; one with several proposals also lists them.
                const manyRows = g.entity_id !== null && g.proposals > 1;
                const expandable = manyRows || g.latest_row_id !== null;
                const convertTargets = g.entity_id ? g.reclassify_to : [];
                const entityMenu = !!g.entity_id && !NO_ENTITY_MENU.has(g.entity_type);
                const toggle = () => {
                  const next = new Set(open);
                  if (next.has(k)) next.delete(k);
                  else next.add(k);
                  setOpen(next);
                };
                return (
                  <Fragment key={k}>
                    <tr>
                      <td>
                        <EntityCell
                          entityType={g.entity_type}
                          entityId={g.entity_id}
                          name={g.name || g.entity_type}
                          meta={entityMeta(g.entity_type, g.entity_id, g.linked)}
                        />
                      </td>
                      <td className={styles.proposedCol}>
                        <div className={cg.chips}>
                          {proposedLabels(g).map((text) => (
                            <span key={text} className={styles.tag}>
                              {text}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className={styles.plain}>{SOURCE_LABEL[g.origin] ?? "Unknown"}</td>
                      <td className={styles.plain}>{g.confidence ?? "n/a"}</td>
                      <td className={styles.why}>
                        <div className={styles.whyBox}>
                          {!entityMenu && g.subject && <span className={styles.subject}>{g.subject}</span>}
                          {g.reason && <span className={styles.reason}>{g.reason}</span>}
                          <span className={styles.whyMeta}>
                            {whyMeta(g.origin, g.proposals)}
                            {expandable && (
                              <>
                                {" · "}
                                <button className={cg.expand} onClick={toggle}>
                                  {isOpen ? "▾ hide evidence" : manyRows ? "▸ evidence and the articles" : "▸ evidence"}
                                </button>
                              </>
                            )}
                          </span>
                        </div>
                      </td>
                      <td className={styles.when} title={formatDateTime(g.latest_at)}>{formatShortDateTime(g.latest_at)}</td>
                      <td>
                        <div className={styles.acts}>
                          {convertTargets.length > 1 ? (
                            <ToolbarDropdown
                              label="Convert"
                              triggerClassName={`${styles.rowBtn} ${styles.bGood}`}
                              title="The articles disagree on the type. Pick one and every article's proposal is settled at once."
                            >
                              {convertTargets.map((t) => (
                                <DropdownItem
                                  key={t.type}
                                  label={`${getEntityLabel(t.type)} · ${t.count.toLocaleString()} article${t.count === 1 ? "" : "s"}`}
                                  disabled={busy || bulkRunning}
                                  onClick={() => void reclassifyGroup(g, t.type)}
                                />
                              ))}
                            </ToolbarDropdown>
                          ) : convertTargets.length === 1 ? (
                            <button
                              className={`${styles.rowBtn} ${styles.bGood}`}
                              disabled={busy || bulkRunning}
                              onClick={() => reclassifyGroup(g, convertTargets[0].type)}
                              title={`Convert ${g.name} to a ${getEntityLabel(convertTargets[0].type).toLowerCase()}. Every article's proposal is settled at once.`}
                            >
                              Convert
                            </button>
                          ) : label ? (
                            <button
                              className={`${styles.rowBtn} ${label === "Remove links" || label === "Delete" ? styles.bWarn : styles.bGood}`}
                              disabled={busy || bulkRunning}
                              onClick={() => applyGroup(g)}
                              title="Apply what this row shows under the filters"
                            >
                              {label}
                            </button>
                          ) : (
                            <span />
                          )}
                          <button
                            className={`${styles.rowBtn} ${styles.bGhost}`}
                            disabled={busy || bulkRunning}
                            onClick={() => dismissGroup(g)}
                            title={
                              g.entity_id
                                ? "Leave it as it is and clear what this row shows under the filters. The adjudicator will not file these verdicts for these articles again. A dismissed type change is not proposed again, but a scan can propose its fix again."
                                : "Drop this proposal. The adjudicator will not file it for this article again."
                            }
                          >
                            Dismiss
                          </button>
                          {entityMenu ? (
                            <EntityRowActions entityType={g.entity_type} entityId={g.entity_id as string} name={g.name} disabled={busy} />
                          ) : (
                            <RowMenu items={rowMenuItems(g.links, navigate)} name={g.name || g.subject || "this row"} disabled={busy} />
                          )}
                        </div>
                      </td>
                    </tr>
                    {isOpen && g.latest_row_id && (
                      <tr className={cg.subRow}>
                        <td colSpan={7}>
                          <RowEvidencePanel id={g.latest_row_id} names={[g.name, ...g.matched_names]} />
                        </td>
                      </tr>
                    )}
                    {isOpen && manyRows && <GroupRows group={g} scope={scope} busy={busy} onAction={doRow} />}
                  </Fragment>
                );
              })}
            {!hist && !groups.isLoading && groupRows.length === 0 && (
              <tr>
                <td colSpan={7} className={styles.empty}>
                  {q ? "No pending proposals match." : "No pending proposals. Run scan can file more."}
                </td>
              </tr>
            )}
            {hist && !feed.isLoading && rows.length === 0 && (
              <tr>
                <td colSpan={6} className={styles.empty}>
                  No applied changes match.
                </td>
              </tr>
            )}
            {(hist ? feed.isLoading : groups.isLoading) && (
              <tr>
                <td colSpan={7} className={styles.empty}>
                  Loading {hist ? "history" : "proposals"}…
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {!hist && (total > PAGE || offset > 0) && (
        <div className={cg.pager}>
          <button className={styles.rowBtn} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
            ← Prev
          </button>
          <span className={styles.muted}>
            {Math.min(offset + 1, total)}–{Math.min(offset + PAGE, total)} of {total.toLocaleString()} entities
          </span>
          <button className={styles.rowBtn} disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)}>
            Next →
          </button>
        </div>
      )}
      {hist && (feed.data?.has_more || offset > 0) && (
        <div className={cg.pager}>
          <button className={styles.rowBtn} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
            ← Newer
          </button>
          <span className={styles.muted}>
            {(offset + 1).toLocaleString()}–{(offset + rows.length).toLocaleString()}
          </span>
          <button className={styles.rowBtn} disabled={!feed.data?.has_more} onClick={() => setOffset(offset + PAGE)}>
            Older →
          </button>
        </div>
      )}
    </div>
  );
}
