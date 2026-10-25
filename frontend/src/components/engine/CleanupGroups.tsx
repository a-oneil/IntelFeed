/**
 * CleanupGroups — the Engine console's per-entity cleanup queues.
 *
 * Both queues hold one decision per entity that the backend files once per
 * article: a reclassify proposal ("Linux Kernel: tool → product", ×626) and a
 * held autolink match ("Royal" in nine articles). Each row is the entity; its
 * buttons settle every article's copy at once.
 *
 *  - ReclassifyQueue: pick the target type (or dismiss for good).
 *  - UnlinkQueue:     remove the links the review flagged, or keep them.
 *  - HeldLinksQueue:  link the held matches or reject them, all or per article;
 *    rejecting a whole entity offers to stop matching the word for good.
 */

import { Fragment, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { usePendingMatches, useResolvePending, type PendingMatchGroup } from "@/hooks/useAutolinking";
import { useAddAutolinkName } from "@/hooks/useEngine";
import {
  useApplyReclassifyGroups,
  useDismissReclassifyGroups,
  useReclassifyGroups,
  useUnlinkAction,
  useUnlinkGroups,
  useUnlinkRows,
  type ReclassifyGroup,
  type UnlinkGroup,
} from "@/hooks/useHygiene";
import { confirmDialog } from "@/utils/dialog";
import { getEntityCssVar, getEntityLabel } from "@/utils/entityTheme";
import { formatDateTime } from "@/utils/formatDate";

import styles from "./ProposalsQueue.module.css";
import cg from "./CleanupGroups.module.css";

const PAGE = 100;
const RECLASSIFY_TYPES = ["threat_actor", "malware", "tool", "vendor", "product", "country"];

const keyOf = (g: { entity_type: string; entity_id: string }) => `${g.entity_type}:${g.entity_id}`;

function EntityCell({ type, id, name, gone }: { type: string; id: string; name: string; gone?: boolean }) {
  const navigate = useNavigate();
  return (
    <button
      className={styles.ent}
      disabled={gone}
      onClick={() => navigate(`/workbench/${type}/${id}`)}
      title={gone ? "Already deleted or converted" : getEntityLabel(type)}
    >
      <span className={styles.entDot} style={{ background: getEntityCssVar(type) }} />
      {name}
      {gone && <span className={cg.gone}>gone</span>}
    </button>
  );
}

function SelectAll({ keys, selected, setSelected }: { keys: string[]; selected: Set<string>; setSelected: (s: Set<string>) => void }) {
  const all = keys.length > 0 && keys.every((k) => selected.has(k));
  return (
    <input
      type="checkbox"
      aria-label="Select all on this page"
      checked={all}
      onChange={() => setSelected(all ? new Set() : new Set(keys))}
    />
  );
}

function Pager({ offset, total, setOffset }: { offset: number; total: number; setOffset: (n: number) => void }) {
  if (total <= PAGE) return null;
  return (
    <div className={cg.pager}>
      <button className={styles.rowBtn} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
        ← Prev
      </button>
      <span className={styles.muted}>
        {offset + 1}–{Math.min(offset + PAGE, total)} of {total.toLocaleString()}
      </span>
      <button className={styles.rowBtn} disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)}>
        Next →
      </button>
    </div>
  );
}

// ─── Reclassify ────────────────────────────────────────────────────────────

export function ReclassifyQueue() {
  const [search, setSearch] = useState("");
  const q = useDebouncedValue(search, 250);
  const [typeFilter, setTypeFilter] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState<string | null>(null);

  const groups = useReclassifyGroups({ q: q || undefined, entity_type: typeFilter || undefined, limit: PAGE, offset });
  const apply = useApplyReclassifyGroups();
  const dismiss = useDismissReclassifyGroups();
  const rows = useMemo(() => groups.data?.groups ?? [], [groups.data]);
  const total = groups.data?.total ?? 0;
  const picked = rows.filter((g) => selected.has(keyOf(g)));

  const report = (verb: string, r: { entities: number; cleared_rows: number; failed: number; errors: { error: string }[] }) => {
    const msg = `${verb} ${r.entities} entit${r.entities === 1 ? "y" : "ies"} · ${r.cleared_rows.toLocaleString()} proposal${r.cleared_rows === 1 ? "" : "s"} cleared`;
    if (r.failed) toast.warning(`${msg} · ${r.failed} failed`, { description: r.errors[0]?.error });
    else toast.success(msg);
  };

  const applyOne = async (g: ReclassifyGroup, target: string) => {
    setBusy(keyOf(g));
    try {
      report("Reclassified", await apply.mutateAsync([{ entity_type: g.entity_type, entity_id: g.entity_id, target_type: target }]));
    } catch (e) {
      toast.error(`Apply failed: ${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  };
  const dismissOne = async (g: ReclassifyGroup) => {
    setBusy(keyOf(g));
    try {
      report("Dismissed", await dismiss.mutateAsync([{ entity_type: g.entity_type, entity_id: g.entity_id }]));
    } catch (e) {
      toast.error(`Dismiss failed: ${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  };

  const applySelected = async () => {
    const conflicted = picked.filter((g) => g.suggestions.length > 1).length;
    if (
      !(await confirmDialog({
        title: "Apply reclassifies",
        message: `Convert ${picked.length} entit${picked.length === 1 ? "y" : "ies"} to their most-proposed type?${
          conflicted ? ` ${conflicted} of them have more than one proposed type; the top one wins.` : ""
        }`,
        confirmLabel: "Apply",
      }))
    )
      return;
    try {
      report(
        "Reclassified",
        await apply.mutateAsync(
          picked.map((g) => ({ entity_type: g.entity_type, entity_id: g.entity_id, target_type: g.suggestions[0]?.type })),
        ),
      );
      setSelected(new Set());
    } catch (e) {
      toast.error(`Apply failed: ${(e as Error).message}`);
    }
  };
  const dismissSelected = async () => {
    if (
      !(await confirmDialog({
        title: "Dismiss reclassifies",
        message: `Dismiss every proposal for ${picked.length} entit${picked.length === 1 ? "y" : "ies"}? They won't be proposed again.`,
        confirmLabel: "Dismiss",
        destructive: true,
      }))
    )
      return;
    try {
      report("Dismissed", await dismiss.mutateAsync(picked.map((g) => ({ entity_type: g.entity_type, entity_id: g.entity_id }))));
      setSelected(new Set());
    } catch (e) {
      toast.error(`Dismiss failed: ${(e as Error).message}`);
    }
  };

  const working = apply.isPending || dismiss.isPending;

  return (
    <div className={styles.wrap}>
      <div className={styles.toolbar}>
        <span className={styles.system}>Reclassify</span>
        <input
          className={cg.search}
          placeholder="Find an entity…"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setOffset(0);
          }}
        />
        <label className={styles.facetLabel}>
          Now a
          <select
            className={styles.sel}
            value={typeFilter}
            onChange={(e) => {
              setTypeFilter(e.target.value);
              setOffset(0);
            }}
          >
            <option value="">any type</option>
            {RECLASSIFY_TYPES.map((t) => (
              <option key={t} value={t}>
                {getEntityLabel(t).toLowerCase()}
              </option>
            ))}
          </select>
        </label>
        <span className={styles.grow} />
        {picked.length > 0 && (
          <>
            <span className={styles.muted}>{picked.length} selected</span>
            <button className={`${styles.rowBtn} ${styles.bGood}`} disabled={working} onClick={applySelected}>
              Apply top suggestion
            </button>
            <button className={`${styles.rowBtn} ${styles.bGhost}`} disabled={working} onClick={dismissSelected}>
              Dismiss
            </button>
          </>
        )}
      </div>
      <p className={styles.note}>
        One row per entity — the analysis files a proposal for every article that mentions it. Click a proposed type to
        convert the entity; Dismiss clears every proposal and stops new ones.
      </p>

      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th className={cg.chk}>
                <SelectAll keys={rows.map(keyOf)} selected={selected} setSelected={setSelected} />
              </th>
              <th>Entity</th>
              <th>Now</th>
              <th>Convert to</th>
              <th>Why</th>
              <th className={styles.actCol} />
            </tr>
          </thead>
          <tbody>
            {rows.map((g) => {
              const k = keyOf(g);
              return (
                <tr key={k}>
                  <td className={cg.chk}>
                    <input
                      type="checkbox"
                      aria-label={`Select ${g.name}`}
                      checked={selected.has(k)}
                      onChange={() => {
                        const next = new Set(selected);
                        if (next.has(k)) next.delete(k);
                        else next.add(k);
                        setSelected(next);
                      }}
                    />
                  </td>
                  <td>
                    <EntityCell type={g.entity_type} id={g.entity_id} name={g.name} gone={!g.exists} />
                  </td>
                  <td className={styles.muted}>{getEntityLabel(g.entity_type)}</td>
                  <td>
                    <div className={cg.chips}>
                      {g.exists ? (
                        g.suggestions.map((s) => (
                          <button
                            key={s.type}
                            className={cg.target}
                            disabled={busy === k || working}
                            onClick={() => applyOne(g, s.type)}
                            title={`Convert ${g.name} to a ${getEntityLabel(s.type).toLowerCase()} — proposed by ${s.count} article${s.count === 1 ? "" : "s"}`}
                          >
                            <span className={styles.entDot} style={{ background: getEntityCssVar(s.type) }} />
                            {getEntityLabel(s.type)}
                            <span className={cg.cnt}>{s.count.toLocaleString()}</span>
                          </button>
                        ))
                      ) : (
                        <span className={styles.muted}>entity is gone</span>
                      )}
                    </div>
                  </td>
                  <td className={styles.detail}>
                    {g.reason && <span className={styles.reason}>{g.reason}</span>}
                    <span className={cg.meta}>
                      {g.proposals.toLocaleString()} proposal{g.proposals === 1 ? "" : "s"} · latest {formatDateTime(g.latest_at)}
                      {g.sample_entry_id && (
                        <>
                          {" · "}
                          <a className={styles.linkChip} href={`/?entry=${g.sample_entry_id}`}>
                            example article
                          </a>
                        </>
                      )}
                    </span>
                  </td>
                  <td>
                    <div className={styles.acts}>
                      <button
                        className={`${styles.rowBtn} ${g.exists ? styles.bGhost : styles.bGood}`}
                        disabled={busy === k || working}
                        onClick={() => dismissOne(g)}
                        title={g.exists ? "Keep it as it is — clear every proposal and stop new ones" : "Clear the leftover proposals"}
                      >
                        {g.exists ? "Dismiss" : "Clear"}
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {!groups.isLoading && rows.length === 0 && (
              <tr>
                <td colSpan={6} className={styles.empty}>
                  {q || typeFilter ? "No reclassify proposals match." : "No reclassify proposals — nothing waiting."}
                </td>
              </tr>
            )}
            {groups.isLoading && (
              <tr>
                <td colSpan={6} className={styles.empty}>
                  Loading…
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <Pager offset={offset} total={total} setOffset={setOffset} />
    </div>
  );
}

// ─── Held links ────────────────────────────────────────────────────────────

export function HeldLinksQueue() {
  const [search, setSearch] = useState("");
  const q = useDebouncedValue(search, 250);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState<string | null>(null);
  const pending = usePendingMatches(q);
  const resolve = useResolvePending();
  const blockWord = useAddAutolinkName("blocked");
  const rows = useMemo(() => pending.data?.groups ?? [], [pending.data]);
  const picked = rows.filter((g) => selected.has(keyOf(g)));

  const say = (r: { promoted: number; rejected: number }) =>
    toast.success(
      r.promoted
        ? `Linked ${r.promoted} article${r.promoted === 1 ? "" : "s"}`
        : `Rejected ${r.rejected} match${r.rejected === 1 ? "" : "es"}`,
    );

  // After rejecting a whole entity, offer to stop the word matching at all —
  // otherwise the next article that uses it is held all over again.
  const offerBlock = (g: PendingMatchGroup) => {
    const form = [...new Set(g.entries.flatMap((e) => e.matched_names))][0] ?? g.name;
    toast(`Rejected every held "${form}" match`, {
      description: `Never match "${form}" again, for any entity?`,
      duration: 10000,
      action: {
        label: "Never match",
        onClick: () =>
          blockWord
            .mutateAsync(form)
            .then(() => toast.success(`"${form}" won't be matched again`))
            .catch((e) => toast.error(`Failed: ${(e as Error).message}`)),
      },
    });
  };

  const resolveGroup = async (g: PendingMatchGroup, resolution: "promote" | "reject") => {
    setBusy(keyOf(g));
    try {
      const r = await resolve.mutateAsync({ resolution, entity_type: g.entity_type, entity_id: g.entity_id });
      if (resolution === "reject") offerBlock(g);
      else say(r);
    } catch (e) {
      toast.error(`Failed: ${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  };
  const resolveRow = async (id: string, resolution: "promote" | "reject") => {
    setBusy(id);
    try {
      say(await resolve.mutateAsync({ resolution, ids: [id] }));
    } catch (e) {
      toast.error(`Failed: ${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  };
  const resolveSelected = async (resolution: "promote" | "reject") => {
    const n = picked.reduce((a, g) => a + g.count, 0);
    if (
      !(await confirmDialog({
        title: resolution === "promote" ? "Link held matches" : "Reject held matches",
        message: `${resolution === "promote" ? "Link" : "Reject"} ${n} held match${n === 1 ? "" : "es"} across ${picked.length} entit${picked.length === 1 ? "y" : "ies"}?`,
        confirmLabel: resolution === "promote" ? "Link" : "Reject",
        destructive: resolution === "reject",
      }))
    )
      return;
    let promoted = 0;
    let rejected = 0;
    try {
      for (const g of picked) {
        const r = await resolve.mutateAsync({ resolution, entity_type: g.entity_type, entity_id: g.entity_id });
        promoted += r.promoted;
        rejected += r.rejected;
      }
      say({ promoted, rejected });
      setSelected(new Set());
    } catch (e) {
      toast.error(`Failed: ${(e as Error).message}`);
    }
  };

  return (
    <div className={styles.wrap}>
      <div className={styles.toolbar}>
        <span className={styles.system}>Held links</span>
        <input className={cg.search} placeholder="Find an entity or article…" value={search} onChange={(e) => setSearch(e.target.value)} />
        {pending.data && (
          <span className={styles.muted}>
            {pending.data.total_matches.toLocaleString()} match{pending.data.total_matches === 1 ? "" : "es"} · {rows.length} entit
            {rows.length === 1 ? "y" : "ies"}
          </span>
        )}
        <span className={styles.grow} />
        {picked.length > 0 && (
          <>
            <span className={styles.muted}>{picked.length} selected</span>
            <button className={`${styles.rowBtn} ${styles.bGood}`} disabled={resolve.isPending} onClick={() => resolveSelected("promote")}>
              Link all
            </button>
            <button className={`${styles.rowBtn} ${styles.bGhost}`} disabled={resolve.isPending} onClick={() => resolveSelected("reject")}>
              Reject all
            </button>
          </>
        )}
      </div>
      <p className={styles.note}>
        Names that are also ordinary words ("Royal", "Session", "Canada"), held out of the graph until the AI or you confirm
        them. Expand a row to judge article by article.
      </p>

      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th className={cg.chk}>
                <SelectAll keys={rows.map(keyOf)} selected={selected} setSelected={setSelected} />
              </th>
              <th>Entity</th>
              <th>Type</th>
              <th>Held in</th>
              <th>Matched as</th>
              <th className={styles.actCol} />
            </tr>
          </thead>
          <tbody>
            {rows.map((g) => {
              const k = keyOf(g);
              const expanded = open.has(k);
              const forms = [...new Set(g.entries.flatMap((e) => e.matched_names))].slice(0, 4);
              return (
                <Fragment key={k}>
                  <tr>
                    <td className={cg.chk}>
                      <input
                        type="checkbox"
                        aria-label={`Select ${g.name}`}
                        checked={selected.has(k)}
                        onChange={() => {
                          const next = new Set(selected);
                          if (next.has(k)) next.delete(k);
                          else next.add(k);
                          setSelected(next);
                        }}
                      />
                    </td>
                    <td>
                      <EntityCell type={g.entity_type} id={g.entity_id} name={g.name} />
                    </td>
                    <td className={styles.muted}>{getEntityLabel(g.entity_type)}</td>
                    <td>
                      <button
                        className={cg.expand}
                        aria-expanded={expanded}
                        onClick={() => {
                          const next = new Set(open);
                          if (next.has(k)) next.delete(k);
                          else next.add(k);
                          setOpen(next);
                        }}
                      >
                        {expanded ? "▾" : "▸"} {g.count} article{g.count === 1 ? "" : "s"}
                        {g.high > 0 && <span className={cg.cnt}>{g.high} high</span>}
                      </button>
                    </td>
                    <td className={styles.muted}>{forms.join(", ") || "—"}</td>
                    <td>
                      <div className={styles.acts}>
                        <button
                          className={`${styles.rowBtn} ${styles.bGood}`}
                          disabled={busy === k || resolve.isPending}
                          onClick={() => resolveGroup(g, "promote")}
                        >
                          Link all
                        </button>
                        <button
                          className={`${styles.rowBtn} ${styles.bGhost}`}
                          disabled={busy === k || resolve.isPending}
                          onClick={() => resolveGroup(g, "reject")}
                        >
                          Reject all
                        </button>
                      </div>
                    </td>
                  </tr>
                  {expanded &&
                    g.entries.map((e) => (
                      <tr key={e.id} className={cg.subRow}>
                        <td />
                        <td colSpan={3}>
                          <a className={cg.article} href={`/?entry=${e.entry_id}`}>
                            {e.entry_title}
                          </a>
                          {e.published_at && <span className={cg.meta}> · {formatDateTime(e.published_at)}</span>}
                        </td>
                        <td className={styles.muted}>
                          {e.matched_names.join(", ")}
                          {e.confidence && <span className={cg.cnt}>{e.confidence}</span>}
                        </td>
                        <td>
                          <div className={styles.acts}>
                            <button
                              className={`${styles.rowBtn} ${styles.bGood}`}
                              disabled={busy === e.id || resolve.isPending}
                              onClick={() => resolveRow(e.id, "promote")}
                            >
                              Link
                            </button>
                            <button
                              className={`${styles.rowBtn} ${styles.bGhost}`}
                              disabled={busy === e.id || resolve.isPending}
                              onClick={() => resolveRow(e.id, "reject")}
                            >
                              Reject
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                </Fragment>
              );
            })}
            {!pending.isLoading && rows.length === 0 && (
              <tr>
                <td colSpan={6} className={styles.empty}>
                  {q ? "No held links match." : "No held links — every match has been confirmed or rejected."}
                </td>
              </tr>
            )}
            {pending.isLoading && (
              <tr>
                <td colSpan={6} className={styles.empty}>
                  Loading…
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Remove links ──────────────────────────────────────────────────────────

function UnlinkArticles({ group, disabled, act }: { group: UnlinkGroup; disabled: boolean; act: (a: "apply" | "keep", ids: string[]) => void }) {
  const rows = useUnlinkRows(group);
  if (rows.isLoading)
    return (
      <tr className={cg.subRow}>
        <td />
        <td colSpan={5} className={styles.muted}>
          Loading articles…
        </td>
      </tr>
    );
  return (
    <>
      {(rows.data ?? []).map((r) => (
        <tr key={r.id} className={cg.subRow}>
          <td />
          <td colSpan={2}>
            {r.entry_id ? (
              <a className={cg.article} href={`/?entry=${r.entry_id}`}>
                {r.entry_title ?? "(untitled)"}
              </a>
            ) : (
              <span className={styles.muted}>article gone</span>
            )}
            <span className={cg.meta}> · {formatDateTime(r.created_at)}</span>
          </td>
          <td className={styles.muted}>{r.matched_names.join(", ") || "—"}</td>
          <td className={styles.detail}>{r.reason && <span className={styles.reason}>{r.reason}</span>}</td>
          <td>
            <div className={styles.acts}>
              <button className={`${styles.rowBtn} ${styles.bWarn}`} disabled={disabled} onClick={() => act("apply", [r.id])}>
                Remove
              </button>
              <button className={`${styles.rowBtn} ${styles.bGhost}`} disabled={disabled} onClick={() => act("keep", [r.id])}>
                Keep
              </button>
            </div>
          </td>
        </tr>
      ))}
    </>
  );
}

export function UnlinkQueue() {
  const [search, setSearch] = useState("");
  const q = useDebouncedValue(search, 250);
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState<string | null>(null);
  const groups = useUnlinkGroups({ q: q || undefined, limit: PAGE, offset });
  const unlink = useUnlinkAction();
  const rows = useMemo(() => groups.data?.groups ?? [], [groups.data]);
  const total = groups.data?.total ?? 0;
  const picked = rows.filter((g) => selected.has(keyOf(g)));

  const run = async (busyKey: string, action: "apply" | "keep", target: Parameters<typeof unlink.mutateAsync>[0]["target"]) => {
    setBusy(busyKey);
    try {
      const r = await unlink.mutateAsync({ action, target });
      const msg =
        action === "apply"
          ? `Removed ${r.done.toLocaleString()} link${r.done === 1 ? "" : "s"} — restorable from History`
          : `Kept ${r.done.toLocaleString()} link${r.done === 1 ? "" : "s"}`;
      if (r.failed) toast.warning(`${msg} · ${r.failed} failed`, { description: r.errors[0]?.error });
      else toast.success(msg);
    } catch (e) {
      toast.error(`Failed: ${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  };
  const item = (g: UnlinkGroup) => ({ entity_type: g.entity_type, entity_id: g.entity_id });

  const runSelected = async (action: "apply" | "keep") => {
    const n = picked.reduce((a, g) => a + g.proposals, 0);
    if (
      !(await confirmDialog({
        title: action === "apply" ? "Remove links" : "Keep links",
        message:
          action === "apply"
            ? `Remove ${n.toLocaleString()} link${n === 1 ? "" : "s"} across ${picked.length} entit${picked.length === 1 ? "y" : "ies"}? Each stays restorable from History.`
            : `Keep ${n.toLocaleString()} link${n === 1 ? "" : "s"} across ${picked.length} entit${picked.length === 1 ? "y" : "ies"} and clear the proposals?`,
        confirmLabel: action === "apply" ? "Remove" : "Keep",
        destructive: action === "apply",
      }))
    )
      return;
    await run("bulk", action, { items: picked.map(item) });
    setSelected(new Set());
  };

  const working = unlink.isPending;

  return (
    <div className={styles.wrap}>
      <div className={styles.toolbar}>
        <span className={styles.system}>Remove links</span>
        <input
          className={cg.search}
          placeholder="Find an entity…"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setOffset(0);
          }}
        />
        {groups.data && (
          <span className={styles.muted}>
            {groups.data.proposals.toLocaleString()} proposal{groups.data.proposals === 1 ? "" : "s"} · {total.toLocaleString()} entit
            {total === 1 ? "y" : "ies"}
          </span>
        )}
        <span className={styles.grow} />
        {picked.length > 0 && (
          <>
            <span className={styles.muted}>{picked.length} selected</span>
            <button className={`${styles.rowBtn} ${styles.bWarn}`} disabled={working} onClick={() => runSelected("apply")}>
              Remove links
            </button>
            <button className={`${styles.rowBtn} ${styles.bGhost}`} disabled={working} onClick={() => runSelected("keep")}>
              Keep
            </button>
          </>
        )}
      </div>
      <p className={styles.note}>
        Links the review thinks are wrong, one row per entity — usually a name the autolinker over-matches. Remove takes
        the entity off every flagged article (restorable from History); Keep clears the proposals and leaves the links.
      </p>

      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th className={cg.chk}>
                <SelectAll keys={rows.map(keyOf)} selected={selected} setSelected={setSelected} />
              </th>
              <th>Entity</th>
              <th>Flagged</th>
              <th>Matched as</th>
              <th>Why</th>
              <th className={styles.actCol} />
            </tr>
          </thead>
          <tbody>
            {rows.map((g) => {
              const k = keyOf(g);
              const expanded = open.has(k);
              return (
                <Fragment key={k}>
                  <tr>
                    <td className={cg.chk}>
                      <input
                        type="checkbox"
                        aria-label={`Select ${g.name}`}
                        checked={selected.has(k)}
                        onChange={() => {
                          const next = new Set(selected);
                          if (next.has(k)) next.delete(k);
                          else next.add(k);
                          setSelected(next);
                        }}
                      />
                    </td>
                    <td>
                      <EntityCell type={g.entity_type} id={g.entity_id} name={g.name} gone={!g.exists} />
                      <span className={cg.meta}> {getEntityLabel(g.entity_type)}</span>
                    </td>
                    <td>
                      <button
                        className={cg.expand}
                        aria-expanded={expanded}
                        onClick={() => {
                          const next = new Set(open);
                          if (next.has(k)) next.delete(k);
                          else next.add(k);
                          setOpen(next);
                        }}
                        title="Show the articles"
                      >
                        {expanded ? "▾" : "▸"} {g.proposals.toLocaleString()}
                        {g.linked != null && <span className={cg.meta}> of {g.linked.toLocaleString()} articles</span>}
                      </button>
                    </td>
                    <td className={styles.muted}>{g.matched_names.join(", ") || "—"}</td>
                    <td className={styles.detail}>{g.reason && <span className={styles.reason}>{g.reason}</span>}</td>
                    <td>
                      <div className={styles.acts}>
                        <button
                          className={`${styles.rowBtn} ${styles.bWarn}`}
                          disabled={busy === k || working}
                          onClick={() => run(k, "apply", { items: [item(g)] })}
                          title={`Unlink ${g.name} from all ${g.proposals} flagged articles`}
                        >
                          {busy === k ? "Removing…" : "Remove all"}
                        </button>
                        <button
                          className={`${styles.rowBtn} ${styles.bGhost}`}
                          disabled={busy === k || working}
                          onClick={() => run(k, "keep", { items: [item(g)] })}
                        >
                          Keep all
                        </button>
                      </div>
                    </td>
                  </tr>
                  {expanded && (
                    <UnlinkArticles group={g} disabled={working} act={(a, ids) => run(k, a, { row_ids: ids })} />
                  )}
                </Fragment>
              );
            })}
            {!groups.isLoading && rows.length === 0 && (
              <tr>
                <td colSpan={6} className={styles.empty}>
                  {q ? "No remove-link proposals match." : "No remove-link proposals — nothing waiting."}
                </td>
              </tr>
            )}
            {groups.isLoading && (
              <tr>
                <td colSpan={6} className={styles.empty}>
                  Loading…
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <Pager offset={offset} total={total} setOffset={setOffset} />
    </div>
  );
}
