/**
 * CleanupGroups — the Engine console's Held links queue.
 *
 * One row per entity the autolinker matched but would not commit to ("Royal"
 * in nine articles). Link the held matches or reject them, all or per
 * article; rejecting a whole entity offers to stop matching the word for
 * good. (Proposals from the review logs live in ProposalsQueue, one row per
 * entity as well.)
 */

import { Fragment, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { usePendingMatches, useResolvePending, type PendingMatchGroup } from "@/hooks/useAutolinking";
import { useAddAutolinkName } from "@/hooks/useEngine";
import { confirmDialog } from "@/utils/dialog";
import { getEntityCssVar, getEntityLabel } from "@/utils/entityTheme";
import { formatDateTime } from "@/utils/formatDate";

import styles from "./ProposalsQueue.module.css";
import cg from "./CleanupGroups.module.css";

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
