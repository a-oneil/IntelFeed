/**
 * Keys: the one place enrichment's API keys are set. One row per key, the
 * sources it serves, the shared key's state and the viewer's own key. Keys are
 * stored encrypted and never shown again.
 */
import { useState } from "react";
import { toast } from "sonner";

import {
  useEnrichmentKeys,
  useSetEnrichmentKey,
  useTestEnrichmentKey,
  type EnrichmentKey,
} from "@/hooks/useEnrichment";

import s from "../EnrichmentConsole.module.css";

const STATUS: Record<EnrichmentKey["status"], [string, string]> = {
  set: ["Set", s.okWord],
  rejected: ["Rejected", s.badWord],
  missing: ["Not set", s.muted],
  optional: ["Optional", s.muted],
};

export function KeysView({ editing, setEditing }: { editing: string | null; setEditing: (id: string | null) => void }) {
  const keysQ = useEnrichmentKeys();
  if (!keysQ.data) {
    return <p className={s.note}>{keysQ.isError ? "Couldn't load the keys." : "Loading keys…"}</p>;
  }
  const open = keysQ.data.find((k) => k.id === editing) ?? null;
  return (
    <div className={s.stack}>
      <p className={s.note}>
        Every key enrichment uses, in one place. The shared key works for every lookup and job; your own key replaces it
        for the lookups you start. Keys are stored encrypted and never shown again.
      </p>
      <div className={s.scroll}>
        <table className={s.keys}>
          <thead>
            <tr>
              <th>Key</th>
              <th>Used by</th>
              <th>Shared key</th>
              <th>Your key</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {keysQ.data.map((k) => {
              const [word, cls] = STATUS[k.status];
              return (
                <tr key={k.id} aria-current={k.id === editing}>
                  <td>
                    <b>{k.label}</b>
                    <small>{k.note}</small>
                  </td>
                  <td className={s.muted}>
                    {k.sources.map((x) => x.label).join(", ")}
                    {k.also_used_by && `; also ${k.also_used_by}`}
                  </td>
                  <td>
                    <span className={cls}>{word}</span>
                    {k.message && <small>{k.message}</small>}
                  </td>
                  <td className={k.mine ? s.okWord : s.muted}>
                    {!k.personal_allowed
                      ? "—"
                      : k.mine
                        ? "Yours is used"
                        : k.status === "set" || k.status === "rejected"
                          ? "Uses the shared key"
                          : "None"}
                  </td>
                  <td>
                    <button type="button" className={s.btn} onClick={() => setEditing(k.id === editing ? null : k.id)}>
                      {k.status === "set" ? "Change" : k.status === "rejected" ? "Replace key" : "Add key"}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {open && <KeyEditor key={open.id} k={open} onDone={() => setEditing(null)} />}
    </div>
  );
}

function KeyEditor({ k, onDone }: { k: EnrichmentKey; onDone: () => void }) {
  const set = useSetEnrichmentKey();
  const test = useTestEnrichmentKey();
  const [shared, setShared] = useState("");
  const [mine, setMine] = useState("");
  const busy = set.isPending || test.isPending;

  const runTest = async () => {
    const r = await test.mutateAsync(k.id);
    if (r.status === "ok") toast.success(`${k.label} works`);
    else if (r.status === "rejected") toast.error(`${k.label} was refused${r.message ? `: ${r.message}` : ""}`);
    else if (r.status === "unreachable") toast.warning(r.message ?? `Couldn't reach ${k.label}; try again in a moment`);
    else if (r.status === "untestable") toast.message(r.message ?? "Saved; the next job run checks it");
  };

  const save = async () => {
    try {
      if (shared) await set.mutateAsync({ keyId: k.id, apiKey: shared });
      if (mine) await set.mutateAsync({ keyId: k.id, apiKey: mine, mine: true });
      if (shared) await runTest();
      else toast.success("Saved");
      onDone();
    } catch (e) {
      toast.error(`Couldn't save: ${(e as Error).message}`);
    }
  };

  const remove = async (own: boolean) => {
    try {
      await set.mutateAsync({ keyId: k.id, apiKey: null, mine: own });
      toast.success(own ? "Your key is removed; lookups you start use the shared key" : "Shared key removed");
    } catch (e) {
      toast.error(`Couldn't remove: ${(e as Error).message}`);
    }
  };

  return (
    <div className={s.keyEditor}>
      <h4 className={s.h4}>{k.label}</h4>
      <div className={s.form}>
        <label htmlFor="enr-shared">Shared key</label>
        <span className={s.in}>
          <input
            id="enr-shared"
            className={s.wide}
            type="password"
            autoComplete="off"
            placeholder={k.status === "set" || k.status === "rejected" ? "set · paste to replace" : "paste the key"}
            value={shared}
            onChange={(e) => setShared(e.target.value)}
          />
        </span>
        <span className={s.hint}>
          Used for every lookup and job of {k.sources.map((x) => x.label).join(", ")}.
          {k.signup_url && (
            <>
              {" "}
              Get one at{" "}
              <a href={k.signup_url} target="_blank" rel="noreferrer">
                {new URL(k.signup_url).host}
              </a>
              .
            </>
          )}
        </span>
        {k.personal_allowed && (
          <>
            <label htmlFor="enr-mine">Your own key</label>
            <span className={s.in}>
              <input
                id="enr-mine"
                className={s.wide}
                type="password"
                autoComplete="off"
                placeholder={k.mine ? "yours is set · paste to replace" : "optional"}
                value={mine}
                onChange={(e) => setMine(e.target.value)}
              />
            </span>
            <span className={s.hint}>Replaces the shared key for lookups you start, and counts against your own limit.</span>
          </>
        )}
      </div>
      <div className={s.actions}>
        <button type="button" className={`${s.btn} ${s.primary}`} disabled={busy || (!shared && !mine)} onClick={save}>
          {shared ? "Save and test" : "Save"}
        </button>
        {(k.status === "set" || k.status === "rejected") && !shared && (
          <button type="button" className={s.link} disabled={busy} onClick={() => runTest().catch((e) => toast.error((e as Error).message))}>
            Test
          </button>
        )}
        <button type="button" className={s.link} onClick={onDone}>
          Cancel
        </button>
        <span className={s.spacer} />
        {(k.status === "set" || k.status === "rejected") && (
          <button type="button" className={s.link} disabled={busy} onClick={() => remove(false)}>
            Remove shared key
          </button>
        )}
        {k.mine && (
          <button type="button" className={s.link} disabled={busy} onClick={() => remove(true)}>
            Remove my key
          </button>
        )}
      </div>
    </div>
  );
}
