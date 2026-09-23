import { useState } from "react";
import { toast } from "sonner";

import {
  useAddDenylistEntry,
  useDenylist,
  useRemoveDenylistEntry,
  type ExtractionType,
} from "@/hooks/useExtraction";

import styles from "./DenylistPanel.module.css";

const PAGE_SIZE = 25;

/** "any" is a wildcard row — the name is banned whatever type an article
 *  implies. It's the default for a hand-added name. */
type DenyType = ExtractionType | "any";

const TYPES: { key: DenyType; label: string }[] = [
  { key: "any", label: "Any type" },
  { key: "threat_actor", label: "Actor" },
  { key: "malware", label: "Malware" },
  { key: "tool", label: "Tool" },
  { key: "cve", label: "CVE" },
  { key: "ttp", label: "TTP" },
];

const TYPE_LABEL = Object.fromEntries(TYPES.map((t) => [t.key, t.label]));

/** Names the extract stage refuses to mint. Rows land here from the AI entities
 *  table's delete, the entity profile's delete popover, or the box below —
 *  every name is mirrored into Autolink → False Positive Names too. */
export function DenylistPanel() {
  const [q, setQ] = useState("");
  const [type, setType] = useState<DenyType | "">("");
  const [offset, setOffset] = useState(0);
  const [newType, setNewType] = useState<DenyType>("any");
  const [newName, setNewName] = useState("");

  const { data, isLoading } = useDenylist({
    q: q.trim() || undefined,
    entity_type: type || undefined,
    limit: PAGE_SIZE,
    offset,
  });
  const addEntry = useAddDenylistEntry();
  const removeEntry = useRemoveDenylistEntry();

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  const submitAdd = async () => {
    const name = newName.trim();
    if (!name) return;
    try {
      await addEntry.mutateAsync({ entityType: newType, name });
      setNewName("");
      toast.success(
        newType === "any"
          ? `"${name}" won't be created as any entity type`
          : `"${name}" won't be created as ${TYPE_LABEL[newType].toLowerCase()}`,
      );
    } catch {
      toast.error("Couldn't add that name");
    }
  };

  return (
    <section className={styles.wrap}>
      <h4 className={styles.heading}>
        Do-not-recreate list <span className={styles.count}>{total}</span>
      </h4>
      <p className={styles.sub}>
        Names the extract stage won&apos;t mint, whatever an article says. Deleting an entity from{" "}
        <strong>AI entities</strong> or its profile adds it here (with its aliases) and to{" "}
        <strong>Autolink → False Positive Names</strong>. Removing a row lifts both.
      </p>

      <div className={styles.filters}>
        <input
          className={styles.search}
          placeholder="Search names…"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setOffset(0);
          }}
        />
        <select
          className={styles.select}
          value={type}
          onChange={(e) => {
            setType(e.target.value as DenyType | "");
            setOffset(0);
          }}
          aria-label="Filter by entity type"
        >
          <option value="">All types</option>
          {TYPES.map((t) => (
            <option key={t.key} value={t.key}>
              {t.label}
            </option>
          ))}
        </select>
      </div>

      <div className={styles.rows}>
        {items.map((row) => (
          <div key={row.id} className={styles.row}>
            <span className={styles.name} title={row.reason ?? undefined}>
              {row.display_name}
            </span>
            <span className={`${styles.type} ${row.entity_type === "any" ? styles.typeAny : ""}`}>
              {TYPE_LABEL[row.entity_type] ?? row.entity_type}
            </span>
            <span className={styles.origin}>
              {row.source === "do_not_recreate" ? row.reason || "analyst" : "2026-08 cleanup"}
            </span>
            <button
              type="button"
              className={styles.remove}
              title="Allow this name to be created again"
              disabled={removeEntry.isPending}
              onClick={async () => {
                await removeEntry.mutateAsync(row.id);
                toast.success(`"${row.display_name}" can be created again`);
              }}
            >
              ✕
            </button>
          </div>
        ))}
        {!isLoading && items.length === 0 && (
          <div className={styles.empty}>
            {q || type ? "No names match." : "Nothing is blocked from being re-created."}
          </div>
        )}
      </div>

      {total > PAGE_SIZE && (
        <div className={styles.pager}>
          <button type="button" disabled={offset === 0} onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}>
            ← Prev
          </button>
          <span>
            {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
          </span>
          <button
            type="button"
            disabled={offset + PAGE_SIZE >= total}
            onClick={() => setOffset((o) => o + PAGE_SIZE)}
          >
            Next →
          </button>
        </div>
      )}

      <div className={styles.addRow}>
        <select
          className={styles.select}
          value={newType}
          onChange={(e) => setNewType(e.target.value as DenyType)}
          aria-label="Type to ban the name for"
        >
          {TYPES.map((t) => (
            <option key={t.key} value={t.key}>
              {t.label}
            </option>
          ))}
        </select>
        <input
          className={styles.search}
          placeholder="Name to never create…"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") submitAdd();
          }}
        />
        <button type="button" className={styles.add} disabled={!newName.trim() || addEntry.isPending} onClick={submitAdd}>
          Add
        </button>
      </div>
    </section>
  );
}
