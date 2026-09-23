import { useState } from "react";
import { toast } from "sonner";

import {
  useAddAutolinkName,
  useAutolinkNames,
  useRemoveAutolinkName,
  type AutolinkNameList,
} from "@/hooks/useEngine";

import styles from "./DenylistPanel.module.css";

const PAGE_SIZE = 25;

const COPY: Record<AutolinkNameList, { heading: string; sub: React.ReactNode; addPlaceholder: string }> = {
  fp: {
    heading: "False positive names",
    sub: (
      <>
        Surface forms the autolinker never matches — they&apos;re dropped when the vocabulary is built, so
        no entry links to an entity through them. Deleting an entity with <strong>don&apos;t re-create it</strong>{" "}
        adds its names here as well. Vendors, products, tools and mitigations deliberately ignore this
        list, since their real names are common brand words.
      </>
    ),
    addPlaceholder: "Name to never match…",
  },
  blocked: {
    heading: "Blocked everywhere",
    sub: (
      <>
        Written when an analyst picks <strong>Never match &ldquo;…&rdquo; anywhere</strong> from a
        highlighted entity in the reader. Unlike the list above, these bind for <em>every</em> entity
        type — including vendors and products. Remove one to let it match again.
      </>
    ),
    addPlaceholder: "Form to block everywhere…",
  },
};

/** An autolink name-list setting as a table. Each is one comma-separated string
 *  underneath — at ~170 entries a textarea can't be read, searched, or edited a
 *  name at a time. */
export function FpNamesPanel({ list = "fp" }: { list?: AutolinkNameList }) {
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [newName, setNewName] = useState("");

  const copy = COPY[list];
  const { data, isLoading } = useAutolinkNames(list, { q: q.trim() || undefined, limit: PAGE_SIZE, offset });
  const addName = useAddAutolinkName(list);
  const removeName = useRemoveAutolinkName(list);

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  const submitAdd = async () => {
    const name = newName.trim();
    if (!name) return;
    try {
      await addName.mutateAsync(name);
      setNewName("");
      toast.success(`"${name}" won't be autolinked`);
    } catch {
      toast.error("Couldn't add that name");
    }
  };

  return (
    <section className={styles.wrap}>
      <h4 className={styles.heading}>
        {copy.heading} <span className={styles.count}>{total}</span>
      </h4>
      <p className={styles.sub}>{copy.sub}</p>

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
      </div>

      <div className={styles.rows}>
        {items.map((name) => (
          <div key={name} className={styles.row}>
            <span className={styles.name}>{name}</span>
            <button
              type="button"
              className={styles.remove}
              title="Let the autolinker match this name again"
              disabled={removeName.isPending}
              onClick={async () => {
                await removeName.mutateAsync(name);
                toast.success(`"${name}" can be autolinked again`);
              }}
            >
              ✕
            </button>
          </div>
        ))}
        {!isLoading && items.length === 0 && (
          <div className={styles.empty}>{q ? "No names match." : "Nothing here yet."}</div>
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
        <input
          className={styles.search}
          placeholder={copy.addPlaceholder}
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") submitAdd();
          }}
        />
        <button type="button" className={styles.add} disabled={!newName.trim() || addName.isPending} onClick={submitAdd}>
          Add
        </button>
      </div>
    </section>
  );
}
