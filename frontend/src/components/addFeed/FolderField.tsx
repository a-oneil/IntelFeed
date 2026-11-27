import { useState } from "react";
import { useCreateCategory } from "@/hooks/useFeeds";
import type { Category } from "@/api/types";
import styles from "../AddFeedModal.module.css";

const NEW = "__new__";

/** Categories as one list, children under their parent ("Parent / Child"). */
export function flattenCategories(categories: Category[] | undefined, prefix = ""): { id: string; name: string }[] {
  const out: { id: string; name: string }[] = [];
  for (const cat of categories ?? []) {
    const name = prefix ? `${prefix} / ${cat.name}` : cat.name;
    out.push({ id: cat.id, name });
    if (cat.children?.length) out.push(...flattenCategories(cat.children, name));
  }
  return out;
}

/**
 * The folder a new feed is filed in. A feed left without one misses every
 * change made by folder and inherits no folder defaults, so once folders exist
 * one has to be picked; the dialog preselects the folder feeds of the same
 * kind already live in. "New folder…" makes one on the spot.
 */
export function FolderField({
  categories,
  value,
  onChange,
}: {
  categories: Category[] | undefined;
  value: string;
  onChange: (id: string) => void;
}) {
  const options = flattenCategories(categories);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const create = useCreateCategory();

  const submit = async () => {
    const trimmed = name.trim();
    if (!trimmed) return;
    try {
      const made = await create.mutateAsync({ name: trimmed });
      onChange(made.id);
      setCreating(false);
      setName("");
    } catch {
      // the mutation's toast says why
    }
  };

  if (creating) {
    return (
      <div className={styles.row}>
        <label className={styles.rowLabel} htmlFor="add-feed-new-folder">
          Folder
        </label>
        <input
          id="add-feed-new-folder"
          className={styles.field}
          value={name}
          placeholder="New folder name"
          autoFocus
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              void submit();
            } else if (e.key === "Escape") {
              e.stopPropagation();
              setCreating(false);
            }
          }}
        />
        <button type="button" className={styles.smallBtn} onClick={() => void submit()} disabled={!name.trim() || create.isPending}>
          {create.isPending ? "Adding…" : "Add"}
        </button>
        <button type="button" className={styles.smallBtn} onClick={() => setCreating(false)}>
          Cancel
        </button>
      </div>
    );
  }

  return (
    <div className={styles.row}>
      <label className={styles.rowLabel} htmlFor="add-feed-folder">
        Folder
      </label>
      <select
        id="add-feed-folder"
        className={styles.field}
        value={value}
        required={options.length > 0}
        aria-invalid={options.length > 0 && !value}
        onChange={(e) => {
          if (e.target.value === NEW) setCreating(true);
          else onChange(e.target.value);
        }}
      >
        {options.length > 0 ? (
          <option value="" disabled>
            Choose a folder…
          </option>
        ) : (
          <option value="">No folder</option>
        )}
        {options.map((cat) => (
          <option key={cat.id} value={cat.id}>
            {cat.name}
          </option>
        ))}
        <option value={NEW}>New folder…</option>
      </select>
    </div>
  );
}
