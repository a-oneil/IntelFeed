import { useState } from "react";
import { toast } from "sonner";
import { SelectionContextMenu } from "@/components/SelectionContextMenu";
import { CreateEntityPanel } from "@/components/CreateEntityPanel";
import { AddAliasPanel } from "@/components/AddAliasPanel";
import { useCreateNote } from "@/hooks/useNotes";
import styles from "./SummarySelectionMenu.module.css";

/**
 * Brings the entry-reader text-selection menu to entry-less contexts like the
 * daily AI summary. The summary spans a whole day (no single entry), so:
 *  - "Link to entity" is omitted (it attaches an entity to one article).
 *  - "Create note" produces a standalone note quoting the selection.
 *  - "Create entity" / "Add alias" work as in the reader, hosted here in a
 *    lightweight modal since this column has no reader side-panel.
 */

interface Props {
  containerRef: React.RefObject<HTMLElement | null>;
}

type Modal =
  | { kind: "create_entity"; text: string }
  | { kind: "add_alias"; text: string }
  | { kind: "create_note"; text: string }
  | null;

function truncate(text: string, max: number): string {
  return text.length > max ? text.slice(0, max).trimEnd() + "…" : text;
}

export function SummarySelectionMenu({ containerRef }: Props) {
  const [modal, setModal] = useState<Modal>(null);
  const close = () => setModal(null);

  return (
    <>
      <SelectionContextMenu
        containerRef={containerRef}
        onCreateEntity={(text) => setModal({ kind: "create_entity", text })}
        onAddAlias={(text) => setModal({ kind: "add_alias", text })}
        onCreateNote={(text) => setModal({ kind: "create_note", text })}
      />

      {modal && (
        <div className={styles.overlay} onMouseDown={close}>
          <div
            className={styles.modal}
            onMouseDown={(e) => e.stopPropagation()}
          >
            <div className={styles.header}>
              <span className={styles.title}>
                {modal.kind === "create_entity" && "Create Entity"}
                {modal.kind === "add_alias" && "Add Alias"}
                {modal.kind === "create_note" && "Create Note"}
              </span>
              <button className={styles.closeBtn} onClick={close}>
                &times;
              </button>
            </div>
            <div className={styles.body}>
              {modal.kind === "create_entity" && (
                <CreateEntityPanel initialText={modal.text} onClose={close} />
              )}
              {modal.kind === "add_alias" && (
                <AddAliasPanel aliasText={modal.text} onClose={close} />
              )}
              {modal.kind === "create_note" && (
                <StandaloneNoteForm text={modal.text} onClose={close} />
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function StandaloneNoteForm({ text, onClose }: { text: string; onClose: () => void }) {
  const [title, setTitle] = useState(truncate(text, 60));
  const [content, setContent] = useState(`> ${text}\n\n`);
  const createNote = useCreateNote();

  const handleSave = () => {
    createNote.mutate(
      { title: title.trim() || "Daily summary note", content_markdown: content },
      {
        onSuccess: () => {
          toast.success("Note saved");
          onClose();
        },
        onError: () => toast.error("Failed to save note"),
      },
    );
  };

  return (
    <div className={styles.noteForm}>
      <label className={styles.field}>
        <span className={styles.label}>Title</span>
        <input
          className={styles.input}
          type="text"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Note title"
          autoFocus
        />
      </label>
      <label className={styles.field}>
        <span className={styles.label}>Note</span>
        <textarea
          className={styles.textarea}
          value={content}
          onChange={(e) => setContent(e.target.value)}
          rows={6}
          placeholder="Add your note…"
        />
      </label>
      <div className={styles.footer}>
        <button className={styles.cancelBtn} onClick={onClose}>
          Cancel
        </button>
        <button
          className={styles.saveBtn}
          onClick={handleSave}
          disabled={createNote.isPending || !content.trim()}
        >
          {createNote.isPending ? "Saving…" : "Save note"}
        </button>
      </div>
    </div>
  );
}
