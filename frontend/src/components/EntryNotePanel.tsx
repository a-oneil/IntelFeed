import { useState } from "react";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { useAuthStore } from "@/stores/authStore";
import {
  useEntryNotes,
  useDeleteNote,
  useUpdateNote,
  useCreateEntryNote,
} from "@/hooks/useNotes";
import { NoteCard } from "./NoteCard";
import type { InlineNoteSubmit } from "./InlineNoteEditor";
import { formatDate } from "@/utils/formatDate";
import styles from "./EntryNotePanel.module.css";

interface EntryNotePanelProps {
  entryId: string;
  onClose: () => void;
  /** Pre-fill content when creating a new note (e.g. from text selection). */
  initialContent?: string;
}

export function EntryNotePanel({ entryId, onClose: _onClose, initialContent }: EntryNotePanelProps) {
  const { data: notes, isLoading } = useEntryNotes(entryId);
  const deleteNote = useDeleteNote();
  const updateNote = useUpdateNote();
  const createEntryNote = useCreateEntryNote();
  const undoableDelete = useUndoableDelete();
  // The API only lets the author (or an admin) modify a note
  const currentUser = useAuthStore((s) => s.user);
  const canEdit = (authorId?: string | null) =>
    currentUser?.role === "admin" || (!!authorId && authorId === currentUser?.id);
  const [creating, setCreating] = useState(!!initialContent);

  const hasNotes = !!notes && notes.length > 0;
  // Open straight into the editor when the entry has no notes yet.
  const showCreate = creating || (!isLoading && !hasNotes);

  const handleCreate = async (data: InlineNoteSubmit) => {
    await createEntryNote.mutateAsync({
      entryId,
      data: {
        title: data.title || "Untitled Note",
        content_markdown: data.markdown || " ",
        is_pinned: data.isPinned,
      },
    });
  };

  return (
    <div className={styles.panel}>
      {hasNotes && !creating && (
        <button className={styles.newBtn} onClick={() => setCreating(true)}>
          + New Note
        </button>
      )}

      {isLoading && <div className={styles.loading}>Loading...</div>}

      {showCreate && (
        <NoteCard
          content=""
          bodyFormat="html"
          editorMarkdown={initialContent}
          showPin
          startInEdit
          submitLabel="Create"
          onSave={handleCreate}
          onExitCreate={() => setCreating(false)}
        />
      )}

      {notes &&
        notes.map((note) => (
          <NoteCard
            key={note.id}
            title={note.title}
            content={note.content_html || note.content_markdown || ""}
            editorMarkdown={note.content_markdown || ""}
            author={note.creator_username}
            time={formatDate(note.updated_at)}
            isPinned={note.is_pinned}
            showPin
            editable={canEdit(note.created_by)}
            onSave={(data) =>
              updateNote.mutateAsync({
                noteId: note.id,
                data: {
                  title: data.title || "Untitled Note",
                  content_markdown: data.markdown || " ",
                  is_pinned: data.isPinned,
                },
              })
            }
            onDelete={
              canEdit(note.created_by)
                ? () =>
                    undoableDelete({
                      label: `Note "${note.title}"`,
                      key: `note-${note.id}`,
                      onDelete: () => deleteNote.mutate(note.id),
                    })
                : undefined
            }
          />
        ))}
    </div>
  );
}
