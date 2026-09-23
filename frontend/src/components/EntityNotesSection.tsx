import { useState } from "react";
import {
  useEntityNotes,
  useCreateEntityNote,
  useUpdateEntityNote,
  useDeleteEntityNote,
} from "@/hooks/useEntityNotes";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { useAuthStore } from "@/stores/authStore";
import { NoteCard } from "./NoteCard";
import type { InlineNoteSubmit } from "./InlineNoteEditor";
import styles from "./EntityNotesSection.module.css";

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

interface EntityNotesSectionProps {
  entityType: string;
  entityId: string;
}

export function EntityNotesSection({ entityType, entityId }: EntityNotesSectionProps) {
  const { data: notes } = useEntityNotes(entityType, entityId);
  const createNote = useCreateEntityNote();
  const updateNote = useUpdateEntityNote();
  const deleteNote = useDeleteEntityNote();
  const undoableDelete = useUndoableDelete();
  // The API only lets the author (or an admin) modify a note
  const currentUser = useAuthStore((s) => s.user);
  const canEdit = (authorId?: string | null) =>
    currentUser?.role === "admin" || (!!authorId && authorId === currentUser?.id);
  const [creating, setCreating] = useState(false);

  const handleCreate = async (data: InlineNoteSubmit) => {
    await createNote.mutateAsync({
      entity_type: entityType,
      entity_id: entityId,
      title: data.title || null,
      content: data.markdown,
    });
  };

  return (
    <div className={styles.wrapper}>
      <div className={styles.header}>
        <span>
          Notes <span className={styles.count}>{notes?.length ?? 0}</span>
        </span>
        {!creating && (
          <button className={styles.addBtn} onClick={() => setCreating(true)}>
            + Add Note
          </button>
        )}
      </div>
      <div className={styles.body}>
        <div className={styles.cardList}>
          {creating && (
            <NoteCard
              content=""
              bodyFormat="markdown"
              startInEdit
              submitLabel="Add Note"
              onSave={handleCreate}
              onExitCreate={() => setCreating(false)}
            />
          )}

          {notes && notes.length > 0
            ? notes.map((note) => (
                <NoteCard
                  key={note.id}
                  title={note.title}
                  content={note.content}
                  bodyFormat="markdown"
                  excludeEntityId={entityId}
                  author={note.username}
                  time={timeAgo(note.created_at)}
                  submitLabel="Save"
                  onSave={(data) =>
                    updateNote.mutateAsync({
                      id: note.id,
                      title: data.title || null,
                      content: data.markdown,
                    })
                  }
                  editable={canEdit(note.user_id)}
                  onDelete={
                    canEdit(note.user_id)
                      ? () =>
                          undoableDelete({
                            label: "Note",
                            key: `entity-note-${note.id}`,
                            onDelete: () => deleteNote.mutate(note.id),
                          })
                      : undefined
                  }
                />
              ))
            : !creating && <div className={styles.empty}>No notes yet</div>}
        </div>
      </div>
    </div>
  );
}
