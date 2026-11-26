import { useEffect, useState } from "react";
import { toast } from "sonner";
import type { TelemetrySourceNote } from "@/api/types";
import { InlineNoteEditor, type InlineNoteSubmit } from "@/components/InlineNoteEditor";
import { NoteCard } from "@/components/NoteCard";
import { Spinner } from "@/components/primitives";
import {
  useCreateTelemetryNote,
  useDeleteTelemetryNote,
  useTelemetryNotes,
  useUpdateTelemetryNote,
} from "@/hooks/useTelemetrySources";
import { useAuthStore } from "@/stores/authStore";
import { confirmDialog } from "@/utils/dialog";
import { formatDate } from "@/utils/formatDate";
import styles from "./TelemetrySourceDrawer.module.css";

export interface TelemetrySourceInfo {
  name: string;
  category?: string;
  vendor?: string | null;
  product?: string | null;
  log_types?: string[];
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

/** Only http(s) links are ever rendered as links. */
function safeHref(url: string | null): string | null {
  return url && /^https?:\/\//i.test(url) ? url : null;
}

function errorMessage(err: unknown): string {
  const e = err as { response?: { data?: { error?: { message?: string } } }; message?: string };
  return e.response?.data?.error?.message || e.message || "Something went wrong";
}

/**
 * Side panel for one telemetry source: what it is, then the notes and saved
 * links analysts have about it. Shared by the Telemetry page and the rule
 * rail. Notes are markdown, written and shown with the same editor and card
 * as every other note. Anyone adds; the author or an admin edits and deletes.
 */
export function TelemetrySourceDrawer({ source, onClose }: { source: TelemetrySourceInfo; onClose: () => void }) {
  const { data, isLoading } = useTelemetryNotes(source.name);
  const create = useCreateTelemetryNote();
  const [url, setUrl] = useState("");
  // Remounts the editor to clear it after a save.
  const [editorKey, setEditorKey] = useState(0);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // The note editor handles its own Escape (cancel) and marks it handled.
      if (e.key === "Escape" && !e.defaultPrevented) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const notes = data?.items ?? [];
  const links = notes.filter((n) => n.url);
  const plain = notes.filter((n) => !n.url);

  const add = ({ markdown }: InlineNoteSubmit) => {
    const content = markdown.trim();
    if (!url.trim() && !content) {
      toast.error("Add a link, a note, or both.");
      return;
    }
    create.mutate(
      { source_name: source.name, url: url.trim() || null, content: content || null },
      {
        onSuccess: () => {
          setUrl("");
          setEditorKey((k) => k + 1);
        },
        onError: (err) => toast.error(errorMessage(err)),
      },
    );
  };

  const meta = [source.vendor, source.product && source.product !== source.vendor ? source.product : null]
    .filter(Boolean)
    .join(" / ");

  return (
    <div className={styles.overlay} onClick={onClose}>
      <aside
        className={styles.drawer}
        role="dialog"
        aria-label={`${source.name} notes`}
        onClick={(e) => e.stopPropagation()}
      >
        <header className={styles.head}>
          <div>
            <h2 className={styles.title}>{source.name}</h2>
            {meta && <div className={styles.meta}>{meta}</div>}
          </div>
          <button className={styles.close} onClick={onClose} aria-label="Close">
            ×
          </button>
        </header>

        {source.log_types && source.log_types.length > 0 && (
          <div className={styles.logTypes}>
            {source.log_types.map((lt) => (
              <span key={lt} className={styles.logType}>
                {lt}
              </span>
            ))}
          </div>
        )}

        <div className={styles.form}>
          <input
            className={styles.input}
            type="url"
            placeholder="Link to a page about this source (optional)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <InlineNoteEditor
            key={editorKey}
            showTitle={false}
            autoFocus={false}
            submitLabel={url.trim() ? "Save link" : "Save note"}
            saving={create.isPending}
            onSubmit={add}
            onCancel={() => {
              setUrl("");
              setEditorKey((k) => k + 1);
            }}
          />
        </div>

        {isLoading ? (
          <div className={styles.empty}>
            <Spinner /> Loading…
          </div>
        ) : notes.length === 0 ? (
          <div className={styles.empty}>No notes or links yet.</div>
        ) : (
          <>
            {links.length > 0 && (
              <section>
                <h3 className={styles.section}>Links</h3>
                {links.map((n) => (
                  <NoteRow key={n.id} note={n} />
                ))}
              </section>
            )}
            {plain.length > 0 && (
              <section>
                <h3 className={styles.section}>Notes</h3>
                {plain.map((n) => (
                  <NoteRow key={n.id} note={n} />
                ))}
              </section>
            )}
          </>
        )}
      </aside>
    </div>
  );
}

function NoteRow({ note }: { note: TelemetrySourceNote }) {
  const me = useAuthStore((s) => s.user);
  const canEdit = !!me && (me.role === "admin" || me.id === note.user_id);
  const update = useUpdateTelemetryNote();
  const remove = useDeleteTelemetryNote();
  const href = safeHref(note.url);

  const del = async () => {
    const ok = await confirmDialog({
      title: note.url ? "Delete this link?" : "Delete this note?",
      message: "Notes are shared, so this removes it for everyone.",
      confirmLabel: "Delete",
      destructive: true,
    });
    if (ok) remove.mutate(note.id, { onError: (err) => toast.error(errorMessage(err)) });
  };

  return (
    <div className={styles.note}>
      {href && (
        <a className={styles.linkTitle} href={href} target="_blank" rel="noopener noreferrer">
          {note.page_title || href}
          <span className={styles.host}>{hostOf(href)}</span>
        </a>
      )}
      {note.quote && <blockquote className={styles.quote}>{note.quote}</blockquote>}
      <NoteCard
        content={note.content || ""}
        bodyFormat="markdown"
        author={note.username ?? "Unknown"}
        time={formatDate(note.updated_at)}
        showTitle={false}
        editable={canEdit}
        onSave={(d) =>
          // The link and quote stay as saved; the editor holds the note text.
          // NoteCard shows the error; give it the server's message.
          update.mutateAsync({ id: note.id, content: d.markdown.trim() }).catch((err) => {
            throw new Error(errorMessage(err));
          })
        }
        onDelete={canEdit ? del : undefined}
      />
    </div>
  );
}
