import { useState, useMemo, useCallback, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  useNotes,
  useDeleteNote,
  useUpdateNote,
  useCreateNote,
} from "@/hooks/useNotes";
import {
  useAllEntityNotes,
  useDeleteEntityNote,
  useUpdateEntityNote,
} from "@/hooks/useEntityNotes";
import { useUIStore } from "@/stores/uiStore";
import { useAuthStore } from "@/stores/authStore";
import { NoteCard } from "./NoteCard";
import type { Note, EntityNote } from "@/api/types";
import type { InlineNoteSubmit } from "./InlineNoteEditor";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { formatDate } from "@/utils/formatDate";
import styles from "./NoteBrowser.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";

type UnifiedNote =
  | { kind: "note"; data: Note }
  | { kind: "entity"; data: EntityNote };

const ENTITY_TYPE_LABELS: Record<string, string> = {
  threat_actor: "Threat Actor",
  malware: "Malware",
  cve: "CVE",
  ttp: "TTP",
  campaign: "Campaign",
  vendor: "Vendor",
  product: "Product",
};

const ENTITY_PROFILE_ROUTES: Record<string, string> = {
  threat_actor: "/workbench/threat_actor",
  malware: "/workbench/malware",
  cve: "/workbench/cve",
  ttp: "/workbench/ttp",
  campaign: "/workbench/campaign",
  vendor: "/workbench/vendor",
  product: "/workbench/product",
};

type SourceFilter = "all" | "notes_only" | "entity_only" | "pinned";

export function NoteBrowser() {
  const [creating, setCreating] = useState(false);
  const navigate = useNavigate();

  // Filter state
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>("all");
  const [entityTypeFilter, setEntityTypeFilter] = useState("");

  // Debounce search — send to server after 300ms of inactivity
  const debounceRef = useState<ReturnType<typeof setTimeout> | null>(null);
  const handleSearchChange = useCallback(
    (value: string) => {
      setSearch(value);
      if (debounceRef[0]) clearTimeout(debounceRef[0]);
      debounceRef[0] = setTimeout(() => setDebouncedSearch(value.trim()), 300);
    },
    [debounceRef],
  );

  // A note opened from global search lands here with its title as the filter,
  // since the browser has no per-note route to deep-link to.
  const pendingNoteSearch = useUIStore((s) => s.pendingNoteSearch);
  const clearPendingNoteSearch = useUIStore((s) => s.clearPendingNoteSearch);
  useEffect(() => {
    if (pendingNoteSearch == null) return;
    setSearch(pendingNoteSearch);
    setDebouncedSearch(pendingNoteSearch);
    setSourceFilter("all");
    setEntityTypeFilter("");
    clearPendingNoteSearch();
  }, [pendingNoteSearch, clearPendingNoteSearch]);

  const showNotes = sourceFilter !== "entity_only";
  const showEntity = sourceFilter !== "notes_only" && sourceFilter !== "pinned";

  // Fetch regular notes (server-side search)
  const { data, isLoading } = useNotes(
    showNotes
      ? {
          is_pinned: sourceFilter === "pinned" ? true : undefined,
          q: debouncedSearch || undefined,
          limit: 200,
        }
      : { limit: 0 },
  );

  // Fetch entity notes (server-side search + filters)
  const { data: entityNotesData, isLoading: entityNotesLoading } =
    useAllEntityNotes(
      showEntity
        ? {
            q: debouncedSearch || undefined,
            entity_type: entityTypeFilter || undefined,
            limit: 200,
          }
        : { limit: 0 },
    );

  const deleteNote = useDeleteNote();
  const updateNote = useUpdateNote();
  const createNote = useCreateNote();
  const deleteEntityNote = useDeleteEntityNote();
  const updateEntityNote = useUpdateEntityNote();
  const undoableDelete = useUndoableDelete();
  // The API only lets the author (or an admin) modify a note
  const currentUser = useAuthStore((s) => s.user);
  const canEdit = (authorId?: string | null) =>
    currentUser?.role === "admin" || (!!authorId && authorId === currentUser?.id);
  const setSelectedEntry = useUIStore((s) => s.setSelectedEntry);
  const setActivePanel = useUIStore((s) => s.setActivePanel);
  const setActiveReaderPanel = useUIStore((s) => s.setActiveReaderPanel);

  const notes = data?.items || [];
  const entityNotes = entityNotesData?.items || [];

  // Build unified list
  const unified = useMemo<UnifiedNote[]>(() => {
    const noteItems: UnifiedNote[] = showNotes
      ? notes.map((n) => ({ kind: "note" as const, data: n }))
      : [];
    const entityItems: UnifiedNote[] = showEntity
      ? entityNotes.map((en) => ({ kind: "entity" as const, data: en }))
      : [];

    return [...noteItems, ...entityItems].sort(
      (a, b) =>
        new Date(b.data.updated_at).getTime() -
        new Date(a.data.updated_at).getTime(),
    );
  }, [notes, entityNotes, showNotes, showEntity]);

  const hasActiveFilters =
    !!debouncedSearch || sourceFilter !== "all" || !!entityTypeFilter;

  const clearFilters = () => {
    setSearch("");
    setDebouncedSearch("");
    setSourceFilter("all");
    setEntityTypeFilter("");
  };

  const openEntry = (entryId: string) => {
    setActivePanel("entries");
    setSelectedEntry(entryId);
    setActiveReaderPanel?.("notes");
  };

  const handleCreate = async (d: InlineNoteSubmit) => {
    await createNote.mutateAsync({
      title: d.title || "Untitled Note",
      content_markdown: d.markdown || " ",
      is_pinned: d.isPinned,
    });
  };

  const allLoading = isLoading || entityNotesLoading;

  return (
    <div className={styles.browser}>
      <div className={styles.toolbar}>
        <input
          className={styles.searchInput}
          type="text"
          placeholder="Search notes..."
          value={search}
          onChange={(e) => handleSearchChange(e.target.value)}
        />
        <select
          className={styles.toolbarSelect}
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value as SourceFilter)}
        >
          <option value="all">All Sources</option>
          <option value="notes_only">Notes Only</option>
          <option value="entity_only">Entity Notes Only</option>
          <option value="pinned">Pinned Only</option>
        </select>
        {showEntity && (
          <select
            className={styles.toolbarSelect}
            value={entityTypeFilter}
            onChange={(e) => setEntityTypeFilter(e.target.value)}
          >
            <option value="">All Entity Types</option>
            {Object.entries(ENTITY_TYPE_LABELS).map(([val, label]) => (
              <option key={val} value={val}>
                {label}
              </option>
            ))}
          </select>
        )}
        {hasActiveFilters && (
          <button className={styles.clearBtn} onClick={clearFilters}>
            Clear
          </button>
        )}
        <button className={styles.newBtn} onClick={() => setCreating(true)}>
          + New Note
        </button>
      </div>

      {hasActiveFilters && !allLoading && (
        <div className={styles.resultCount}>
          {unified.length} result{unified.length !== 1 ? "s" : ""}
        </div>
      )}

      {allLoading ? (
        <AsyncStateLoading label="Loading notes…" />
      ) : unified.length === 0 && !creating ? (
        <div className={styles.empty}>
          {hasActiveFilters
            ? "No notes match your search."
            : "No notes yet. Create one to get started."}
        </div>
      ) : (
        <div className={styles.notesList}>
          {creating && (
            <NoteCard
              content=""
              bodyFormat="html"
              showPin
              startInEdit
              submitLabel="Create"
              onSave={handleCreate}
              onExitCreate={() => setCreating(false)}
            />
          )}

          {unified.map((item) =>
            item.kind === "note" ? (
              <NoteCard
                key={`note-${item.data.id}`}
                title={item.data.title}
                content={item.data.content_html || item.data.content_markdown || ""}
                editorMarkdown={item.data.content_markdown || ""}
                author={item.data.creator_username}
                time={formatDate(item.data.updated_at)}
                isPinned={item.data.is_pinned}
                showPin
                linkedLabel={
                  item.data.entry_title
                    ? `${item.data.feed_title} › ${item.data.entry_title}`
                    : undefined
                }
                onOpenLinked={
                  item.data.entry_id
                    ? () => openEntry(item.data.entry_id as string)
                    : undefined
                }
                onSave={(d) =>
                  updateNote.mutateAsync({
                    noteId: item.data.id,
                    data: {
                      title: d.title || "Untitled Note",
                      content_markdown: d.markdown || " ",
                      is_pinned: d.isPinned,
                    },
                  })
                }
                editable={canEdit(item.data.created_by)}
                onDelete={
                  canEdit(item.data.created_by)
                    ? () =>
                        undoableDelete({
                          label: `Note "${item.data.title}"`,
                          key: `note-${item.data.id}`,
                          onDelete: () => deleteNote.mutate(item.data.id),
                        })
                    : undefined
                }
              />
            ) : (
              <NoteCard
                key={`entity-${item.data.id}`}
                title={item.data.title}
                content={item.data.content}
                bodyFormat="markdown"
                excludeEntityId={item.data.entity_id}
                author={item.data.username}
                time={formatDate(item.data.updated_at)}
                linkedLabel={`${ENTITY_TYPE_LABELS[item.data.entity_type] || item.data.entity_type}${
                  item.data.entity_name ? ` — ${item.data.entity_name}` : ""
                }`}
                onOpenLinked={() => {
                  const route = ENTITY_PROFILE_ROUTES[item.data.entity_type];
                  if (route) navigate(`${route}/${item.data.entity_id}`);
                }}
                onSave={(d) =>
                  updateEntityNote.mutateAsync({
                    id: item.data.id,
                    title: d.title || null,
                    content: d.markdown,
                  })
                }
                editable={canEdit(item.data.user_id)}
                onDelete={
                  canEdit(item.data.user_id)
                    ? () =>
                        undoableDelete({
                          label: "Entity note",
                          key: `entity-note-${item.data.id}`,
                          onDelete: () => deleteEntityNote.mutate(item.data.id),
                        })
                    : undefined
                }
              />
            ),
          )}
        </div>
      )}
    </div>
  );
}
