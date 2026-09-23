import { useState, useMemo, useRef, useEffect } from "react";
import { useTags, useEntryTags, useCreateTag, useAddTagsToEntry, useRemoveTagFromEntry } from "@/hooks/useTags";
import type { Tag } from "@/api/types";
import { Chip } from "./primitives";
import styles from "./TagInput.module.css";

interface TagInputProps {
  entryId: string;
  onClose?: () => void;
}

export function TagInput({ entryId, onClose }: TagInputProps) {
  const [query, setQuery] = useState("");
  const [newTagColor, setNewTagColor] = useState("#6B7280");
  const inputRef = useRef<HTMLInputElement>(null);
  const { data: allTags } = useTags();
  const { data: currentEntryTags } = useEntryTags(entryId);
  const createTag = useCreateTag();
  const addTags = useAddTagsToEntry();
  const removeTag = useRemoveTagFromEntry();

  const tags = allTags || [];
  const activeTagIds = useMemo(
    () => new Set((currentEntryTags || []).map((t) => t.id)),
    [currentEntryTags],
  );

  const trimmedQuery = query.trim().toLowerCase();

  const filteredTags = useMemo(() => {
    if (!trimmedQuery) return tags;
    return tags.filter((t) => t.name.toLowerCase().includes(trimmedQuery));
  }, [tags, trimmedQuery]);

  const exactMatch = useMemo(
    () => tags.some((t) => t.name.toLowerCase() === trimmedQuery),
    [tags, trimmedQuery],
  );

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleCreateAndAdd = async () => {
    if (!query.trim() || exactMatch) return;
    const tag = await createTag.mutateAsync({ name: query.trim(), color: newTagColor });
    addTags.mutate({ entryId, tagIds: [tag.id] });
    setQuery("");
  };

  const handleToggleTag = (tag: Tag) => {
    if (activeTagIds.has(tag.id)) {
      removeTag.mutate({ entryId, tagId: tag.id });
    } else {
      addTags.mutate({ entryId, tagIds: [tag.id] });
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      if (trimmedQuery && filteredTags.length === 1 && !activeTagIds.has(filteredTags[0].id)) {
        handleToggleTag(filteredTags[0]);
        setQuery("");
      } else if (trimmedQuery && !exactMatch) {
        handleCreateAndAdd();
      }
    }
    if (e.key === "Escape") {
      if (query) {
        setQuery("");
      } else {
        onClose?.();
      }
    }
  };

  return (
    <div className={styles.tagInput}>
      <div className={styles.header}>
        <span className={styles.label}>Tags</span>
        {onClose && (
          <button className={styles.closeBtn} onClick={onClose}>&times;</button>
        )}
      </div>

      {/* Search / create input */}
      <div className={styles.searchRow}>
        <input
          ref={inputRef}
          type="text"
          className={styles.searchInput}
          placeholder="Search or create tag..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
        />
        {query.trim() && !exactMatch && (
          <div className={styles.createRow}>
            <input
              type="color"
              className={styles.colorPicker}
              value={newTagColor}
              onChange={(e) => setNewTagColor(e.target.value)}
            />
            <button
              className={styles.addBtn}
              onClick={handleCreateAndAdd}
            >
              Create "{query.trim()}"
            </button>
          </div>
        )}
      </div>

      {/* Tag list */}
      <div className={styles.tagList}>
        {filteredTags.length === 0 && !query.trim() && (
          <span className={styles.empty}>No tags yet</span>
        )}
        {filteredTags.length === 0 && query.trim() && exactMatch && (
          <span className={styles.empty}>No matches</span>
        )}
        {filteredTags.map((tag) => (
          <Chip
            key={tag.id}
            pill
            marker
            markerShape="dot"
            tint={tag.color}
            className={`${styles.tag} ${activeTagIds.has(tag.id) ? styles.active : ""}`}
            onClick={() => handleToggleTag(tag)}
            aria-pressed={activeTagIds.has(tag.id)}
          >
            {tag.name}
            <span className={styles.count}>({tag.entry_count})</span>
          </Chip>
        ))}
      </div>
    </div>
  );
}
