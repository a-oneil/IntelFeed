import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import type { EntryTag } from "@/api/types";
import { Chip } from "@/components/primitives/Chip";
import { useRemoveTagFromEntry } from "@/hooks/useTags";
import { useUIStore } from "@/stores/uiStore";
import styles from "./TagChips.module.css";

/** Chips shown inline before the rest fold into `+N`. */
export const TAG_CHIP_CAP = 3;

/** Tags promoted to chips, in the order the entry carries them. */
export function chipTags(tags: EntryTag[] | undefined): EntryTag[] {
  return (tags ?? []).filter((t) => t.display_as_chip);
}

function chipTitle(tag: EntryTag): string {
  const lines = [tag.description || tag.name];
  lines.push(tag.personal ? "Only you see this tag" : "Everyone sees this tag");
  lines.push(`Click to see everything tagged "${tag.name}"`);
  return lines.join("\n");
}

const UNTINTED = "#6B7280";

interface ChipItemProps {
  tag: EntryTag;
  entryId?: string;
  onPivot: (name: string) => void;
}

/**
 * One analyst-authored chip: a solid Chip in the tag's own colour (foreground
 * derived from that colour, so no choice of tint is unreadable), plus a
 * hover/focus × that takes the tag off this entry.
 */
function TagChipItem({ tag, entryId, onPivot }: ChipItemProps) {
  const remove = useRemoveTagFromEntry();
  const canRemove = !!entryId && !!tag.id;

  return (
    <span className={styles.item}>
      <Chip
        tone="solid"
        tint={tag.color || UNTINTED}
        size="sm"
        className={styles.chip}
        title={chipTitle(tag)}
        onClick={() => onPivot(tag.name)}
      >
        <span className={styles.label}>{tag.name}</span>
      </Chip>
      {canRemove && (
        <button
          type="button"
          className={styles.remove}
          aria-label={`Remove "${tag.name}" from this entry`}
          title={`Remove "${tag.name}" from this entry`}
          disabled={remove.isPending}
          onClick={(e) => {
            e.stopPropagation();
            remove.mutate(
              { entryId: entryId!, tagId: tag.id! },
              { onError: () => toast.error(`Couldn't remove "${tag.name}"`) },
            );
          }}
        >
          ×
        </button>
      )}
    </span>
  );
}

interface TagChipsProps {
  /** The entry's tags; only the ones promoted to chips render. */
  tags?: EntryTag[];
  /** Needed for the × to remove a chip; without it chips are read-only. */
  entryId?: string;
}

/**
 * The analyst-authored lead of the badge row: tags promoted to chips. Capped at
 * TAG_CHIP_CAP with a `+N` popover for the rest, mirroring the PIR chip, so a
 * few enthusiastic rules can't wrap the scan-line.
 */
export function TagChips({ tags, entryId }: TagChipsProps) {
  const chips = chipTags(tags);
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ top: 0, left: 0 });
  const setHeaderSearchQuery = useUIStore((s) => s.setHeaderSearchQuery);
  const navigate = useNavigate();

  const pivot = useCallback(
    (name: string) => {
      setHeaderSearchQuery(`tag:"${name.replace(/"/g, '\\"')}"`);
      navigate("/search");
      setOpen(false);
    },
    [setHeaderSearchQuery, navigate],
  );

  useEffect(() => {
    if (!open) return;
    if (triggerRef.current) {
      const rect = triggerRef.current.getBoundingClientRect();
      setPos({ top: rect.bottom + 4, left: rect.left });
    }
    const handleClick = (e: MouseEvent) => {
      if (triggerRef.current?.contains(e.target as Node) || popoverRef.current?.contains(e.target as Node)) return;
      setOpen(false);
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    const handleScroll = () => setOpen(false);
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);
    window.addEventListener("scroll", handleScroll, true);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
      window.removeEventListener("scroll", handleScroll, true);
    };
  }, [open]);

  if (chips.length === 0) return null;

  const shown = chips.slice(0, TAG_CHIP_CAP);
  const rest = chips.slice(TAG_CHIP_CAP);

  return (
    // Clicks inside the chip group must not also open the entry card.
    <span className={styles.group} onClick={(e) => e.stopPropagation()}>
      {shown.map((tag) => (
        <TagChipItem key={tag.id ?? tag.name} tag={tag} entryId={entryId} onPivot={pivot} />
      ))}
      {rest.length > 0 && (
        <button
          ref={triggerRef}
          type="button"
          className={styles.more}
          aria-haspopup="true"
          aria-expanded={open}
          title={rest.map((t) => t.name).join(", ")}
          onClick={() => setOpen((o) => !o)}
        >
          +{rest.length}
        </button>
      )}
      {open &&
        createPortal(
          <div
            ref={popoverRef}
            className={styles.popover}
            style={{ top: pos.top, left: pos.left }}
            onClick={(e) => e.stopPropagation()}
          >
            {rest.map((tag) => (
              <TagChipItem key={tag.id ?? tag.name} tag={tag} entryId={entryId} onPivot={pivot} />
            ))}
          </div>,
          document.body,
        )}
    </span>
  );
}
