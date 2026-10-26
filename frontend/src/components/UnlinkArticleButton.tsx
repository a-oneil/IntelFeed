import { useUnlinkEntity } from "@/hooks/useIntelligence";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { useIsVisitor } from "@/stores/authStore";
import styles from "./UnlinkArticleButton.module.css";

type EntityType =
  | "ttp"
  | "cve"
  | "cwe"
  | "threat_actor"
  | "malware"
  | "country"
  | "sector"
  | "mitigation"
  | "tool"
  | "vendor"
  | "product"
  | "observable";

interface UnlinkArticleButtonProps {
  entryId: string;
  entityId: string;
  entityType: EntityType;
}

export function UnlinkArticleButton({
  entryId,
  entityId,
  entityType,
}: UnlinkArticleButtonProps) {
  const unlink = useUnlinkEntity();
  const undoableDelete = useUndoableDelete();
  // Unlinking curates the instance's data; a visitor only reads it.
  const isVisitor = useIsVisitor();
  if (isVisitor) return null;

  return (
    <button
      className={styles.unlinkBtn}
      title="Unlink"
      onClick={(e) => {
        e.stopPropagation();
        undoableDelete({
          label: "Article link",
          key: `unlink-${entryId}-${entityId}`,
          onDelete: () => unlink.mutate({ entryId, entityId, entityType }),
        });
      }}
      disabled={unlink.isPending}
    >
      {unlink.isPending ? "..." : "\u2717"}
    </button>
  );
}
