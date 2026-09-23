import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { useWatchlist, useUpsertWatch, useDeleteWatch, type EntityWatch } from "@/hooks/useWatchlist";
import { Chip, PageHeader } from "@/components/primitives";
import { entityProfilePath, ENTITY_PROFILE_CONFIG } from "@/components/entityProfile/entityProfileConfig";
import { getEntityCssVar } from "@/utils/entityTheme";
import { DataTable, type DataTableColumn } from "@/components/table/DataTable";
import { NameCell, ActionsCell, RowActionButton } from "@/components/table/cells";
import type { EntityType } from "@/stores/intelStore";
import styles from "./WatchlistPanel.module.css";

const ENTITY_TYPE_LABEL: Record<string, string> = {
  threat_actor: "Threat Actor",
  malware: "Malware",
  cve: "CVE",
  tool: "Tool",
  vendor: "Vendor",
  product: "Product",
  country: "Country",
};

function isKnownEntityType(t: string): t is EntityType {
  return t in ENTITY_PROFILE_CONFIG;
}

export function WatchlistPanel() {
  const navigate = useNavigate();
  const { data: watches, isLoading, isError } = useWatchlist();
  const upsertWatch = useUpsertWatch();
  const deleteWatch = useDeleteWatch();

  const rows = watches ?? [];
  const watchedCount = rows.filter((w) => w.mode === "watch").length;
  const mutedCount = rows.length - watchedCount;

  const handleBoostChange = async (w: EntityWatch, boost: number) => {
    try {
      await upsertWatch.mutateAsync({ entity_type: w.entity_type, entity_id: w.entity_id, mode: "watch", boost });
    } catch {
      toast.error("Failed to update boost");
    }
  };

  const handleRemove = async (w: EntityWatch) => {
    try {
      await deleteWatch.mutateAsync({ entity_type: w.entity_type, entity_id: w.entity_id });
      toast.success(`Removed ${w.entity_name ?? w.entity_id} from ${w.mode === "watch" ? "watchlist" : "mute list"}`);
    } catch {
      toast.error("Failed to remove");
    }
  };

  const openEntity = (w: EntityWatch) => {
    if (isKnownEntityType(w.entity_type)) navigate(entityProfilePath(w.entity_type, w.entity_id));
  };

  // Mutations are captured per render, so the column set has to be rebuilt when
  // their pending state flips — otherwise Remove stays enabled mid-delete.
  const columns: DataTableColumn<EntityWatch>[] = useMemo(() => [
    {
      key: "entity", label: "Entity", width: 280, minWidth: 140, flex: true,
      textValue: (w) => w.entity_name ?? w.entity_id,
      sortValue: (w) => (w.entity_name ?? w.entity_id).toLowerCase(),
      render: (w) => <NameCell value={w.entity_name ?? w.entity_id} />,
    },
    {
      key: "entity_type", label: "Type", width: 130, minWidth: 90,
      textValue: (w) => ENTITY_TYPE_LABEL[w.entity_type] ?? w.entity_type,
      choices: [
        { value: "all", label: "Any type" },
        ...Object.entries(ENTITY_TYPE_LABEL).map(([value, label]) => ({ value, label })),
      ],
      choiceMatch: (w, v) => w.entity_type === v,
      render: (w) => (
        <Chip truncate marker tint={getEntityCssVar(w.entity_type)}>
          {ENTITY_TYPE_LABEL[w.entity_type] ?? w.entity_type}
        </Chip>
      ),
    },
    {
      // Replaces the two hand-rolled "Watching" / "Muted" sections: one list,
      // one filter — the same shape as every other workbench table.
      key: "mode", label: "Mode", width: 110, minWidth: 90,
      textValue: (w) => w.mode,
      sortValue: (w) => w.mode,
      choices: [
        { value: "all", label: "Watched + muted" },
        { value: "watch", label: "Watched" },
        { value: "mute", label: "Muted" },
      ],
      choiceMatch: (w, v) => w.mode === v,
      render: (w) =>
        w.mode === "watch" ? (
          <Chip tone="toned" tint="var(--success)">watching</Chip>
        ) : (
          <Chip tone="toned" tint="var(--text-muted)">muted</Chip>
        ),
    },
    {
      key: "boost", label: "Boost", width: 90, minWidth: 74,
      sortValue: (w) => (w.mode === "watch" ? w.boost : -1),
      render: (w) =>
        w.mode === "watch" ? (
          <input
            type="number"
            min={0}
            max={5}
            step={0.5}
            defaultValue={w.boost}
            className={styles.boostInput}
            onClick={(e) => e.stopPropagation()}
            onBlur={(e) => {
              const next = Number(e.target.value);
              if (!Number.isNaN(next) && next !== w.boost) handleBoostChange(w, next);
            }}
          />
        ) : (
          /* Boost is meaningless on a mute — muting suppresses the entity outright. */
          <span className={styles.zero}>·</span>
        ),
    },
    {
      key: "actions", label: "", width: 90, minWidth: 90, sticky: "right",
      render: (w) => (
        <ActionsCell>
          <RowActionButton danger onClick={() => handleRemove(w)} disabled={deleteWatch.isPending}>
            Remove
          </RowActionButton>
        </ActionsCell>
      ),
    },
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [deleteWatch.isPending]);

  if (isError) return <div className={styles.error}>Failed to load watchlist.</div>;

  return (
    <>
      <PageHeader
        title="Watchlist"
        count={`${watchedCount} watched · ${mutedCount} muted`}
        subtitle="Watched entities get a priority boost in Triage; muted entities are suppressed. Use the eye icon on any entity profile to add one."
      />
      <DataTable<EntityWatch>
        tableId="watchlist"
        columns={columns}
        rows={rows}
        getRowId={(w) => `${w.entity_type}:${w.entity_id}`}
        onRowClick={openEntity}
        isLoading={isLoading}
        noun="entity"
        nounPlural="entities"
        emptyMessage="Nothing watched or muted yet — use the eye icon on an entity profile to add one."
      />
    </>
  );
}
