/**
 * EntityActionsMenu — the entity maintenance menu, shared by the profile hero
 * and the workbench entity tables. High-frequency actions sit at the top and
 * destructive ones live below a separator.
 *
 * Two variants:
 * - "header": anchored under the profile's ⋯ button (absolute positioning).
 * - "row":    opened from a table row's ⋯ cell. Positions itself fixed against
 *             the trigger so it escapes the table's scroll clipping, and adds
 *             the actions a profile doesn't need buttons for — Open profile and
 *             Edit (the profile's inline editors gathered into one form).
 */
import { useState, useRef, useEffect, useLayoutEffect, useCallback, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

import api from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { useDeleteWatch, useUpsertWatch, useWatchlist } from "@/hooks/useWatchlist";
import { useDenyObservable } from "@/hooks/useIntelligence";
import { confirmDialog } from "@/utils/dialog";

const WATCHABLE_TYPES = ["threat_actor", "malware", "cve", "tool", "vendor", "product", "country", "sector"];

/** Report entity_ids buckets by entity type — types without a bucket attach
 *  their linked articles only. */
const ENTITY_ID_BUCKETS: Record<string, string> = {
  threat_actor: "actors",
  malware: "malware",
  cve: "cves",
  ttp: "ttps",
  country: "countries",
  observable: "observables",
};
import { useCampaigns, useAddCampaignEntity } from "@/hooks/useCampaigns";
import { useUIStore } from "@/stores/uiStore";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import {
  useGenerateEntitySummary,
  useUnlinkAllEntries,
  useConvertEntity,
  useFetchWikipedia,
  useRescanEntity,
  DENIABLE_ENTITY_TYPES,
  useDeleteEntity,
  useDenyEntityName,
  MERGEABLE_ENTITY_TYPES,
} from "@/hooks/useEntityProfile";
import { useClearEntityTimeline } from "@/hooks/useCorrelation";
import { exportEntityProfile } from "@/hooks/useExport";
import { getEntityLabel } from "@/utils/entityTheme";
import { convertTargetsFor, runEntityConvert, type ConvertTarget } from "@/utils/entityConvert";
import { CascadePreview } from "@/components/CascadePreview";
import { EntityMergeIntoModal } from "@/components/EntityMergeIntoModal";
import type { EntityType } from "@/stores/intelStore";
import type { EntitySearchResult } from "@/api/types";
import { EntityEditModal, isEditableEntityType } from "./EntityEditModal";
import {
  getEntityProfileConfig,
  entityProfilePath,
  type EntityProfileConfig,
} from "./entityProfileConfig";
import styles from "./entityProfile.module.css";


export function EntityActionsMenu({
  entityType,
  entityId,
  config: configProp,
  displayName,
  entity,
  entries,
  onNavigateAway,
  variant = "header",
  defaultOpen = false,
}: {
  entityType: EntityType;
  entityId: string;
  /** Defaults to the type's profile config — row callers don't need to pass it. */
  config?: EntityProfileConfig;
  displayName: string;
  /** Row payload, used to seed the edit form (the profile passes its entity). */
  entity?: EntitySearchResult;
  /** Entries linked to the entity; the report wizard needs their ids. Row
   *  callers omit this and the pivot is fetched on demand. */
  entries?: Array<{ id: string }>;
  /** Called when the entity this menu acts on stops existing (delete, convert). */
  onNavigateAway?: () => void;
  variant?: "header" | "row";
  /** Row callers mount this component on the first ⋯ click — open immediately. */
  defaultOpen?: boolean;
}) {
  const config = configProp ?? getEntityProfileConfig(entityType);
  const isRow = variant === "row";
  const navigate = useNavigate();

  const [campaignMenuOpen, setCampaignMenuOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(defaultOpen);
  const [convertOpen, setConvertOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  // Opt-in on the delete popover: also ban the name from being re-created.
  const [denyOnDelete, setDenyOnDelete] = useState(false);
  const [mergeModalOpen, setMergeModalOpen] = useState(false);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [loadingReport, setLoadingReport] = useState(false);
  // Row menus render fixed so they escape the table's scroll container.
  const [anchor, setAnchor] = useState<{ top?: number; bottom?: number; right: number; maxHeight: number } | null>(null);

  const menuWrapRef = useRef<HTMLDivElement>(null);
  const floatRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  const { data: campaignsData } = useCampaigns({ limit: 100 });
  const { data: watchlist } = useWatchlist();
  const upsertWatch = useUpsertWatch();
  const deleteWatch = useDeleteWatch();
  const watchState =
    watchlist?.find((w) => w.entity_type === entityType && w.entity_id === entityId)?.mode ?? null;
  const addToCampaign = useAddCampaignEntity();
  const unlinkAll = useUnlinkAllEntries();
  const clearTimeline = useClearEntityTimeline();
  const convertEntity = useConvertEntity();
  const fetchWikipedia = useFetchWikipedia();
  const rescanEntity = useRescanEntity();
  const runAIOnEntity = useGenerateEntitySummary();
  const undoableDelete = useUndoableDelete();

  // Merge, convert, unlink-all and the observable tombstone are admin-only.
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");

  const deleteEntity = useDeleteEntity();
  const denyEntityName = useDenyEntityName();
  const denyObservable = useDenyObservable();
  // An observable has no name to ban — its "don't bring it back" is the deny
  // tombstone, which keeps the row instead of deleting it.
  const isObservable = entityType === "observable";
  const canDeny = DENIABLE_ENTITY_TYPES.has(entityType) || (isObservable && isAdmin);

  const closeMenu = useCallback(() => {
    setMenuOpen(false);
    setConvertOpen(false);
    setCampaignMenuOpen(false);
    setConfirmDelete(false);
    setDenyOnDelete(false);
  }, []);

  useEffect(() => {
    if (!menuOpen) return;
    const onDown = (e: MouseEvent) => {
      const target = e.target as Node;
      if (menuWrapRef.current?.contains(target) || floatRef.current?.contains(target)) return;
      closeMenu();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeMenu();
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    // A fixed menu can't follow its row, so scrolling the table dismisses it.
    if (isRow) window.addEventListener("scroll", closeMenu, true);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
      if (isRow) window.removeEventListener("scroll", closeMenu, true);
    };
  }, [menuOpen, isRow, closeMenu]);

  // Anchor a row menu to its trigger, flipping above the row when the space
  // below it can't hold the menu.
  const anchorToTrigger = useCallback(() => {
    const el = triggerRef.current;
    if (!isRow || !el) return;
    const rect = el.getBoundingClientRect();
    const right = Math.max(8, window.innerWidth - rect.right);
    const below = window.innerHeight - rect.bottom - 12;
    const above = rect.top - 12;
    // Open downward unless the row sits low enough that flipping buys real
    // room; either way the menu scrolls inside whatever space it gets.
    setAnchor(
      below < 240 && above > below
        ? { bottom: window.innerHeight - rect.top + 4, right, maxHeight: above }
        : { top: rect.bottom + 4, right, maxHeight: below },
    );
  }, [isRow]);

  useLayoutEffect(() => {
    if (defaultOpen) anchorToTrigger();
    // Mount-only: later opens go through toggleMenu.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const toggleMenu = () => {
    if (menuOpen) {
      closeMenu();
      return;
    }
    anchorToTrigger();
    setMenuOpen(true);
  };

  // Fixed placement for row menus; the header variant keeps its CSS anchoring.
  const floatStyle: React.CSSProperties | undefined =
    isRow && anchor
      ? {
          position: "fixed",
          top: anchor.top,
          bottom: anchor.bottom,
          right: anchor.right,
          left: "auto",
          maxHeight: anchor.maxHeight,
          overflowY: "auto",
        }
      : undefined;

  // A virtualized row is inside a `transform`ed wrapper, which would become the
  // containing block for anything position:fixed — so row popovers and modals
  // are portaled out to the body instead.
  const escapeRow = (node: ReactNode) =>
    isRow
      ? createPortal(
          // React events still bubble through a portal, so the row's own click
          // handler is stopped here rather than on every popover inside.
          <div onClick={(e) => e.stopPropagation()}>{node}</div>,
          document.body,
        )
      : node;

  const has = (key: EntityProfileConfig["actions"][number]) => config.actions.includes(key);

  const handleDelete = useCallback(
    (deny: boolean) => {
      // Denying an observable keeps its row as the tombstone, so that path
      // replaces the delete rather than preceding it.
      const tombstone = isObservable && deny;
      undoableDelete({
        label: `${entityType.replace(/_/g, " ")} "${displayName}"`,
        verb: tombstone ? "tombstoned" : "deleted",
        key: `entity-${entityType}-${entityId}`,
        onDelete: async () => {
          try {
            if (tombstone) {
              await denyObservable.mutateAsync(entityId);
              toast.success(`${displayName} won't be captured or exported again`);
              return;
            }
            // Denial reads the live entity, so it has to run before the delete.
            if (deny) await denyEntityName.mutateAsync({ entityType, entityId });
            await deleteEntity(entityType, entityId);
            if (deny) toast.success(`${displayName} won't be re-created by extraction`);
          } catch {
            toast.error(`Couldn't ${tombstone ? "tombstone" : "delete"} ${displayName}`);
          }
        },
        onInitiate: () => onNavigateAway?.(),
      });
    },
    [entityType, entityId, displayName, isObservable, onNavigateAway, undoableDelete, deleteEntity, denyEntityName, denyObservable],
  );

  const handleExportMarkdown = async () => {
    setExporting(true);
    try {
      await exportEntityProfile(entityType, entityId);
      toast.success("Profile exported as Markdown");
    } catch {
      toast.error("Failed to export profile");
    } finally {
      setExporting(false);
      closeMenu();
    }
  };

  const handleAISummary = () => {
    closeMenu();
    runAIOnEntity.mutate(
      { entityType, entityId },
      {
        onSuccess: () => toast.success("AI summary generated and saved"),
        onError: (err: unknown) =>
          toast.error((err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || "Failed to generate summary"),
      },
    );
  };

  // Row menus have no pivot loaded, so the linked entries the wizard reports on
  // are fetched at click time.
  const handleGenerateReport = async () => {
    let entryIds = (entries ?? []).map((e) => e.id);
    if (entryIds.length === 0) {
      setLoadingReport(true);
      try {
        const { data } = await api.get<{ entries?: Array<{ id: string }> }>(
          `/intelligence/pivot/${entityType}/${entityId}`,
        );
        entryIds = (data.entries ?? []).map((e) => e.id);
      } catch {
        toast.error("Couldn't load linked articles");
        setLoadingReport(false);
        return;
      }
      setLoadingReport(false);
    }
    closeMenu();
    if (entryIds.length === 0) {
      toast.error("No linked articles to report on");
      return;
    }
    const bucket = ENTITY_ID_BUCKETS[entityType];
    useUIStore.getState().openSendToReport({
      entryIds,
      entityIds: bucket ? { [bucket]: [entityId] } : undefined,
      label: `${getEntityLabel(entityType)}: ${displayName}`,
      wizardState: {
        sourceType: "entries",
        entryIds,
        entryTitle: `${getEntityLabel(entityType)}: ${displayName}`,
      },
    });
  };

  const handleConvert = (opt: ConvertTarget) => {
    setConvertOpen(false);
    setMenuOpen(false);
    void runEntityConvert({
      entityType,
      entityId,
      target: opt,
      convert: convertEntity,
      onConverted: () => onNavigateAway?.(),
    });
  };

  const convertTargets = convertTargetsFor(entityType);
  const canConvert = isAdmin && has("convert") && convertTargets.length > 0;
  const canMerge = isAdmin && has("merge") && MERGEABLE_ENTITY_TYPES.includes(entityType as (typeof MERGEABLE_ENTITY_TYPES)[number]);
  const canEdit = isRow && !!entity && isEditableEntityType(entityType);

  return (
    <>
      <div className={styles.actionsMenuWrap} ref={menuWrapRef}>
        <button
          ref={triggerRef}
          className={isRow ? styles.rowMenuBtn : styles.menuBtn}
          aria-label={isRow ? `Actions for ${displayName}` : "More actions"}
          onClick={(e) => {
            e.stopPropagation();
            toggleMenu();
          }}
        >
          ⋯
        </button>
        {menuOpen && !confirmDelete && escapeRow(
          <div ref={floatRef} className={styles.menu} style={floatStyle}>
            {isRow && (
              <button
                className={styles.menuItem}
                onClick={() => {
                  closeMenu();
                  navigate(entityProfilePath(entityType, entityId));
                }}
              >
                Open profile
              </button>
            )}
            {canEdit && (
              <button
                className={styles.menuItem}
                onClick={() => {
                  closeMenu();
                  setEditModalOpen(true);
                }}
              >
                Edit…
              </button>
            )}
            {has("add_to_campaign") && (
              <>
                <button className={styles.menuItem} onClick={() => setCampaignMenuOpen((o) => !o)}>
                  Add to campaign
                </button>
                {campaignMenuOpen && (
                  <div className={styles.submenu} style={{ maxHeight: 240, overflowY: "auto" }}>
                    {campaignsData?.items?.length ? (
                      campaignsData.items.map((c) => (
                        <button
                          key={c.id}
                          className={styles.menuItem}
                          onClick={() => {
                            addToCampaign.mutate({ campaignId: c.id, entityType, entityId });
                            setCampaignMenuOpen(false);
                            setMenuOpen(false);
                            toast.success(`Added to ${c.name}`);
                          }}
                        >
                          {c.name}
                        </button>
                      ))
                    ) : (
                      <span className={styles.menuItem} style={{ opacity: 0.5 }}>No campaigns</span>
                    )}
                  </div>
                )}
              </>
            )}
            {has("ai_summary") && (
              <button className={styles.menuItem} disabled={runAIOnEntity.isPending} onClick={handleAISummary}>
                {runAIOnEntity.isPending ? "Summarizing…" : "AI summary"}
              </button>
            )}
            {canConvert && (
              <>
                <button className={styles.menuItem} onClick={() => setConvertOpen((o) => !o)}>
                  Convert type
                </button>
                {convertOpen && (
                  <div className={styles.submenu}>
                    {convertTargets.map((opt) => (
                      <button key={opt.key} className={styles.menuItem} onClick={() => handleConvert(opt)}>
                        {opt.label}
                      </button>
                    ))}
                  </div>
                )}
              </>
            )}
            <button className={styles.menuItem} disabled={exporting} onClick={handleExportMarkdown}>
              {exporting ? "Exporting…" : "Export as Markdown"}
            </button>
            {has("fetch_wikipedia") && (
              <button
                className={styles.menuItem}
                disabled={fetchWikipedia.isPending}
                onClick={() => {
                  fetchWikipedia.mutate({ entityType, entityId });
                  closeMenu();
                }}
              >
                {fetchWikipedia.isPending ? "Fetching…" : "Fetch Wikipedia"}
              </button>
            )}
            {(entityType === "vendor" || entityType === "product") && (
              <button
                className={styles.menuItem}
                title="Follow this vendor/product — its vulnerabilities surface in Vendor Watch and your Radar"
                onClick={() => {
                  if (watchState === "stack") {
                    deleteWatch.mutate({ entity_type: entityType, entity_id: entityId });
                    toast.success(`Unfollowed ${displayName}`);
                  } else {
                    upsertWatch.mutate({ entity_type: entityType, entity_id: entityId, mode: "stack" });
                    toast.success(`Following ${displayName} — its vulnerabilities will surface in Vendor Watch`);
                  }
                  closeMenu();
                }}
              >
                {watchState === "stack" ? "Unfollow" : "Follow for vuln alerts"}
              </button>
            )}
            {has("generate_report") && (
              <button className={styles.menuItem} disabled={loadingReport} onClick={handleGenerateReport}>
                {loadingReport ? "Loading articles…" : "Generate report"}
              </button>
            )}
            {canMerge && (
              <button className={styles.menuItem} onClick={() => { closeMenu(); setMergeModalOpen(true); }}>
                Merge…
              </button>
            )}
            {WATCHABLE_TYPES.includes(entityType) && (
              <button
                className={styles.menuItem}
                onClick={() => {
                  if (watchState === "mute") {
                    deleteWatch.mutate({ entity_type: entityType, entity_id: entityId });
                    toast.success("Mute removed");
                  } else {
                    upsertWatch.mutate({ entity_type: entityType, entity_id: entityId, mode: "mute" });
                    toast.success("Muted — mentions suppressed from Radar");
                  }
                  closeMenu();
                }}
              >
                {watchState === "mute" ? "Unmute entity" : "Mute entity"}
              </button>
            )}
            {has("rescan") && (
              <button
                className={styles.menuItem}
                disabled={rescanEntity.isPending}
                title="Re-scan all existing articles for mentions of this entity"
                onClick={() => {
                  rescanEntity.mutate(
                    { entityType, entityId },
                    {
                      onSuccess: () => toast.success("Re-scan queued — new links will appear shortly"),
                      onError: () => toast.error("Failed to queue re-scan"),
                    },
                  );
                  closeMenu();
                }}
              >
                {rescanEntity.isPending ? "Queuing…" : "Re-scan articles"}
              </button>
            )}
            {WATCHABLE_TYPES.includes(entityType) && (
              <button
                className={styles.menuItem}
                onClick={() => {
                  if (watchState === "watch") {
                    deleteWatch.mutate({ entity_type: entityType, entity_id: entityId });
                    toast.success("Watch removed");
                  } else {
                    upsertWatch.mutate({ entity_type: entityType, entity_id: entityId, mode: "watch" });
                    toast.success("Watching — mentions get a priority boost");
                  }
                  closeMenu();
                }}
              >
                {watchState === "watch" ? "Unwatch entity" : "Watch entity"}
              </button>
            )}

            <div className={styles.menuSep} />

            {has("clear_timeline") && (
              <button
                className={`${styles.menuItem} ${styles.menuItemDanger}`}
                onClick={async () => {
                  if (
                    !(await confirmDialog({
                      title: "Clear timeline",
                      message: "Clear all timeline events for this entity?",
                      confirmLabel: "Clear timeline",
                      destructive: true,
                    }))
                  )
                    return;
                  clearTimeline.mutate({ entityType, entityId });
                  closeMenu();
                }}
              >
                Clear timeline
              </button>
            )}
            {has("delete") && (
              <button className={`${styles.menuItem} ${styles.menuItemDanger}`} onClick={() => setConfirmDelete(true)}>
                Delete…
              </button>
            )}
            {isAdmin && has("unlink_all") && (
              <button
                className={`${styles.menuItem} ${styles.menuItemDanger}`}
                onClick={async () => {
                  if (
                    !(await confirmDialog({
                      title: "Unlink all entries",
                      message: "Unlink all entries from this entity?",
                      confirmLabel: "Unlink all",
                      destructive: true,
                    }))
                  )
                    return;
                  unlinkAll.mutate(
                    { entityType, entityId },
                    { onSuccess: (data) => toast.success(`Unlinked ${data.unlinked} entries`) },
                  );
                  closeMenu();
                }}
              >
                Unlink all entries
              </button>
            )}
          </div>
        )}

        {menuOpen && confirmDelete && escapeRow(
          <div
            ref={floatRef}
            className={styles.deletePopover}
            style={floatStyle}
            role="dialog"
            aria-label="Confirm delete"
          >
            <div className={styles.deletePopoverTitle}>
              Delete {isRow ? displayName : `this ${getEntityLabel(entityType).toLowerCase()}`}?
            </div>
            {config.cascadeType && <CascadePreview entity_type={config.cascadeType} entity_id={entityId} />}
            {canDeny && (
              <label className={styles.deletePopoverOption}>
                <input
                  type="checkbox"
                  checked={denyOnDelete}
                  onChange={(e) => setDenyOnDelete(e.target.checked)}
                />
                <span>
                  {isObservable ? "Never capture it again" : "Don't re-create it"}
                  <span className={styles.deletePopoverHint}>
                    {isObservable
                      ? "Keeps the row as a tombstone instead of deleting it, so every capture door and the outbound feeds refuse the value from now on."
                      : "Adds the name and aliases to the do-not-recreate list, so AI extraction and the autolinker stop bringing it back."}
                  </span>
                </span>
              </label>
            )}
            <div className={styles.deletePopoverActions}>
              <button className={styles.confirmNo} onClick={closeMenu}>
                Cancel
              </button>
              <button
                className={styles.confirmYes}
                onClick={() => {
                  const deny = denyOnDelete;
                  closeMenu();
                  handleDelete(deny);
                }}
              >
                Confirm Delete
              </button>
            </div>
          </div>
        )}
      </div>

      {mergeModalOpen && escapeRow(
        <EntityMergeIntoModal
          entityType={entityType}
          keeperId={entityId}
          keeperName={displayName}
          onClose={() => setMergeModalOpen(false)}
          onMerged={onNavigateAway}
        />
      )}

      {editModalOpen && entity && escapeRow(
        <EntityEditModal
          entityType={entityType}
          entityId={entityId}
          entity={entity}
          displayName={displayName}
          onClose={() => setEditModalOpen(false)}
        />
      )}
    </>
  );
}

/**
 * A table row's ⋯ actions cell. Renders an inert trigger and swaps in the real
 * menu on first click — EntityActionsMenu mounts around twenty data hooks, and
 * a hundred loaded rows shouldn't each pay for them.
 */
export function EntityRowActionsCell({
  entityType,
  entityId,
  displayName,
  entity,
}: {
  entityType: EntityType;
  entityId: string;
  displayName: string;
  entity: EntitySearchResult;
}) {
  const [mounted, setMounted] = useState(false);

  if (!mounted) {
    return (
      <button
        className={styles.rowMenuBtn}
        aria-label={`Actions for ${displayName}`}
        onClick={(e) => {
          e.stopPropagation();
          setMounted(true);
        }}
      >
        ⋯
      </button>
    );
  }

  return (
    <EntityActionsMenu
      variant="row"
      defaultOpen
      entityType={entityType}
      entityId={entityId}
      displayName={displayName}
      entity={entity}
    />
  );
}
