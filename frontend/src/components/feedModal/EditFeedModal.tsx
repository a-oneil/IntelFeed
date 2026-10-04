import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useDeleteFeed, useUpdateFeed } from "@/hooks/useFeeds";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { useAuthStore } from "@/stores/authStore";
import { confirmDialog } from "@/utils/dialog";
import { FeedSubscribersPanel } from "@/components/FeedSubscribersPanel";
import { FeedTypeIcon } from "@/components/FeedTypeIcon";
import type { Feed } from "@/api/types";
import { useFeedForm, type PaneId } from "./useFeedForm";
import { AssessmentPane } from "./panes/AssessmentPane";
import { IdentityPane } from "./panes/IdentityPane";
import { OverviewPane } from "./panes/OverviewPane";
import { PipelinePane } from "./panes/PipelinePane";
import { SourcePane } from "./panes/SourcePane";
import styles from "./EditFeedModal.module.css";

interface Props {
  subscription: Feed;
  onClose: () => void;
}

interface RailEntry {
  id: PaneId;
  label: string;
  /** Infrastructure panes the API only serves to admins. */
  adminOnly?: boolean;
}

const RAIL: RailEntry[] = [
  { id: "overview", label: "Overview" },
  { id: "identity", label: "Identity" },
  { id: "source", label: "Source", adminOnly: true },
  { id: "pipeline", label: "Pipeline", adminOnly: true },
  { id: "assessment", label: "Assessment" },
  { id: "readers", label: "Readers", adminOnly: true },
];

/**
 * One feed's settings, as six panes behind a rail.
 *
 * The previous version was a single 480px column of 26 fields and 11
 * checkboxes with the action row at the bottom of the scroller, so on a
 * Telegram feed Save sat about 1,300px below the fold. Splitting it means
 * never more than a pane's worth on screen, fixed chrome, and — because the
 * admin/non-admin split now falls on pane boundaries — a non-admin sees three
 * coherent panes rather than a form with holes punched in it.
 */
export function EditFeedModal({ subscription, onClose }: Props) {
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  const form = useFeedForm(subscription);
  const updateFeed = useUpdateFeed();
  const deleteFeed = useDeleteFeed();
  const undoableDelete = useUndoableDelete();

  const rail = useMemo(() => RAIL.filter((r) => isAdmin || !r.adminOnly), [isAdmin]);
  const [pane, setPane] = useState<PaneId>("overview");

  const trapRef = useFocusTrap<HTMLDivElement>();
  const activeRailRef = useRef<HTMLButtonElement>(null);

  // Declared after useFocusTrap so this effect runs second and wins the initial
  // focus. The trap focuses the first focusable element, which is the close
  // button — leaving Enter-on-open meaning "discard and close". The rail's
  // current item is the honest landing spot for a two-pane dialog.
  useEffect(() => {
    activeRailRef.current?.focus();
  }, []);

  // With per-user subscriptions on, unsubscribing only affects the caller;
  // otherwise removal deletes the feed for everyone and is admin-only.
  const canUnsubscribe = isAdmin || Boolean(subscription.per_user);

  const requestClose = async () => {
    if (!form.isDirty) {
      onClose();
      return;
    }
    const ok = await confirmDialog({
      message: "Discard your unsaved changes to this feed?",
      confirmLabel: "Discard",
      destructive: true,
    });
    if (ok) onClose();
  };

  const handleSave = async () => {
    const payload = form.buildPayload(isAdmin, Boolean(subscription.per_user));
    if (Object.keys(payload).length === 0) {
      onClose();
      return;
    }
    try {
      await updateFeed.mutateAsync({ feedId: subscription.id, data: payload });
      onClose();
    } catch {
      // The mutation cache raises a toast; stay open so nothing is lost.
    }
  };

  const handleUnsubscribe = () => {
    const title = subscription.custom_title || subscription.title;
    undoableDelete({
      label: `Feed "${title}"`,
      key: `feed-${subscription.id}`,
      onDelete: () => deleteFeed.mutate(subscription.id),
      onInitiate: () => onClose(),
    });
  };

  const dirtyCount = form.dirtyFields.length;

  // Portalled to the body. Both call sites render this deep inside other
  // components — the sidebar's feed row and, in the reader, an entry card's
  // source line — and an overlay has no business inheriting their text layout
  // or stacking context. It did: the card sets `white-space: nowrap` to
  // truncate its title, so every hint and stage description in here rendered
  // on one clipped line.
  return createPortal(
    <div className={styles.overlay} onClick={requestClose}>
      <div
        className={styles.modal}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.stopPropagation();
            void requestClose();
          }
        }}
        ref={trapRef}
        role="dialog"
        aria-modal="true"
        aria-label={`Edit feed: ${subscription.custom_title || subscription.title}`}
      >
        <div className={styles.header}>
          <span className={styles.headerIcon}>
            <FeedTypeIcon type={subscription.feed_type?.toLowerCase() || "rss"} size={16} />
          </span>
          <div className={styles.headerText}>
            <div className={styles.titleRow}>
              <h2 className={styles.title}>
                {subscription.custom_title || subscription.title}
              </h2>
              <span className={styles.typeChip}>{subscription.feed_type}</span>
              {!subscription.is_active && <span className={styles.pausedChip}>paused</span>}
            </div>
            <span className={styles.headerUrl}>{subscription.url}</span>
          </div>
          <button
            type="button"
            onClick={requestClose}
            className={styles.closeBtn}
            aria-label="Close"
          >
            <svg
              width="15"
              height="15"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              aria-hidden="true"
            >
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className={styles.body}>
          <nav className={styles.rail} aria-label="Feed settings sections">
            {rail.map((entry) => {
              const active = entry.id === pane;
              return (
                <button
                  key={entry.id}
                  type="button"
                  ref={active ? activeRailRef : undefined}
                  className={`${styles.railItem} ${active ? styles.railItemActive : ""}`}
                  aria-current={active ? "true" : undefined}
                  onClick={() => setPane(entry.id)}
                >
                  <span className={styles.railLabel}>{entry.label}</span>
                  {form.dirtyPanes.has(entry.id) && (
                    <span
                      className={styles.railDot}
                      aria-label="has unsaved changes"
                      role="img"
                    />
                  )}
                </button>
              );
            })}
          </nav>

          <div className={styles.pane}>
            {pane === "overview" && (
              <OverviewPane feed={subscription} isAdmin={isAdmin} />
            )}
            {pane === "identity" && <IdentityPane feed={subscription} form={form} isAdmin={isAdmin} />}
            {pane === "source" && isAdmin && (
              <SourcePane feedId={subscription.id} form={form} />
            )}
            {pane === "pipeline" && isAdmin && (
              <PipelinePane feedId={subscription.id} form={form} />
            )}
            {pane === "assessment" && <AssessmentPane form={form} />}
            {pane === "readers" && isAdmin && (
              <FeedSubscribersPanel
                feedId={subscription.id}
                feedTitle={subscription.title}
              />
            )}
          </div>
        </div>

        <div className={styles.footer}>
          {canUnsubscribe && (
            <button type="button" onClick={handleUnsubscribe} className={styles.dangerBtn}>
              Unsubscribe
            </button>
          )}
          <span className={styles.footerSpacer} />
          <span className={dirtyCount ? styles.dirtyNote : styles.cleanNote}>
            {dirtyCount
              ? `${dirtyCount} unsaved change${dirtyCount === 1 ? "" : "s"}`
              : "No changes"}
          </span>
          <button type="button" onClick={requestClose} className={styles.cancelBtn}>
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={updateFeed.isPending || !form.isDirty}
            className={styles.saveBtn}
          >
            {updateFeed.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}
