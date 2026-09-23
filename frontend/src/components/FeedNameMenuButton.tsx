import { useCallback, useEffect, useLayoutEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import { useFeeds } from "@/hooks/useFeeds";
import { useUIStore } from "@/stores/uiStore";
import { EditFeedModal } from "@/components/EditFeedModal";
import styles from "./FeedNameMenuButton.module.css";

interface FeedNameMenuButtonProps {
  feedId: string;
  className?: string;
  children: ReactNode;
}

export function FeedNameMenuButton({ feedId, className, children }: FeedNameMenuButtonProps) {
  const [open, setOpen] = useState(false);
  const [menuStyle, setMenuStyle] = useState<CSSProperties>({});
  const [showEdit, setShowEdit] = useState(false);
  const btnRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const setSelectedFeed = useUIStore((s) => s.setSelectedFeed);
  const { data: feedsData } = useFeeds();

  const compute = useCallback((): CSSProperties => {
    const btn = btnRef.current;
    if (!btn) return { position: "fixed", top: 0, left: 0, zIndex: 1000, visibility: "hidden" };
    const rect = btn.getBoundingClientRect();
    const menu = menuRef.current;
    const menuWidth = menu?.offsetWidth || 220;
    const menuHeight = menu?.offsetHeight || 80;
    const margin = 8;
    let left = rect.left;
    let top = rect.bottom + 4;
    if (left + menuWidth + margin > window.innerWidth) {
      left = Math.max(margin, window.innerWidth - menuWidth - margin);
    }
    if (left < margin) left = margin;
    if (top + menuHeight + margin > window.innerHeight) {
      top = Math.max(margin, rect.top - menuHeight - 4);
    }
    return { position: "fixed", top, left, zIndex: 1000 };
  }, []);

  const openMenu = useCallback(() => {
    setMenuStyle(compute());
    setOpen(true);
  }, [compute]);

  useLayoutEffect(() => {
    if (!open) return;
    const update = () => setMenuStyle(compute());
    update();
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    return () => {
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update, true);
    };
  }, [open, compute]);

  useEffect(() => {
    if (!open) return;
    const handleClick = (e: MouseEvent) => {
      const target = e.target as Node;
      if (btnRef.current?.contains(target)) return;
      if (menuRef.current?.contains(target)) return;
      setOpen(false);
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
    };
  }, [open]);

  const subscription = feedsData?.items.find((s) => s.id === feedId);

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        className={className ? `${styles.btn} ${className}` : styles.btn}
        title="Feed actions"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={(e) => {
          e.stopPropagation();
          if (open) setOpen(false);
          else openMenu();
        }}
      >
        {children}
      </button>
      {open && createPortal(
        <div ref={menuRef} className={styles.menu} role="menu" style={menuStyle}>
          <button
            type="button"
            className={styles.item}
            role="menuitem"
            onClick={(e) => {
              e.stopPropagation();
              setOpen(false);
              setSelectedFeed(feedId);
              navigate("/");
            }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
            </svg>
            Show only this feed's entries
          </button>
          <button
            type="button"
            className={styles.item}
            role="menuitem"
            onClick={(e) => {
              e.stopPropagation();
              setOpen(false);
              setShowEdit(true);
            }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
              <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
            </svg>
            Edit feed
          </button>
        </div>,
        document.body,
      )}
      {showEdit && subscription && (
        <EditFeedModal subscription={subscription} onClose={() => setShowEdit(false)} />
      )}
    </>
  );
}
