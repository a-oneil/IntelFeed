import { useState, useRef, useEffect, useLayoutEffect, type ReactNode, type CSSProperties } from "react";
import { createPortal } from "react-dom";
import styles from "./ToolbarDropdown.module.css";

interface ToolbarDropdownProps {
  label: string;
  icon?: ReactNode;
  children: ReactNode;
}

export function ToolbarDropdown({ label, icon, children }: ToolbarDropdownProps) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const [panelStyle, setPanelStyle] = useState<CSSProperties>({});

  useLayoutEffect(() => {
    if (!open || !triggerRef.current) return;
    const isMobile = window.matchMedia("(max-width: 767px)").matches;
    if (isMobile) {
      setPanelStyle({});
      return;
    }
    const update = () => {
      if (!triggerRef.current) return;
      const rect = triggerRef.current.getBoundingClientRect();
      setPanelStyle({
        position: "fixed",
        top: rect.bottom + 4,
        right: window.innerWidth - rect.right,
      });
    };
    update();
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    return () => {
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update, true);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;

    function handleClickOutside(e: MouseEvent) {
      const target = e.target as Node;
      if (containerRef.current?.contains(target)) return;
      if (panelRef.current?.contains(target)) return;
      setOpen(false);
    }

    function handleEscape(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setOpen(false);
      }
    }

    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleEscape);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleEscape);
    };
  }, [open]);

  return (
    <div className={styles.container} ref={containerRef}>
      <button
        ref={triggerRef}
        className={`${styles.trigger} ${open ? styles.triggerOpen : ""}`}
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-haspopup="true"
        aria-label={label}
      >
        {icon && <span className={styles.triggerIcon}>{icon}</span>}
        <span className={styles.triggerLabel}>{label}</span>
        <svg className={styles.chevron} width="10" height="10" viewBox="0 0 10 10" fill="none">
          <path d="M2.5 3.75L5 6.25L7.5 3.75" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>

      {open && createPortal(
        <div
          ref={panelRef}
          className={styles.panel}
          role="menu"
          style={panelStyle}
          onClick={() => setOpen(false)}
        >
          {children}
        </div>,
        document.body,
      )}
    </div>
  );
}

interface DropdownItemProps {
  icon?: ReactNode;
  label: string;
  onClick?: () => void;
  href?: string;
  active?: boolean;
  shortcut?: string;
}

export function DropdownItem({ icon, label, onClick, href, active, shortcut }: DropdownItemProps) {
  const className = `${styles.item} ${active ? styles.itemActive : ""}`;

  if (href) {
    return (
      <a
        className={className}
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        role="menuitem"
      >
        {icon && <span className={styles.itemIcon}>{icon}</span>}
        <span className={styles.itemLabel}>{label}</span>
        {shortcut && <span className={styles.itemShortcut}>{shortcut}</span>}
      </a>
    );
  }

  return (
    <button className={className} onClick={onClick} role="menuitem">
      {icon && <span className={styles.itemIcon}>{icon}</span>}
      <span className={styles.itemLabel}>{label}</span>
      {shortcut && <span className={styles.itemShortcut}>{shortcut}</span>}
    </button>
  );
}

interface DropdownSubMenuProps {
  label: string;
  icon?: ReactNode;
  children: ReactNode;
}

export function DropdownSubMenu({ label, icon, children }: DropdownSubMenuProps) {
  return (
    <div className={styles.subMenu}>
      <div className={styles.subMenuLabel}>
        {icon && <span className={styles.itemIcon}>{icon}</span>}
        {label}
      </div>
      <div className={styles.subMenuContent}>{children}</div>
    </div>
  );
}
