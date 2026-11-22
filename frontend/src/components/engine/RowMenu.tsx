/**
 * RowMenu — a "⋯" menu for a Review row that is not about one catalogue
 * entity (a relationship edge, an article): open either end, open the graph.
 * Same trigger and popover as EntityRowActions, so every row ends the same way.
 */

import { useEffect, useRef, useState } from "react";

import styles from "./EntityRowActions.module.css";

export interface RowMenuItem {
  label: string;
  onClick: () => void;
  danger?: boolean;
}

export function RowMenu({ items, name, disabled }: { items: RowMenuItem[]; name: string; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const btnRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    const onDown = (e: MouseEvent) => {
      if (menuRef.current?.contains(e.target as Node) || btnRef.current?.contains(e.target as Node)) return;
      close();
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [open]);

  if (items.length === 0) return null;

  function toggle() {
    if (!open && btnRef.current) {
      const r = btnRef.current.getBoundingClientRect();
      setPos({ top: r.bottom + 4, left: r.right });
    }
    setOpen((o) => !o);
  }

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        className={styles.trigger}
        title={`More actions for ${name}`}
        aria-label={`More actions for ${name}`}
        aria-haspopup="menu"
        aria-expanded={open}
        disabled={disabled}
        onClick={toggle}
      >
        ⋯
      </button>
      {open && pos && (
        <div ref={menuRef} className={styles.menu} style={{ top: pos.top, left: pos.left }} role="menu">
          {items.map((it) => (
            <button
              key={it.label}
              type="button"
              className={`${styles.item} ${it.danger ? styles.danger : ""}`}
              role="menuitem"
              onClick={() => {
                setOpen(false);
                it.onClick();
              }}
            >
              {it.label}
            </button>
          ))}
        </div>
      )}
    </>
  );
}
