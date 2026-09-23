import { useFocusTrap } from "@/hooks/useFocusTrap";
import styles from "./KeyboardShortcutsHelp.module.css";

interface KeyboardShortcutsHelpProps {
  onClose: () => void;
}

const SHORTCUTS = [
  { section: "Navigation", items: [
    { key: "j / \u2193", action: "Next entry" },
    { key: "k / \u2191", action: "Previous entry" },
    { key: "o / Enter", action: "Open original article" },
  ]},
  { section: "Actions", items: [
    { key: "s", action: "Star / unstar entry" },
    { key: "b", action: "Bookmark / unbookmark entry" },
    { key: "m", action: "Toggle read / unread" },
    { key: "Shift+M", action: "Mark all above as read" },
    { key: "t", action: "Add tag to current entry" },
    { key: "e", action: "Export current entry as markdown" },
  ]},
  { section: "Panels", items: [
    { key: "w", action: "Toggle intel panel" },
    { key: "a", action: "Toggle AI panel" },
    { key: "n", action: "Toggle notes panel" },
    { key: "Ctrl+K / \u2318+K", action: "Command palette" },
    { key: "/", action: "Open search" },
    { key: "Escape", action: "Close reader / search / panel" },
    { key: "?", action: "Show this help" },
  ]},
  { section: "Note Editor", items: [
    { key: "Ctrl+S / \u2318+S", action: "Save note" },
    { key: "Ctrl+B / \u2318+B", action: "Bold" },
    { key: "Ctrl+I / \u2318+I", action: "Italic" },
    { key: "Escape", action: "Close editor" },
  ]},
];

export function KeyboardShortcutsHelp({ onClose }: KeyboardShortcutsHelpProps) {
  const trapRef = useFocusTrap<HTMLDivElement>();

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()} ref={trapRef} role="dialog" aria-modal="true" aria-label="Keyboard shortcuts">
        <div className={styles.header}>
          <h2>Keyboard Shortcuts</h2>
          <button className={styles.closeBtn} onClick={onClose} aria-label="Close">&times;</button>
        </div>
        <div className={styles.body}>
          {SHORTCUTS.map((section) => (
            <div key={section.section} className={styles.section}>
              <h3 className={styles.sectionTitle}>{section.section}</h3>
              <div className={styles.shortcutList}>
                {section.items.map((item) => (
                  <div key={item.key} className={styles.shortcutRow}>
                    <kbd className={styles.key}>{item.key}</kbd>
                    <span className={styles.action}>{item.action}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
