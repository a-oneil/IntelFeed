import { useEffect, useRef } from "react";
import type { CopilotCommand } from "@/components/copilotCommands";
import styles from "./SlashCommandMenu.module.css";

interface SlashCommandMenuProps {
  /** Filtered commands to display (already matched against the typed query). */
  commands: CopilotCommand[];
  /** Index of the currently highlighted command (arrow-key navigation). */
  activeIndex: number;
  /** Select a command (Enter/click) — parent fills the input with its prompt. */
  onSelect: (command: CopilotCommand) => void;
  /** Hover/keyboard move updates the active index. */
  onHover: (index: number) => void;
}

/**
 * Floating menu of preset copilot slash commands, rendered above the input when
 * the user types "/" at the start of an empty input. Purely presentational:
 * keyboard handling (arrows/Enter/Esc) lives in the parent's key handler; this
 * component only renders rows and reports hover/click.
 */
export function SlashCommandMenu({
  commands,
  activeIndex,
  onSelect,
  onHover,
}: SlashCommandMenuProps) {
  const listRef = useRef<HTMLDivElement>(null);

  // Keep the highlighted row scrolled into view as the user arrows through.
  useEffect(() => {
    const active = listRef.current?.querySelector<HTMLElement>(
      `[data-index="${activeIndex}"]`,
    );
    active?.scrollIntoView({ block: "nearest" });
  }, [activeIndex]);

  if (commands.length === 0) return null;

  return (
    <div className={styles.menu} role="listbox" aria-label="Slash commands">
      <div className={styles.list} ref={listRef}>
        {commands.map((command, i) => (
          <button
            key={command.id}
            type="button"
            data-index={i}
            role="option"
            aria-selected={i === activeIndex}
            className={`${styles.row} ${i === activeIndex ? styles.rowActive : ""}`}
            // Prevent the textarea from blurring before the click registers.
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => onSelect(command)}
            onMouseEnter={() => onHover(i)}
          >
            <span className={styles.label}>{command.label}</span>
            <span className={styles.hint}>{command.hint}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
