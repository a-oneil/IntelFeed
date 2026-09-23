import { useState, useMemo } from "react";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import type { Theme } from "@/api/types";
import styles from "./ThemeEditor.module.css";

interface Props {
  theme?: Theme;
  onSave: (name: string, vars: Record<string, string>) => void;
  onClose: () => void;
}

interface ColorGroup {
  label: string;
  vars: string[];
}

const COLOR_GROUPS: ColorGroup[] = [
  {
    label: "Backgrounds",
    vars: ["bg-primary", "bg-secondary", "bg-tertiary", "bg-hover"],
  },
  {
    label: "Text",
    vars: ["text-primary", "text-secondary", "text-muted"],
  },
  {
    label: "Accent",
    vars: ["accent", "accent-hover", "accent-text"],
  },
  {
    label: "UI",
    vars: ["border", "danger", "success", "warning"],
  },
  {
    label: "Sidebar",
    vars: ["sidebar-bg", "sidebar-hover", "sidebar-active"],
  },
  {
    label: "Cards",
    vars: ["card-bg", "card-border"],
  },
  {
    label: "Severity",
    vars: [
      "severity-critical",
      "severity-high",
      "severity-medium",
      "severity-low",
      "severity-info",
    ],
  },
];

const DEFAULT_COLORS: Record<string, string> = {
  "bg-primary": "#1a1a2e",
  "bg-secondary": "#252540",
  "bg-tertiary": "#0d0d1a",
  "bg-hover": "#2a2a4a",
  "text-primary": "#e0e0e0",
  "text-secondary": "#a0a0b0",
  "text-muted": "#666680",
  accent: "#6c63ff",
  "accent-hover": "#5a52e0",
  "accent-text": "#ffffff",
  border: "#333355",
  danger: "#e54545",
  success: "#22c55e",
  warning: "#f59e0b",
  "sidebar-bg": "#16162a",
  "sidebar-hover": "#222244",
  "sidebar-active": "#2a2a50",
  "card-bg": "#202038",
  "card-border": "#2a2a48",
  "severity-critical": "#dc2626",
  "severity-high": "#ea580c",
  "severity-medium": "#f59e0b",
  "severity-low": "#22c55e",
  "severity-info": "#3b82f6",
};

/**
 * Normalize a color value to a 7-character hex string for <input type="color">.
 * Falls back to #000000 if the value cannot be parsed.
 */
function toHex7(value: string): string {
  const v = value.trim();

  // Already a valid 7-char hex
  if (/^#[0-9a-fA-F]{6}$/.test(v)) {
    return v.toLowerCase();
  }

  // 3-char hex shorthand
  if (/^#[0-9a-fA-F]{3}$/.test(v)) {
    const r = v[1];
    const g = v[2];
    const b = v[3];
    return `#${r}${r}${g}${g}${b}${b}`.toLowerCase();
  }

  // Try using a canvas to parse named colors / rgb() / hsl() etc.
  try {
    const ctx = document.createElement("canvas").getContext("2d");
    if (ctx) {
      ctx.fillStyle = v;
      const result = ctx.fillStyle; // browsers return a #rrggbb string
      if (/^#[0-9a-fA-F]{6}$/.test(result)) {
        return result.toLowerCase();
      }
    }
  } catch {
    // ignore
  }

  return "#000000";
}

export default function ThemeEditor({ theme, onSave, onClose }: Props) {
  const [name, setName] = useState(theme?.name ?? "");

  const initialVars = useMemo(() => {
    const base: Record<string, string> = {};
    for (const group of COLOR_GROUPS) {
      for (const v of group.vars) {
        base[v] = theme?.css_variables[v] ?? DEFAULT_COLORS[v] ?? "#000000";
      }
    }
    return base;
  }, [theme]);

  const [vars, setVars] = useState<Record<string, string>>(initialVars);

  const setVar = (key: string, value: string) => {
    setVars((prev) => ({ ...prev, [key]: value }));
  };

  const handleHexChange = (key: string, value: string) => {
    // Allow typing freely; only update when it looks like a valid hex
    setVar(key, value);
  };

  const handleSave = () => {
    if (!name.trim()) return;
    onSave(name.trim(), vars);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") onClose();
  };

  const trapRef = useFocusTrap<HTMLDivElement>();

  return (
    <div className={styles.overlay} onClick={onClose} onKeyDown={handleKeyDown}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()} ref={trapRef} role="dialog" aria-modal="true" aria-label={theme ? "Edit theme" : "Create theme"}>
        <div className={styles.header}>
          <h2>{theme ? "Edit Theme" : "Create Theme"}</h2>
          <button onClick={onClose} className={styles.closeBtn} aria-label="Close">
            &times;
          </button>
        </div>

        <div className={styles.body}>
          {/* Theme name */}
          <div className={styles.nameRow}>
            <label className={styles.nameLabel}>Theme Name</label>
            <input
              type="text"
              className={styles.nameInput}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Custom Theme"
              autoFocus
            />
          </div>

          {/* Live Preview */}
          <div className={styles.previewSection}>
            <p className={styles.previewLabel}>Preview</p>
            <div
              className={styles.previewBox}
              style={{
                backgroundColor: vars["bg-primary"],
                borderColor: vars["border"],
              }}
            >
              <div
                className={styles.previewSidebar}
                style={{
                  backgroundColor: vars["sidebar-bg"] || vars["bg-secondary"],
                }}
              >
                <div
                  className={styles.previewSidebarItemActive}
                  style={{ backgroundColor: vars["accent"] }}
                />
                <div
                  className={styles.previewSidebarItem}
                  style={{ backgroundColor: vars["text-muted"] }}
                />
                <div
                  className={styles.previewSidebarItem}
                  style={{ backgroundColor: vars["text-muted"] }}
                />
                <div
                  className={styles.previewSidebarItem}
                  style={{ backgroundColor: vars["sidebar-hover"] }}
                />
              </div>
              <div
                className={styles.previewMainArea}
                style={{ backgroundColor: vars["bg-primary"] }}
              >
                <div
                  className={styles.previewHeading}
                  style={{ backgroundColor: vars["text-primary"] }}
                />
                <div
                  className={styles.previewText}
                  style={{ backgroundColor: vars["text-secondary"] }}
                />
                <div
                  className={styles.previewTextMuted}
                  style={{ backgroundColor: vars["text-muted"] }}
                />
                <div
                  className={styles.previewAccentBar}
                  style={{ backgroundColor: vars["accent"] }}
                />
              </div>
            </div>
          </div>

          {/* Color Groups */}
          {COLOR_GROUPS.map((group) => (
            <div key={group.label} className={styles.section}>
              <h4 className={styles.sectionTitle}>{group.label}</h4>
              {group.vars.map((varName) => (
                <div key={varName} className={styles.colorRow}>
                  <span className={styles.colorLabel}>{varName}</span>
                  <input
                    type="color"
                    className={styles.colorPicker}
                    value={toHex7(vars[varName] || "#000000")}
                    onChange={(e) => setVar(varName, e.target.value)}
                  />
                  <input
                    type="text"
                    className={styles.hexInput}
                    value={vars[varName] || ""}
                    onChange={(e) => handleHexChange(varName, e.target.value)}
                  />
                </div>
              ))}
            </div>
          ))}
        </div>

        <div className={styles.footer}>
          <button className={styles.cancelBtn} onClick={onClose}>
            Cancel
          </button>
          <button
            className={styles.saveBtn}
            onClick={handleSave}
            disabled={!name.trim()}
          >
            {theme ? "Save Changes" : "Create Theme"}
          </button>
        </div>
      </div>
    </div>
  );
}
