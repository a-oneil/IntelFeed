import { useMemo, type ReactNode } from "react";
import { contrastText } from "@/utils/contrast";
import styles from "./Chip.module.css";

/**
 * A filled chip needs a foreground that contrasts with ITS OWN fill. The old
 * default — `--accent-text` — is derived from `--accent`, so it was only ever
 * right when the tint was the accent. That mismatch shipped three separate
 * unreadable-badge bugs (rule severities at 4.06:1, glossary categories, and
 * filled severity chips at 1.2:1), so `solid` now derives its own foreground
 * instead of trusting the call site to remember.
 *
 * Resolves `var(--token)` against :root, since every tint in this app is
 * either a literal or a root-level custom property. Anything it cannot parse
 * (color-mix, a nested var chain) falls through to the CSS default.
 */
function autoContrast(tint: string | undefined): string | undefined {
  if (!tint) return undefined;
  let value = tint.trim();
  const varMatch = value.match(/^var\(\s*(--[\w-]+)\s*(?:,\s*(.+))?\)$/);
  if (varMatch) {
    const resolved =
      typeof window !== "undefined"
        ? getComputedStyle(document.documentElement).getPropertyValue(varMatch[1]).trim()
        : "";
    value = resolved || (varMatch[2] ?? "").trim();
  }
  return /^#[0-9a-fA-F]{3}$|^#[0-9a-fA-F]{6}$/.test(value) ? contrastText(value) : undefined;
}

type ChipTone = "default" | "toned" | "solid" | "quiet" | "outline";

interface ChipProps {
  children: ReactNode;
  /** Any CSS color — pass an entity/severity token, e.g. `var(--entity-cve)`. */
  tint?: string;
  /**
   * Foreground override. For `tone="solid"` this is derived automatically from
   * `tint` when omitted, so you only need it to force a specific colour.
   */
  fg?: string;
  tone?: ChipTone;
  size?: "sm" | "md";
  pill?: boolean;
  /** Show a small colour marker before the label. */
  marker?: boolean;
  /** Status legends want a circular dot, not the default rounded square. */
  markerShape?: "square" | "dot";
  title?: string;
  className?: string;
  /**
   * Extra custom properties only (e.g. `--tag-scrim`). Chip's own `--chip-*`
   * values are merged in last and always win. Do NOT set real CSS properties
   * here — those belong in `className`, where the specificity is explicit.
   */
  style?: React.CSSProperties;
  /**
   * Allow the label to shrink and ellipsise. Chip is `flex:none; nowrap` by
   * default, which is right for short labels but overflows its row when the
   * content is long (country names, ATT&CK tactics, product types).
   */
  truncate?: boolean;
  onClick?: () => void;
  /** Only meaningful with `onClick` — renders a disabled button. */
  disabled?: boolean;
  /** Toggle chips must announce their state, not just look active. */
  "aria-pressed"?: boolean;
}

/**
 * The app's small-label primitive: severity badges, entity type tags, filter
 * chips, counts. `tint` drives colour through one custom property so a chip
 * can carry any entity or severity token without a bespoke class.
 */
export function Chip({
  children,
  tint,
  fg,
  tone = "default",
  size = "md",
  pill = false,
  marker = false,
  markerShape = "square",
  title,
  className,
  style: styleProp,
  truncate = false,
  onClick,
  disabled = false,
  "aria-pressed": ariaPressed,
}: ChipProps) {
  const cls = [
    styles.chip,
    styles[size],
    tone !== "default" ? styles[tone] : "",
    pill ? styles.pill : "",
    truncate ? styles.truncate : "",
    onClick ? styles.clickable : "",
    className || "",
  ]
    .filter(Boolean)
    .join(" ");

  // Only `solid` paints text on the tint; the other tones sit on the page
  // ground and must not be second-guessed.
  const resolvedFg = useMemo(
    () => fg ?? (tone === "solid" ? autoContrast(tint) : undefined),
    [fg, tone, tint],
  );

  const ownVars = {
    ...(tint ? { "--chip-tint": tint } : {}),
    ...(resolvedFg ? { "--chip-fg": resolvedFg } : {}),
  } as React.CSSProperties;
  const style =
    styleProp || tint || resolvedFg ? { ...styleProp, ...ownVars } : undefined;

  const content = (
    <>
      {marker && (
        <span
          className={`${styles.marker} ${markerShape === "dot" ? styles.markerDot : ""}`}
          aria-hidden="true"
        />
      )}
      {children}
    </>
  );

  if (onClick) {
    return (
      <button
        type="button"
        className={cls}
        style={style}
        title={title}
        onClick={onClick}
        disabled={disabled}
        aria-pressed={ariaPressed}
      >
        {content}
      </button>
    );
  }
  return (
    <span className={cls} style={style} title={title}>
      {content}
    </span>
  );
}
