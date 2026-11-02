import styles from "./Segmented.module.css";

export interface SegmentedOption<T extends string> {
  value: T;
  label: React.ReactNode;
  /** Native tooltip — several call sites explain the mode this way. */
  title?: string;
  disabled?: boolean;
  /** Tab wiring: the tab's own id and the id of the panel it controls. */
  id?: string;
  controls?: string;
}

interface SegmentedProps<T extends string> {
  options: SegmentedOption<T>[];
  value: T;
  onChange: (value: T) => void;
  /** Names the group for screen readers, e.g. "Matrix domain". */
  label: string;
  /**
   * "tab" when the segments swap the whole view below (Ransomware, Vendor
   * Watch), "group" when they only reshape it (matrix window, rule lens).
   */
  role?: "tablist" | "group";
  size?: "md" | "sm";
  className?: string;
}

/**
 * The app's one segmented switch. Four near-identical copies of this markup
 * existed — ExposurePage `.seg`, AttackMatrixSection `.segmented`,
 * RuleLibrary `.lens`, RansomwareSection `.tabs` — at three different paddings
 * and two radii, all sitting in page headers next to each other.
 */
export function Segmented<T extends string>({
  options,
  value,
  onChange,
  label,
  role = "group",
  size = "md",
  className,
}: SegmentedProps<T>) {
  const isTabs = role === "tablist";
  return (
    <div
      className={[styles.track, size === "sm" ? styles.sm : "", className || ""]
        .filter(Boolean)
        .join(" ")}
      role={role}
      aria-label={label}
    >
      {options.map((opt) => {
        const selected = opt.value === value;
        return (
          <button
            key={opt.value}
            type="button"
            className={styles.segment}
            id={opt.id}
            role={isTabs ? "tab" : undefined}
            aria-selected={isTabs ? selected : undefined}
            aria-controls={isTabs ? opt.controls : undefined}
            aria-pressed={isTabs ? undefined : selected}
            title={opt.title}
            disabled={opt.disabled}
            onClick={() => onChange(opt.value)}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}
