import { Chip } from "@/components/primitives";
import { getEntityCssVar, getEntityLabel } from "@/utils/entityTheme";
import type { CopilotContext } from "@/hooks/useAI";
import styles from "./ContextPill.module.css";

interface ContextPillProps {
  context: CopilotContext;
  /** Optional resolved labels keyed by the field they describe. */
  labels?: { entry?: string; entity?: string; campaign?: string };
  onDismiss: () => void;
}

interface Pill {
  key: string;
  label: string;
  value: string;
  color?: string;
}

/**
 * Renders the current ambient context as dismissible pills so the user can see
 * (and drop) what the copilot is grounded on.
 */
export function ContextPill({ context, labels, onDismiss }: ContextPillProps) {
  const pills: Pill[] = [];

  if (context.entity_type && context.entity_id) {
    pills.push({
      key: "entity",
      label: getEntityLabel(context.entity_type),
      value: labels?.entity || context.entity_id,
      color: getEntityCssVar(context.entity_type),
    });
  }
  if (context.campaign_id) {
    pills.push({
      key: "campaign",
      label: "Campaign",
      value: labels?.campaign || context.campaign_id,
      color: "var(--entity-campaign)",
    });
  }
  if (context.entry_id) {
    pills.push({
      key: "entry",
      label: "Entry",
      value: labels?.entry || context.entry_id,
    });
  }
  if (context.search_query) {
    pills.push({ key: "search", label: "Search", value: context.search_query });
  }

  if (pills.length === 0) return null;

  return (
    <div className={styles.bar}>
      <span className={styles.prefix}>Context</span>
      {pills.map((p) => (
        <Chip
          key={p.key}
          pill
          tone={p.color ? "toned" : "default"}
          tint={p.color}
          title={`${p.label}: ${p.value}`}
        >
          {p.color && (
            <span className={styles.dot} style={{ backgroundColor: p.color }} />
          )}
          <span className={styles.pillLabel}>{p.label}:</span>
          <span className={styles.pillValue}>{p.value}</span>
        </Chip>
      ))}
      <button
        className={styles.dismiss}
        onClick={onDismiss}
        title="Ignore context for this thread"
        aria-label="Dismiss context"
      >
        &times;
      </button>
    </div>
  );
}
