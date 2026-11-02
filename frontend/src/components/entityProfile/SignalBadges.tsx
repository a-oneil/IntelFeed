/**
 * SignalBadges — the per-type header signal chips. Badges with an `editKey`
 * retain the old identity-row functionality: click-to-edit in place (empty
 * values render a ghost chip with the placeholder), and country badges link
 * to the country profile when the country id is resolvable.
 */
import type { EntitySearchResult } from "@/api/types";
import type { EntityType } from "@/stores/intelStore";
import { InlineEditField } from "@/components/InlineEditField";
import type { EntityProvenance } from "@/hooks/useEntityProvenance";
import type { BadgeSpec, BadgeTone } from "./entityProfileConfig";
import { FieldProvenance } from "./FieldProvenance";
import styles from "./entityProfile.module.css";

const TONE_CLASS: Record<BadgeTone, string> = {
  critical: styles.toneCritical,
  high: styles.toneHigh,
  medium: styles.toneMedium,
  low: styles.toneLow,
  info: styles.toneInfo,
  neutral: styles.toneNeutral,
  success: styles.toneSuccess,
  danger: styles.toneDanger,
};

interface RelatedCountry {
  id: string;
  name?: string;
}

export function SignalBadges({
  badges,
  entity,
  relatedCountries = [],
  provenance,
  onUpdateField,
  onOpenEntity,
  onOpenArticle,
}: {
  badges: BadgeSpec[];
  entity?: EntitySearchResult;
  relatedCountries?: RelatedCountry[];
  /** Field-level provenance for this entity; adds a "who says so" marker to
   *  every badge that represents a field. */
  provenance?: EntityProvenance;
  onUpdateField?: (field: string, value: string | string[]) => void;
  onOpenEntity?: (type: EntityType, id: string, label?: string) => void;
  onOpenArticle?: (entryId: string) => void;
}) {
  const visible = badges.filter((b) => b.label || (b.editKey && onUpdateField));
  if (!visible.length) return null;

  /** Marker for a badge that stands for a field, or nothing when it doesn't. */
  const sources = (b: BadgeSpec) => {
    const key = b.provenanceKey ?? b.editKey;
    if (!key || !provenance) return null;
    return (
      <FieldProvenance
        field={key}
        label={b.provenanceLabel || b.title || key}
        bucket={provenance.fields[key]}
        unsourced={provenance.unsourced_fields.includes(key)}
        onOpenArticle={onOpenArticle}
      />
    );
  };

  return (
    <span className={styles.badges}>
      {visible.map((b, i) => {
        const key = `${b.editKey || b.label}-${i}`;
        const cls = `${styles.signalBadge} ${TONE_CLASS[b.tone]}${b.label ? "" : ` ${styles.signalBadgeGhost}`}`;

        // Country badges become a link to the country profile when resolvable
        // (same resolution the identity field used); otherwise fall through to
        // the inline editor so the value can still be set.
        if (b.editKind === "country" && b.label && entity && onOpenEntity) {
          const countryId =
            entity.origin_country_id ??
            entity.country_id ??
            relatedCountries.find((c) => c.name?.toLowerCase() === entity.country?.toLowerCase())?.id ??
            null;
          if (countryId) {
            return (
              <span key={key} className={styles.badgeWithSources}>
                <button
                  className={`${cls} ${styles.signalBadgeLink}`}
                  title={`${b.title || "Country"} — open profile`}
                  onClick={() => onOpenEntity("country", countryId, b.label)}
                >
                  {b.label}
                </button>
                {sources(b)}
              </span>
            );
          }
        }

        // Targeted-sector chips open the sector profile. The route resolves the
        // display label ("Financial Services") to the entity, so no id lookup is
        // needed here; a legacy free-text value that is not a sector 404s on the
        // profile rather than rendering as a dead chip.
        if (b.editKind === "sector" && b.label && onOpenEntity) {
          return (
            <span key={key} className={styles.badgeWithSources}>
              <button
                className={`${cls} ${styles.signalBadgeLink}`}
                title={`${b.title || "Targeted sector"} — open profile`}
                onClick={() => onOpenEntity("sector", b.label, b.label)}
              >
                {b.label}
              </button>
              {sources(b)}
            </span>
          );
        }

        if (b.editKey && onUpdateField) {
          return (
            <span key={key} className={styles.badgeWithSources}>
              <span className={`${cls} ${styles.signalBadgeEditable}`} title={b.title}>
                <InlineEditField
                  value={b.editValue ?? b.label}
                  displayValue={b.label}
                  placeholder={b.placeholder || `set ${(b.title || b.editKey).toLowerCase()}`}
                  onSave={(v) => onUpdateField(b.editKey!, v)}
                />
              </span>
              {sources(b)}
            </span>
          );
        }

        return (
          <span key={key} className={styles.badgeWithSources}>
            <span className={cls} title={b.title}>
              {b.label}
            </span>
            {sources(b)}
          </span>
        );
      })}
    </span>
  );
}
