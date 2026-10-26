/**
 * IdentityMetaFields — the editable scalar identity fields (ISO code, Website,
 * Vendor…) rendered in the profile header meta row, config-driven. Fields with
 * a badge twin live in SignalBadges instead; this row keeps only the rest.
 */
import type { EntitySearchResult } from "@/api/types";
import type { EntityType } from "@/stores/intelStore";
import type { EntityProvenance } from "@/hooks/useEntityProvenance";
import { InlineEditField } from "@/components/InlineEditField";
import { FieldProvenance } from "./FieldProvenance";
import { VendorPicker } from "./VendorPicker";
import { useIsVisitor } from "@/stores/authStore";
import type { EntityProfileConfig } from "./entityProfileConfig";
import styles from "./entityProfile.module.css";

export function IdentityMetaFields({
  config,
  entity,
  provenance,
  onUpdateField,
  onOpenEntity,
  onOpenArticle,
}: {
  config: EntityProfileConfig;
  entity: EntitySearchResult;
  provenance?: EntityProvenance;
  onUpdateField: (field: string, value: string | string[]) => void;
  onOpenEntity: (type: EntityType, id: string, label?: string) => void;
  onOpenArticle?: (entryId: string) => void;
}) {
  const isVisitor = useIsVisitor();
  const get = (key: string) => (entity as unknown as Record<string, unknown>)[key];

  /** The "who says so" marker for one field, or nothing when it isn't tracked. */
  const sources = (key: string, label: string) =>
    provenance ? (
      <FieldProvenance
        field={key}
        label={label}
        bucket={provenance.fields[key]}
        unsourced={provenance.unsourced_fields.includes(key)}
        onOpenArticle={onOpenArticle}
      />
    ) : null;

  return (
    <>
      {config.identityFields.map((field) => {
        const raw = get(field.key);
        const value = raw == null ? "" : String(raw);

        switch (field.kind) {
          case "vendor":
            return (
              <span key={field.key} className={styles.metaItem}>
                <span className={styles.metaLabel}>{field.label}</span>
                {isVisitor ? (
                  // A visitor follows the vendor; picking one is an edit.
                  entity.vendor_id && entity.vendor_name ? (
                    <button
                      type="button"
                      className={styles.metaLink}
                      onClick={() => onOpenEntity("vendor", entity.vendor_id as string)}
                    >
                      {entity.vendor_name}
                    </button>
                  ) : (
                    <span style={{ color: "var(--text-muted)" }}>—</span>
                  )
                ) : (
                  <VendorPicker
                    currentVendorId={entity.vendor_id ?? null}
                    currentVendorName={entity.vendor_name ?? null}
                    onSelect={(id) => onUpdateField("vendor_id", id)}
                    onOpenVendor={(id) => onOpenEntity("vendor", id)}
                  />
                )}
                {sources(field.key, field.label)}
              </span>
            );

          case "text":
          default:
            return (
              <span key={field.key} className={styles.metaItem}>
                <span className={styles.metaLabel}>{field.label}</span>
                <InlineEditField
                  value={value}
                  placeholder={field.placeholder || `Set ${field.label.toLowerCase()}`}
                  onSave={(v) => onUpdateField(field.key, v)}
                />
                {sources(field.key, field.label)}
              </span>
            );
        }
      })}
    </>
  );
}
