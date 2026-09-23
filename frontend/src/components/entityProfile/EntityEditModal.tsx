/**
 * EntityEditModal — the profile's in-place editors gathered into one form, so an
 * entity can be maintained from the workbench table without opening its profile.
 *
 * The field list is derived from the same entityProfileConfig the profile header
 * reads: the display name (when the type's identity isn't an external id), the
 * alias list, every click-to-edit signal badge, the identity meta fields, and
 * the description. Only fields the operator actually changed are sent, so a
 * value the row payload didn't carry can never be blanked by saving.
 */
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { useUpdateEntity, EDITABLE_ENTITY_TYPES } from "@/hooks/useEntityProfile";
import { getEntityLabel } from "@/utils/entityTheme";
import type { EntityType } from "@/stores/intelStore";
import type { EntitySearchResult } from "@/api/types";
import { getEntityProfileConfig, type EntityProfileConfig } from "./entityProfileConfig";
import { VendorPicker } from "./VendorPicker";
import styles from "./EntityEditModal.module.css";

export type EditFieldKind = "text" | "textarea" | "aliases" | "vendor";

export interface EditableField {
  key: string;
  label: string;
  kind: EditFieldKind;
  placeholder?: string;
}

/** True when the type has a PUT endpoint behind `useUpdateEntity`. */
export function isEditableEntityType(entityType: string): boolean {
  return (EDITABLE_ENTITY_TYPES as readonly string[]).includes(entityType);
}

/**
 * The editable surface of a profile, in the order the profile presents it:
 * name → aliases → signal badges → identity fields → description.
 */
export function editableFieldsFor(
  config: EntityProfileConfig,
  entity: EntitySearchResult,
): EditableField[] {
  const fields: EditableField[] = [];
  const seen = new Set<string>();
  const push = (f: EditableField) => {
    if (seen.has(f.key)) return;
    seen.add(f.key);
    fields.push(f);
  };

  if (config.nameEditable) push({ key: "name", label: "Name", kind: "text" });
  if (config.hasAliases) {
    push({ key: "aliases", label: "Aliases", kind: "aliases", placeholder: "One per line" });
  }
  // Badges carry the type's headline attributes (motivation, severity, tactic…);
  // the ones flagged click-to-edit on the profile are the ones editable here.
  for (const badge of config.signalBadges(entity)) {
    if (!badge.editKey) continue;
    push({
      key: badge.editKey,
      label: badge.title || badge.editKey,
      kind: "text",
      placeholder: badge.placeholder,
    });
  }
  for (const field of config.identityFields) {
    push({
      key: field.key,
      label: field.label,
      kind: field.kind === "vendor" ? "vendor" : "text",
      placeholder: field.placeholder,
    });
  }
  if (config.hasDescription) push({ key: "description", label: "Description", kind: "textarea" });

  return fields;
}

function initialValue(entity: EntitySearchResult, field: EditableField): string {
  const raw = (entity as unknown as Record<string, unknown>)[field.key];
  if (field.kind === "aliases") return Array.isArray(raw) ? raw.join("\n") : "";
  return raw == null ? "" : String(raw);
}

function saveError(err: unknown): string {
  const data = (err as { response?: { data?: { error?: { message?: string }; detail?: string } } })?.response?.data;
  return data?.error?.message || data?.detail || "Couldn't save changes";
}

export function EntityEditModal({
  entityType,
  entityId,
  entity,
  displayName,
  onClose,
  onSaved,
}: {
  entityType: EntityType;
  entityId: string;
  /** The row (or profile) payload — seeds the form and is never re-fetched. */
  entity: EntitySearchResult;
  displayName: string;
  onClose: () => void;
  onSaved?: () => void;
}) {
  const config = getEntityProfileConfig(entityType);
  const updateEntity = useUpdateEntity();
  const [saving, setSaving] = useState(false);

  const fields = useMemo(() => editableFieldsFor(config, entity), [config, entity]);
  const initial = useMemo(() => {
    const out: Record<string, string> = {};
    for (const f of fields) out[f.key] = initialValue(entity, f);
    return out;
  }, [fields, entity]);

  const [draft, setDraft] = useState<Record<string, string>>(initial);
  const [vendorName, setVendorName] = useState<string | null>(entity.vendor_name ?? null);

  const dirtyKeys = fields.map((f) => f.key).filter((k) => draft[k] !== initial[k]);

  const handleSave = async () => {
    if (dirtyKeys.length === 0) {
      onClose();
      return;
    }
    const payload: Record<string, unknown> = {};
    for (const key of dirtyKeys) {
      const field = fields.find((f) => f.key === key)!;
      payload[key] =
        field.kind === "aliases"
          ? draft[key]
              .split("\n")
              .map((a) => a.trim())
              .filter(Boolean)
          : draft[key].trim();
    }
    setSaving(true);
    try {
      await updateEntity(entityType, entityId, payload);
      toast.success(`Updated ${displayName}`);
      onSaved?.();
      onClose();
    } catch (err) {
      toast.error(saveError(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className={styles.backdrop} onClick={onClose}>
      <div
        className={styles.modal}
        role="dialog"
        aria-label={`Edit ${displayName}`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className={styles.header}>
          <div>
            <div className={styles.title}>Edit {displayName}</div>
            <div className={styles.subtitle}>{getEntityLabel(entityType)}</div>
          </div>
          <button className={styles.close} onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>

        <div className={styles.body}>
          {fields.length === 0 && <div className={styles.emptyNote}>This type has no editable fields.</div>}
          {fields.map((field) => (
            <label key={field.key} className={styles.field}>
              <span className={styles.fieldLabel}>{field.label}</span>
              {field.kind === "textarea" ? (
                <textarea
                  className={styles.textarea}
                  rows={5}
                  value={draft[field.key]}
                  placeholder={field.placeholder}
                  onChange={(e) => setDraft((d) => ({ ...d, [field.key]: e.target.value }))}
                />
              ) : field.kind === "aliases" ? (
                <textarea
                  className={styles.textarea}
                  rows={4}
                  value={draft[field.key]}
                  placeholder={field.placeholder}
                  onChange={(e) => setDraft((d) => ({ ...d, [field.key]: e.target.value }))}
                />
              ) : field.kind === "vendor" ? (
                <span className={styles.pickerRow}>
                  <VendorPicker
                    currentVendorId={draft[field.key] || null}
                    currentVendorName={vendorName}
                    onSelect={(id) => {
                      setDraft((d) => ({ ...d, [field.key]: id }));
                      setVendorName(null);
                    }}
                    onOpenVendor={() => {}}
                  />
                </span>
              ) : (
                <input
                  className={styles.input}
                  value={draft[field.key]}
                  placeholder={field.placeholder}
                  onChange={(e) => setDraft((d) => ({ ...d, [field.key]: e.target.value }))}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      handleSave();
                    }
                  }}
                />
              )}
            </label>
          ))}
        </div>

        <div className={styles.footer}>
          <span className={styles.dirtyNote}>
            {dirtyKeys.length > 0
              ? `${dirtyKeys.length} field${dirtyKeys.length === 1 ? "" : "s"} changed`
              : "No changes"}
          </span>
          <button className={styles.cancel} onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button className={styles.save} onClick={handleSave} disabled={saving || dirtyKeys.length === 0}>
            {saving ? "Saving…" : "Save changes"}
          </button>
        </div>
      </div>
    </div>
  );
}
