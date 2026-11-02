/**
 * ProfileHeader — the dossier hero: stacked identity (type chip, display name,
 * aka line, signal badges + activity status, action row) with a portrait tile
 * on the right, washed in the entity's intel-panel color. Scrolls with the page;
 * the tab bar below it is the sticky element.
 */
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { Breadcrumb } from "@/components/Breadcrumb";
import { Chip } from "@/components/primitives";
import { InlineEditAliases } from "@/components/InlineEditAliases";
import { useUIStore } from "@/stores/uiStore";
import { getEntityColor, getEntityLabel, getEntityPluralLabel } from "@/utils/entityTheme";
import { formatDate } from "@/utils/formatDate";
import type { EntityType } from "@/stores/intelStore";
import type { EntitySearchResult } from "@/api/types";
import { SignalBadges } from "./SignalBadges";
import { EntityActionsMenu } from "./EntityActionsMenu";
import { WatchToggleButton } from "./WatchToggleButton";
import type { EntityProvenance } from "@/hooks/useEntityProvenance";
import { IdentityMetaFields } from "./IdentityFields";
import { contextBadgeSpecs, entityDisplayName, noPatchBadge, type EntityProfileConfig } from "./entityProfileConfig";
import { useEntityContext } from "@/hooks/useEntityContext";
import { useCveAffectedRows } from "@/hooks/useAffectedCves";
import styles from "./entityProfile.module.css";
import { useIsVisitor } from "@/stores/authStore";

const DAY_MS = 24 * 60 * 60 * 1000;

/** Same derivation as the workbench list's ActivityBadge. */
function activityStatus(lastSeenAt: string | null | undefined): {
  label: string;
  /** Undefined for "Historical" — a default-tone chip, not a tinted one. */
  tint?: string;
  title: string;
} {
  const ageDays = lastSeenAt ? (Date.now() - new Date(lastSeenAt).getTime()) / DAY_MS : null;
  if (ageDays !== null && ageDays < 90) {
    return { label: "Active", tint: "var(--success)", title: "Seen in the last 90 days" };
  }
  if (ageDays !== null && ageDays < 365) {
    return { label: "Dormant", tint: "var(--warning)", title: "Last seen between 90 days and a year ago" };
  }
  return {
    label: "Historical",
    title: ageDays === null ? "Never seen in feed content" : "No sighting in over a year",
  };
}

export function ProfileHeader({
  entityType,
  entityId,
  entity,
  config,
  entries,
  relatedCountries,
  provenance,
  onUpdateField,
  onOpenEntity,
  onOpenArticle,
  onNavigateAway,
}: {
  entityType: EntityType;
  entityId: string;
  entity: EntitySearchResult;
  config: EntityProfileConfig;
  entries: Array<{ id: string }>;
  relatedCountries: Array<{ id: string; name?: string; region?: string }>;
  /** Field-level provenance for this entity; drives the "who says so" markers. */
  provenance?: EntityProvenance;
  onUpdateField: (field: string, value: string | string[]) => void;
  onOpenEntity: (type: EntityType, id: string, label?: string) => void;
  onOpenArticle?: (entryId: string) => void;
  onNavigateAway: () => void;
}) {
  const accent = getEntityColor(entityType);
  const displayName = entityDisplayName(entity, entityId);
  const openCopilotWith = useUIStore((s) => s.openCopilotWith);
  const status = activityStatus(entity.last_seen_at);
  const [editingAliases, setEditingAliases] = useState(false);
  // Public read-only mode: the dossier reads, but nothing on it edits.
  const isVisitor = useIsVisitor();
  // Manifest badges (noise class, SSVC, EOL) — same query as the Context panel.
  const { data: context } = useEntityContext(entityType, entityId);
  // A CVE affecting an end-of-life product gets "no patch coming" — same
  // query as the Overview's Affected panel.
  const { data: affectedRows } = useCveAffectedRows(entityType === "cve" ? entityId : undefined);
  const noPatch = entityType === "cve" ? noPatchBadge(affectedRows) : null;
  const aliases = entity.aliases ?? [];
  // Catalog-keyed types (ttp, cwe) lead with the id in mono, then the name.
  // Which field holds the id is config, not a branch per type here.
  const monoId = config.monoIdKey ? entity[config.monoIdKey] : undefined;
  const monoIdName = config.monoIdKey === "technique_id" ? entity.technique_name : entity.name;

  // Faded wash of the entity's intel-panel color behind the identity block —
  // hex + alpha suffix keeps it subtle on the dark ground in every theme.
  const headerWash = {
    backgroundImage: `radial-gradient(ellipse 640px 300px at 8% -10%, ${accent}30, transparent 68%), radial-gradient(ellipse 420px 260px at 92% -15%, ${accent}16, transparent 62%)`,
  };

  return (
    <div className={styles.header} style={headerWash}>
      <div className={styles.breadcrumbRow}>
        <Breadcrumb
          items={[
            { label: "Workbench", to: "/workbench/explore" },
            { label: getEntityPluralLabel(entityType), to: "/workbench/explore" },
            { label: displayName },
          ]}
        />
      </div>

      <div className={styles.heroGrid}>
        <div className={styles.heroMain}>
          <div>
            <Chip tone="solid" tint={accent} className={styles.typeBadge}>
              {getEntityLabel(entityType)}
            </Chip>
          </div>

          {config.nameEditable && !monoId && !isVisitor ? (
            <InlineEditableName name={displayName} onSave={(next) => onUpdateField("name", next)} />
          ) : (
            <h1 className={styles.heroName}>
              {monoId ? (
                <>
                  <span className={styles.nameMono}>{monoId}</span>
                  {/* Un-hydrated stubs carry name == id — don't render the raw ID twice */}
                  {monoIdName && monoIdName !== monoId ? ` ${monoIdName}` : ""}
                </>
              ) : (
                displayName
              )}
            </h1>
          )}

          {config.hasAliases && isVisitor && aliases.length > 0 && (
            <span className={styles.akaLine}>
              aka{" "}
              <span className={styles.akaNames}>
                {aliases.slice(0, 4).join(" · ")}
                {aliases.length > 4 ? ` +${aliases.length - 4}` : ""}
              </span>
            </span>
          )}
          {config.hasAliases && !isVisitor &&
            (editingAliases ? (
              <div className={styles.akaEdit}>
                <InlineEditAliases aliases={aliases} onSave={(next) => onUpdateField("aliases", next)} />
                <button className={styles.akaDone} onClick={() => setEditingAliases(false)}>
                  Done
                </button>
              </div>
            ) : aliases.length > 0 ? (
              <button className={styles.akaLine} onClick={() => setEditingAliases(true)} title="Edit aliases">
                aka{" "}
                <span className={styles.akaNames}>
                  {aliases.slice(0, 4).join(" · ")}
                  {aliases.length > 4 ? ` +${aliases.length - 4}` : ""}
                </span>
              </button>
            ) : (
              <button className={styles.akaGhost} onClick={() => setEditingAliases(true)}>
                + add aliases
              </button>
            ))}

          <div className={styles.heroBadges}>
            <SignalBadges
              badges={[
                ...config.signalBadges(entity),
                ...(noPatch ? [noPatch] : []),
                ...contextBadgeSpecs(context?.badges, context?.sources),
              ]}
              entity={entity}
              relatedCountries={relatedCountries}
              provenance={provenance}
              // Without it the badges are read-only and empty ones don't show.
              onUpdateField={isVisitor ? undefined : onUpdateField}
              onOpenEntity={onOpenEntity}
              onOpenArticle={onOpenArticle}
            />
            <Chip
              pill
              marker
              markerShape="dot"
              tone={status.tint ? "toned" : "default"}
              tint={status.tint}
              title={status.title}
            >
              {status.label}
            </Chip>
          </div>

          {!isVisitor && (
          <div className={styles.heroActions}>
            <button
              className={styles.primaryBtn}
              title="Ask the copilot about this entity"
              onClick={() =>
                openCopilotWith({
                  // Context-only seed: pin the entity, no auto-submitted prompt.
                  context: { entity_type: entityType, entity_id: entityId, label: displayName },
                  lockContext: true,
                })
              }
            >
              Ask Copilot
            </button>
            <WatchToggleButton entityType={entityType} entityId={entityId} displayName={displayName} />
            <EntityActionsMenu
              entityType={entityType}
              entityId={entityId}
              config={config}
              displayName={displayName}
              entries={entries}
              onNavigateAway={onNavigateAway}
            />
          </div>
          )}
        </div>

        {entity.wikipedia_image_url && (
          <div className={styles.portraitTile}>
            <a
              className={styles.portraitImageLink}
              href={entity.wikipedia_url || "#"}
              target="_blank"
              rel="noopener noreferrer"
              title={entity.wikipedia_url ? "View on Wikipedia" : undefined}
            >
              <img src={entity.wikipedia_image_url} alt={displayName} />
            </a>
          </div>
        )}
      </div>

      <div className={styles.metaRow}>
        <IdentityMetaFields
          config={config}
          entity={entity}
          provenance={provenance}
          onUpdateField={onUpdateField}
          onOpenEntity={onOpenEntity}
          onOpenArticle={onOpenArticle}
        />
        {entity.first_seen_at && (
          <span className={styles.metaItem}>
            <span className={styles.metaLabel}>First seen</span> {formatDate(entity.first_seen_at)}
          </span>
        )}
        {entity.last_seen_at && (
          <span className={styles.metaItem}>
            <span className={styles.metaLabel}>Last seen</span> {formatDate(entity.last_seen_at)}
          </span>
        )}
        {/* External pivot links moved to the Overview's Sources card — the
            header meta row keeps only identity facts. */}
      </div>
    </div>
  );
}

/**
 * Click-to-edit display name. Renders the entity name as an <h1>-styled button;
 * clicking swaps in an input. Enter/blur commits, Escape cancels. A rejected
 * save (e.g. 409 name-already-taken) is surfaced as a toast and the editor stays
 * open so the operator can pick another name.
 */
function InlineEditableName({
  name,
  onSave,
}: {
  name: string;
  onSave: (next: string) => void | Promise<unknown>;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(name);
  const [saving, setSaving] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (editing) {
      setDraft(name);
      inputRef.current?.focus();
      inputRef.current?.select();
    }
  }, [editing, name]);

  const commit = async () => {
    if (saving) return;
    const trimmed = draft.trim();
    if (!trimmed || trimmed === name) {
      setEditing(false);
      return;
    }
    setSaving(true);
    try {
      await onSave(trimmed);
      setEditing(false);
    } catch (err: unknown) {
      const data = (err as { response?: { data?: { error?: { message?: string }; detail?: string } } })?.response?.data;
      toast.error(data?.error?.message || data?.detail || "Couldn't rename this entity");
      inputRef.current?.focus();
    } finally {
      setSaving(false);
    }
  };

  if (editing) {
    return (
      <h1 className={styles.heroName}>
        <input
          ref={inputRef}
          className={styles.heroNameInput}
          value={draft}
          disabled={saving}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              commit();
            } else if (e.key === "Escape") {
              setEditing(false);
            }
          }}
        />
      </h1>
    );
  }

  return (
    <h1 className={styles.heroName}>
      <button
        type="button"
        className={styles.heroNameEditable}
        onClick={() => setEditing(true)}
        title="Rename"
      >
        {name}
        <span className={styles.heroNamePencil} aria-hidden="true">
          ✎
        </span>
      </button>
    </h1>
  );
}
