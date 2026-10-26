/**
 * AssessmentBlock — the profile's voice: the entity description promoted to a
 * prominent, analyst-editable narrative with an AI refresh, followed by dated
 * "latest developments" from the What's-New engine — the briefing column's
 * opening module.
 */
import { toast } from "sonner";
import { Link } from "react-router-dom";
import { InlineEditField } from "@/components/InlineEditField";
import { useGenerateEntitySummary } from "@/hooks/useEntityProfile";
import { useEntityProvenance } from "@/hooks/useEntityProvenance";
import { useTts } from "@/hooks/useTts";
import type { WhatsNewItem } from "@/hooks/useEngine";
import { formatDate } from "@/utils/formatDate";
import type { EntityType } from "@/stores/intelStore";
import type { EntitySearchResult } from "@/api/types";
import { entityProfilePath } from "./entityProfileConfig";
import { FieldProvenance } from "./FieldProvenance";
import styles from "./entityProfile.module.css";
import { useIsVisitor } from "@/stores/authStore";

const DEVELOPMENTS_LIMIT = 4;

const SIGNAL_LABELS: Record<string, string> = {
  novel_entity: "new",
  entity_resurgence: "resurfaced",
  new_pairing: "new pairing",
  scoop: "scoop",
  kev_added: "KEV",
  epss_jump: "EPSS jump",
  epss_high: "high EPSS",
  weaponized_poc: "weaponized PoC",
  under_reported: "under-reported",
};

export function AssessmentBlock({
  entityType,
  entityId,
  entity,
  editable,
  whatsNew = [],
  onUpdateField,
  onOpenArticle,
}: {
  entityType: EntityType;
  entityId: string;
  entity: EntitySearchResult;
  editable: boolean;
  whatsNew?: WhatsNewItem[];
  onUpdateField: (field: string, value: string | string[]) => void;
  onOpenArticle: (entryId: string) => void;
}) {
  // Visitors read the saved assessment; read-aloud for it would have to make new audio.
  const isVisitor = useIsVisitor();
  const runAI = useGenerateEntitySummary();
  const { start: startTts, isPreparing: ttsPreparing } = useTts();
  // Shares the profile header's request — TanStack dedupes on the query key.
  const { data: provenance } = useEntityProvenance(entityType, entityId);

  const displayName = entity.name || entity.cve_id || entity.technique_name || "assessment";
  const listen = () => {
    startTts({
      source: "entity",
      id: entityId,
      entityType,
      track: { entryId: "", title: `${displayName} — assessment`, feedTitle: "IntelFeed briefing" },
    });
  };

  const refresh = () => {
    runAI.mutate(
      { entityType, entityId },
      {
        onSuccess: () => toast.success("Assessment refreshed from recent reporting"),
        onError: (err: unknown) =>
          toast.error(
            (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
              "Failed to refresh assessment",
          ),
      },
    );
  };

  const developments = whatsNew.slice(0, DEVELOPMENTS_LIMIT);

  return (
    <div className={styles.assessment}>
      <div className={styles.assessmentHead}>
        <span className={styles.assessmentTitle}>Assessment</span>
        {provenance && (
          <FieldProvenance
            field="description"
            label="Assessment"
            bucket={provenance.fields.description}
            unsourced={provenance.unsourced_fields.includes("description")}
            onOpenArticle={onOpenArticle}
          />
        )}
        {entity.description && !isVisitor && (
          <button
            className={styles.assessmentListen}
            onClick={listen}
            disabled={ttsPreparing}
            title="Read this assessment aloud"
          >
            {ttsPreparing ? "Preparing…" : "▶ Listen"}
          </button>
        )}
        {editable && (
          <button
            className={styles.assessmentRefresh}
            onClick={refresh}
            disabled={runAI.isPending}
            title="Regenerate from linked articles and relationships using your assigned AI model — saves to the description"
          >
            {runAI.isPending ? "Refreshing…" : "↻ AI refresh"}
          </button>
        )}
      </div>

      <div className={styles.assessmentBody}>
        <InlineEditField
          value={entity.description || ""}
          placeholder={editable ? "No assessment yet — write one, or let AI draft it from recent reporting…" : "No assessment yet"}
          multiline
          renderMarkdown
          linkEntities
          excludeEntityId={entity.id}
          onSave={(v) => onUpdateField("description", v)}
        />
      </div>

      {(() => {
        // Plain-language provenance under the prose: when the assessment was
        // drafted and from how many sources — the popover has the receipts.
        const bucket = provenance?.fields?.description;
        if (!entity.description || !bucket?.claims?.length) return null;
        const ai = bucket.claims.filter((c) => c.source_kind === "ai_assessment" || c.source_kind === "ai_extraction");
        const latest = [...(ai.length ? ai : bucket.claims)].sort(
          (x, y) => new Date(y.last_asserted_at ?? 0).getTime() - new Date(x.last_asserted_at ?? 0).getTime(),
        )[0];
        const when = latest?.last_asserted_at ? formatDate(latest.last_asserted_at) : null;
        const n = bucket.claims.length;
        return (
          <div className={styles.assessmentProvLine}>
            {ai.length ? "AI-drafted" : "Sourced"}
            {when ? ` ${when}` : ""} · {n} claim{n === 1 ? "" : "s"} on record
          </div>
        );
      })()}

      {developments.length > 0 && (
        <div className={styles.developments}>
          <div className={styles.developmentsTitle}>Latest developments</div>
          {developments.map((item, i) => (
            <div key={`${item.signal_type}:${i}`} className={styles.development}>
              <span className={styles.developmentDate}>
                {item.published_at ? formatDate(item.published_at) : "—"}
              </span>
              <span className={styles.developmentText}>
                <button className={styles.developmentLink} onClick={() => onOpenArticle(item.entry_id)}>
                  {item.explanation || item.entry_title}
                </button>
                {item.subject?.id && (
                  <Link
                    className={styles.developmentSubject}
                    to={entityProfilePath(item.subject.type as EntityType, item.subject.id)}
                  >
                    {item.subject.name}
                  </Link>
                )}
                <span className={styles.developmentTag}>
                  {SIGNAL_LABELS[item.signal_type] || item.signal_type.replace(/_/g, " ")}
                </span>
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
