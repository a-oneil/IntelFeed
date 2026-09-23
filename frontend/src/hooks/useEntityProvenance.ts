import { useQuery } from "@tanstack/react-query";

import api from "@/api/client";

/** One assertion of one field value by one source. */
export interface FieldClaim {
  id: string;
  value: string;
  source_kind: "analyst" | "ai_extraction" | "ai_assessment" | "enrichment" | "external_feed" | "seed";
  source_label: string;
  source_ref: string | null;
  quote: string | null;
  confidence: string | null;
  analyst: string | null;
  entry: {
    id: string;
    title: string | null;
    published_at: string | null;
    feed_title: string | null;
    /** The feed's A–F reliability grade, when one has been set. */
    feed_reliability: string | null;
  } | null;
  first_asserted_at: string | null;
  last_asserted_at: string | null;
  /** Whether this claim still matches the live column value. */
  agrees: boolean | null;
}

export interface FieldProvenanceBucket {
  current_value: string | null;
  claims: FieldClaim[];
  agreeing?: number;
  conflicting?: number;
}

export interface EntityProvenance {
  entity_type: string;
  entity_id: string;
  fields: Record<string, FieldProvenanceBucket>;
  /** Tracked fields that hold a value but carry no claim at all. */
  unsourced_fields: string[];
  tracked_fields: string[];
}

/**
 * Field-level provenance for one entity — one request per profile, shared by
 * every field marker on it.
 */
// Types with tracked field claims (mirrors the backend's ENTITY_MODEL_MAP).
// Catalog types (mitigation, cwe) have no claimed fields — asking 400s and
// surfaces an error toast on every profile visit.
const PROVENANCE_TYPES = new Set([
  "threat_actor",
  "malware",
  "ttp",
  "cve",
  "country",
  "tool",
  "vendor",
  "product",
]);

export function useEntityProvenance(entityType: string | undefined, entityId: string | undefined) {
  return useQuery({
    queryKey: ["entity-provenance", entityType, entityId],
    queryFn: async () => {
      const res = await api.get<EntityProvenance>(`/entities/${entityType}/${entityId}/provenance`);
      return res.data;
    },
    enabled: !!entityType && !!entityId && PROVENANCE_TYPES.has(entityType),
    staleTime: 60_000,
  });
}
