import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";

/** One chip or fact in the highlight popover's glance. */
export interface GlanceItem {
  text: string;
  /** "bad" (exploited, no patch, EOL) or "warn" (probably benign, new); null is neutral. */
  tone: "bad" | "warn" | null;
  /** The source that said it; null for a count the enrichment links made. */
  source: string | null;
  observed_at: string | null;
}

interface EntityGlance {
  /** At most two verdict chips. */
  chips: GlanceItem[];
  /** At most three short facts, for the popover's Context row. */
  facts: GlanceItem[];
  /** What the Look up button runs (empty for visitors). */
  lookup_sources: Array<{ source_type: string; label: string }>;
  /** Admins only: sources that need a key before they can run. */
  needs_key: Array<{ source_type: string; label: string; key: string | null }>;
  /** Some source has answered for this entity: the button says Refresh. */
  looked_up: boolean;
}

export const entityGlanceKey = (entityType: string, entityId: string) =>
  ["entity-glance", entityType, entityId] as const;

/** The highlight popover's glance. Optional by design: a failed request
 *  leaves the popover as it is without enrichment. */
export function useEntityGlance(entityType: string, entityId: string | undefined) {
  return useQuery({
    queryKey: entityGlanceKey(entityType, entityId ?? ""),
    queryFn: async () => {
      const { data } = await api.get<EntityGlance>(`/entities/${entityType}/${entityId}/glance`);
      return data;
    },
    enabled: !!entityId,
    // Supplementary: a failure leaves the popover as it is, with no toast.
    meta: { silenceToast: true },
    staleTime: 5 * 60_000,
    retry: false,
  });
}
