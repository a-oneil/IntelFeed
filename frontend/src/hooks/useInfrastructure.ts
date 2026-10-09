import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";
import type { EntityType } from "@/stores/intelStore";

/** One observable behind an entity, as the infrastructure endpoint returns it. */
export interface InfrastructureObservable {
  id: string;
  kind: string;
  value: string;
  label: string | null;
  role: string | null;
  status: string;
  infra_tag: string | null;
  current_confidence: number;
  report_count: number;
  feed_source_count: number;
  sighting_count: number;
  first_seen_at: string | null;
  last_seen_at: string | null;
  created_via: string | null;
}

export interface ClaimedObservable extends InfrastructureObservable {
  relationship_id: string;
  relationship_type: string;
  relationship_confidence: string;
  relationship_source: string;
  adjudication_verdict: string | null;
  evidence_entry_ids: string[];
  evidence_count: number;
}

export interface ReportedObservable extends InfrastructureObservable {
  article_count: number;
  last_reported_at: string | null;
  entry_ids: string[];
}

export interface EntityInfrastructure {
  entity_type: string;
  entity_id: string;
  claimed: ClaimedObservable[];
  reported_alongside: ReportedObservable[];
  counts: {
    claimed: number;
    reported_alongside: number;
    by_kind: Record<string, number>;
    /** This entity's articles still carrying staged (un-promoted) candidates. */
    staged_candidate_articles: number;
  };
}

export const INFRASTRUCTURE_TYPES: readonly EntityType[] = ["threat_actor", "malware", "campaign", "tool"];

/** Claimed + reported-alongside observables for an actor/family/campaign/tool.
 *  Disabled (no request) for every other entity type. */
export function useEntityInfrastructure(entityType: EntityType | undefined, entityId: string | undefined) {
  const enabled = !!entityId && !!entityType && INFRASTRUCTURE_TYPES.includes(entityType);
  return useQuery({
    queryKey: ["entity-infrastructure", entityType, entityId],
    queryFn: async () => {
      const { data } = await api.get<EntityInfrastructure>(`/entities/${entityType}/${entityId}/infrastructure`);
      return data;
    },
    enabled,
    staleTime: 5 * 60 * 1000,
  });
}

export interface ObservableBacklink {
  entity_type: string;
  entity_id: string;
  name: string | null;
  relationship_id?: string;
  relationship_type?: string;
  relationship_confidence?: string;
  relationship_source?: string;
  adjudication_verdict?: string | null;
  evidence_count?: number;
  article_count?: number;
}

export interface ObservableBacklinks {
  observable_id: string;
  claimed_by: ObservableBacklink[];
  reported_with: ObservableBacklink[];
}

/** The mirror for an observable's profile: who claims it, who it is reported with. */
export function useObservableBacklinks(observableId: string | undefined) {
  return useQuery({
    queryKey: ["observable-backlinks", observableId],
    queryFn: async () => {
      const { data } = await api.get<ObservableBacklinks>(`/observables/${observableId}/backlinks`);
      return data;
    },
    enabled: !!observableId,
    staleTime: 5 * 60 * 1000,
  });
}

export function infrastructureCsvUrl(entityType: string, entityId: string): string {
  return `/entities/${entityType}/${entityId}/infrastructure?format=csv`;
}
