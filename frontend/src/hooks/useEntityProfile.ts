import { useCallback } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import { useDeleteCampaign } from "@/hooks/useCampaigns";
import { useDeleteObservable } from "@/hooks/useIntelligence";
import { useIntelStore } from "@/stores/intelStore";
import type { CampaignDetectionGaps } from "@/api/types";

/**
 * Generate an AI assessment for an entity from its linked articles + metadata
 * and persist it to the entity's description. Backed by the dedicated
 * /entities/{type}/{id}/ai-summary endpoint (which saves to description), not
 * the generic AI-run endpoint — that one only stores an AIResult and, run on an
 * entity, blows up on the entry-oriented article_summary prompt.
 */
export function useGenerateEntitySummary() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ entityType, entityId }: { entityType: string; entityId: string }) => {
      const { data } = await api.post<{ summary: string; entity_id: string; entity_type: string }>(
        `/entities/${entityType}/${entityId}/ai-summary`,
        {},
        { timeout: 120000 },
      );
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["pivot", vars.entityType, vars.entityId] });
    },
  });
}

export function useUpdateThreatActor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: { id: string; name?: string; aliases?: string[]; description?: string; mitre_id?: string; country?: string; motivation?: string }) => {
      const { data } = await api.put(`/entities/threat-actors/${id}`, body);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["threat-actor", vars.id] });
      qc.invalidateQueries({ queryKey: ["threat-actors"] });
      qc.invalidateQueries({ queryKey: ["pivot", "threat_actor", vars.id] });
      // Refresh entry-level entity data so alias highlights update
      qc.invalidateQueries({ queryKey: ["entry-threat-actors"] });
    },
  });
}

export function useUpdateMalwareFamily() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: { id: string; name?: string; aliases?: string[]; description?: string; malpedia_url?: string; malware_type?: string }) => {
      const { data } = await api.put(`/entities/malware/${id}`, body);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["pivot", "malware", vars.id] });
      qc.invalidateQueries({ queryKey: ["malware"] });
      // Refresh entry-level entity data so alias highlights update
      qc.invalidateQueries({ queryKey: ["entry-malware"] });
    },
  });
}

export function useUpdateCVE() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: { id: string; description?: string; severity?: string; exploit_status?: string; affected_products?: unknown[]; exploit_availability?: string }) => {
      const { data } = await api.put(`/entities/cves/${id}`, body);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["cve", vars.id] });
      qc.invalidateQueries({ queryKey: ["cves"] });
      qc.invalidateQueries({ queryKey: ["pivot", "cve", vars.id] });
    },
  });
}

export function useUpdateTTP() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: { id: string; technique_name?: string; tactic?: string; description?: string }) => {
      const { data } = await api.put(`/entities/ttps/${id}`, body);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["pivot", "ttp", vars.id] });
      qc.invalidateQueries({ queryKey: ["ttps"] });
    },
  });
}

export function useUpdateCountry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: { id: string; name?: string; aliases?: string[]; iso_code?: string; region?: string; description?: string }) => {
      const { data } = await api.put(`/entities/countries/${id}`, body);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["country", vars.id] });
      qc.invalidateQueries({ queryKey: ["countries"] });
      qc.invalidateQueries({ queryKey: ["pivot", "country", vars.id] });
      // Refresh entry-level entity data so alias highlights update
      qc.invalidateQueries({ queryKey: ["entry-countries"] });
    },
  });
}

export function useUpdateOffensiveTool() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: { id: string; name?: string; aliases?: string[]; description?: string; tool_type?: string; malpedia_url?: string; github_url?: string }) => {
      const { data } = await api.put(`/entities/tools/${id}`, body);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["pivot", "tool", vars.id] });
      qc.invalidateQueries({ queryKey: ["tools"] });
    },
  });
}

// --- Unlink all entries ---

/** Matches the per-type entry→entity queries (["entry-vendors", id], …) that the
 *  reader's inline highlighter reads. Anything that removes or retypes an entity
 *  has to invalidate them or the old highlight survives in an open article. */
function isEntryEntityQuery(q: { queryKey: readonly unknown[] }): boolean {
  return typeof q.queryKey[0] === "string" && (q.queryKey[0] as string).startsWith("entry-");
}

export function useUnlinkAllEntries() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ entityType, entityId }: { entityType: string; entityId: string }) => {
      const { data } = await api.delete<{ unlinked: number }>(`/entities/${entityType}/${entityId}/unlink-all`);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["pivot", vars.entityType, vars.entityId] });
      qc.invalidateQueries({ queryKey: ["entity-graph", vars.entityType, vars.entityId] });
      qc.invalidateQueries({ queryKey: ["entity-timeline", vars.entityType, vars.entityId] });
      qc.invalidateQueries({ queryKey: ["workbench"] });
      // Entry→entity lists feed the reader's inline highlighter; without this the
      // just-unlinked entity stays underlined in any open article.
      qc.invalidateQueries({ predicate: isEntryEntityQuery });
    },
  });
}

// --- Delete hooks ---

export function useDeleteThreatActor() {
  const qc = useQueryClient();
  const clearSelectedEntity = useIntelStore((s) => s.clearSelectedEntity);
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/entities/threat-actors/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["threat-actors"] });
      qc.invalidateQueries({ queryKey: ["workbench"] });
      clearSelectedEntity();
    },
  });
}

export function useDeleteMalwareFamily() {
  const qc = useQueryClient();
  const clearSelectedEntity = useIntelStore((s) => s.clearSelectedEntity);
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/entities/malware/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["malware"] });
      qc.invalidateQueries({ queryKey: ["workbench"] });
      clearSelectedEntity();
    },
  });
}

export function useDeleteCVE() {
  const qc = useQueryClient();
  const clearSelectedEntity = useIntelStore((s) => s.clearSelectedEntity);
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/entities/cves/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cves"] });
      qc.invalidateQueries({ queryKey: ["workbench"] });
      clearSelectedEntity();
    },
  });
}

export function useDeleteTTP() {
  const qc = useQueryClient();
  const clearSelectedEntity = useIntelStore((s) => s.clearSelectedEntity);
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/entities/ttps/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ttps"] });
      qc.invalidateQueries({ queryKey: ["workbench"] });
      clearSelectedEntity();
    },
  });
}

export function useDeleteCountry() {
  const qc = useQueryClient();
  const clearSelectedEntity = useIntelStore((s) => s.clearSelectedEntity);
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/entities/countries/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["countries"] });
      qc.invalidateQueries({ queryKey: ["workbench"] });
      clearSelectedEntity();
    },
  });
}

export function useDeleteOffensiveTool() {
  const qc = useQueryClient();
  const clearSelectedEntity = useIntelStore((s) => s.clearSelectedEntity);
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/entities/tools/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tools"] });
      qc.invalidateQueries({ queryKey: ["workbench"] });
      clearSelectedEntity();
    },
  });
}


export function useUpdateVendor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: { id: string; name?: string; aliases?: string[]; description?: string; vendor_type?: string; website?: string }) => {
      const { data } = await api.put(`/entities/vendors/${id}`, body);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["vendor", vars.id] });
      qc.invalidateQueries({ queryKey: ["vendors"] });
      qc.invalidateQueries({ queryKey: ["pivot", "vendor", vars.id] });
      qc.invalidateQueries({ queryKey: ["entry-vendors"] });
    },
  });
}

export function useUpdateProduct() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: { id: string; name?: string; aliases?: string[]; description?: string; product_type?: string; website?: string; vendor_id?: string }) => {
      const { data } = await api.put(`/entities/products/${id}`, body);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["product", vars.id] });
      qc.invalidateQueries({ queryKey: ["products"] });
      qc.invalidateQueries({ queryKey: ["pivot", "product", vars.id] });
      qc.invalidateQueries({ queryKey: ["entry-products"] });
    },
  });
}

/** Entity types that expose a PUT endpoint (mitigation has none). */
export const EDITABLE_ENTITY_TYPES = [
  "threat_actor",
  "malware",
  "cve",
  "ttp",
  "country",
  "tool",
  "vendor",
  "product",
] as const;

export type EditableEntityType = (typeof EDITABLE_ENTITY_TYPES)[number];

/**
 * One field-update entry point for every entity type — the per-type PUT hooks
 * behind a single dispatch, so callers (profile header, table edit modal) don't
 * each re-implement the switch. Returns the underlying mutateAsync promise, so
 * a rejected save (e.g. 409 duplicate name) still surfaces to the caller.
 */
export function useUpdateEntity() {
  const qc = useQueryClient();
  const updateActor = useUpdateThreatActor();
  const updateMalware = useUpdateMalwareFamily();
  const updateCVE = useUpdateCVE();
  const updateTTP = useUpdateTTP();
  const updateCountry = useUpdateCountry();
  const updateTool = useUpdateOffensiveTool();
  const updateVendor = useUpdateVendor();
  const updateProduct = useUpdateProduct();

  return useCallback(
    (entityType: string, entityId: string, values: Record<string, unknown>): Promise<unknown> => {
      const payload = { id: entityId, ...values };
      switch (entityType) {
        case "threat_actor": return updateActor.mutateAsync(payload as Parameters<typeof updateActor.mutateAsync>[0]);
        case "malware": return updateMalware.mutateAsync(payload as Parameters<typeof updateMalware.mutateAsync>[0]);
        case "cve": return updateCVE.mutateAsync(payload as Parameters<typeof updateCVE.mutateAsync>[0]);
        case "ttp": return updateTTP.mutateAsync(payload as Parameters<typeof updateTTP.mutateAsync>[0]);
        case "country": return updateCountry.mutateAsync(payload as Parameters<typeof updateCountry.mutateAsync>[0]);
        case "tool": return updateTool.mutateAsync(payload as Parameters<typeof updateTool.mutateAsync>[0]);
        case "vendor": return updateVendor.mutateAsync(payload as Parameters<typeof updateVendor.mutateAsync>[0]);
        case "product": return updateProduct.mutateAsync(payload as Parameters<typeof updateProduct.mutateAsync>[0]);
        // Campaigns have their own resource; the shell edits name/status/TLP
        // through it exactly as it edits an actor's fields through /threat-actors.
        case "campaign":
          return api.patch(`/campaigns/${entityId}`, values).then((r) => {
            // The sibling hooks invalidate through their own mutations; the
            // campaign path is a bare request, so it clears the profile's
            // queries itself or the header keeps showing the old name.
            qc.invalidateQueries({ queryKey: ["pivot", "campaign", entityId] });
            qc.invalidateQueries({ queryKey: ["campaign", entityId] });
            qc.invalidateQueries({ queryKey: ["campaigns"] });
            return r.data;
          });
        default: return Promise.resolve();
      }
    },
    [qc, updateActor, updateMalware, updateCVE, updateTTP, updateCountry, updateTool, updateVendor, updateProduct],
  );
}

export function useDeleteVendor() {
  const qc = useQueryClient();
  const clearSelectedEntity = useIntelStore((s) => s.clearSelectedEntity);
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/entities/vendors/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vendors"] });
      qc.invalidateQueries({ queryKey: ["workbench"] });
      clearSelectedEntity();
    },
  });
}

export function useDeleteProduct() {
  const qc = useQueryClient();
  const clearSelectedEntity = useIntelStore((s) => s.clearSelectedEntity);
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/entities/products/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["products"] });
      qc.invalidateQueries({ queryKey: ["workbench"] });
      clearSelectedEntity();
    },
  });
}


/** Entity types whose creation paths consult the analyst do-not-recreate list.
 *  Denying anything else would write a row nothing reads. Mirrors
 *  DENIABLE_TYPES in app/intelligence/entity_resolution.py. */
export const DENIABLE_ENTITY_TYPES = new Set(["threat_actor", "malware", "tool", "cve", "ttp"]);

/** Ban an entity's name + aliases from being re-created by the one-pass
 *  extractor / autolinker. Call before deleting — it reads the live entity. */
export function useDenyEntityName() {
  return useMutation({
    mutationFn: async ({ entityType, entityId }: { entityType: string; entityId: string }) => {
      const { data } = await api.post<{ denied: number; names: string[] }>(
        `/entities/${entityType}/${entityId}/deny-name`,
        {},
      );
      return data;
    },
  });
}

/**
 * One delete entry point for every entity type — the per-type DELETE hooks
 * behind a single dispatch, so row menus and bulk table actions don't each
 * re-implement the switch.
 */
export function useDeleteEntity() {
  const deleteActor = useDeleteThreatActor();
  const deleteMalware = useDeleteMalwareFamily();
  const deleteCVE = useDeleteCVE();
  const deleteTTP = useDeleteTTP();
  const deleteCountry = useDeleteCountry();
  const deleteTool = useDeleteOffensiveTool();
  const deleteMitigationEntity = useDeleteMitigation();
  const deleteVendor = useDeleteVendor();
  const deleteProduct = useDeleteProduct();
  const deleteCampaign = useDeleteCampaign();
  const deleteObservable = useDeleteObservable();

  return useCallback(
    (entityType: string, entityId: string): Promise<unknown> => {
      switch (entityType) {
        case "threat_actor": return deleteActor.mutateAsync(entityId);
        case "malware": return deleteMalware.mutateAsync(entityId);
        case "cve": return deleteCVE.mutateAsync(entityId);
        case "ttp": return deleteTTP.mutateAsync(entityId);
        case "country": return deleteCountry.mutateAsync(entityId);
        case "tool": return deleteTool.mutateAsync(entityId);
        case "mitigation": return deleteMitigationEntity.mutateAsync(entityId);
        case "vendor": return deleteVendor.mutateAsync(entityId);
        case "product": return deleteProduct.mutateAsync(entityId);
        // Sightings and relationships go with the row. Callers that want the
        // value kept out for good deny it instead (useDenyObservable) — that
        // leaves the tombstone every capture door reads.
        case "observable": return deleteObservable.mutateAsync(entityId);
        // Campaigns cascade their own membership rows server-side; nothing the
        // campaign held is deleted with it, only the fact that it held them.
        case "campaign": return deleteCampaign.mutateAsync(entityId);
        // No handler = loud failure — a resolved promise here once produced
        // "Deleted N observables" toasts over rows that were never touched.
        default: return Promise.reject(new Error(`No delete handler for entity type "${entityType}"`));
      }
    },
    [deleteActor, deleteMalware, deleteCVE, deleteTTP, deleteCountry, deleteTool, deleteMitigationEntity, deleteVendor, deleteProduct, deleteCampaign, deleteObservable],
  );
}


// --- Merge & Duplicate Detection ---

export interface DuplicateEntity {
  id: string;
  name: string;
  aliases: string[];
  mitre_id?: string | null;
  article_count: number;
  description?: string | null;
  match_reasons: string[];
}

export interface DuplicateGroup {
  entities: DuplicateEntity[];
}

export interface DuplicatesResponse {
  groups: DuplicateGroup[];
  total_groups: number;
}

export function useFindDuplicates(entityType: string, enabled: boolean) {
  return useQuery<DuplicatesResponse>({
    queryKey: ["entity-duplicates", entityType],
    queryFn: async () => {
      const { data } = await api.get(`/entities/${entityType}/duplicates`);
      return data;
    },
    enabled,
    staleTime: 60_000,
  });
}

export function useMergeEntities() {
  const qc = useQueryClient();
  const clearSelectedEntity = useIntelStore((s) => s.clearSelectedEntity);
  return useMutation({
    mutationFn: async ({ entityType, keeperId, mergeIds }: { entityType: string; keeperId: string; mergeIds: string[] }) => {
      const { data } = await api.post(`/entities/${entityType}/merge`, {
        keeper_id: keeperId,
        merge_ids: mergeIds,
      });
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["entity-duplicates", vars.entityType] });
      qc.invalidateQueries({ queryKey: ["entity-merge-suggestions"] });
      qc.invalidateQueries({ queryKey: ["threat-actors"] });
      qc.invalidateQueries({ queryKey: ["malware"] });
      qc.invalidateQueries({ queryKey: ["countries"] });
      qc.invalidateQueries({ queryKey: ["tools"] });
      qc.invalidateQueries({ queryKey: ["vendors"] });
      qc.invalidateQueries({ queryKey: ["products"] });
      qc.invalidateQueries({ queryKey: ["workbench"] });
      qc.invalidateQueries({ queryKey: ["pivot"] });
      qc.invalidateQueries({ predicate: isEntryEntityQuery });
      clearSelectedEntity();
    },
  });
}

// --- Ranked merge suggestions (scored pairs + persisted dismissals) ---

export interface MergeSuggestionEntity {
  id: string;
  entity_type: string;
  name: string;
  aliases: string[];
  article_count: number;
}

export interface MergeSuggestion {
  keeper: MergeSuggestionEntity;
  candidate: MergeSuggestionEntity;
  score: number;
  reasons: string[];
  cross_type: boolean;
}

export interface MergeSuggestionsResponse {
  suggestions: MergeSuggestion[];
  total: number;
}

export function useMergeSuggestions(entityType: string, enabled: boolean) {
  return useQuery<MergeSuggestionsResponse>({
    queryKey: ["entity-merge-suggestions", entityType],
    queryFn: async () => {
      const { data } = await api.get(`/entities/${entityType}/merge-suggestions`);
      return data;
    },
    enabled,
    staleTime: 60_000,
  });
}

export function useDismissMergeSuggestion() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (suggestion: MergeSuggestion) => {
      const { data } = await api.post(`/entities/merge-suggestions/dismiss`, {
        entity_type_a: suggestion.keeper.entity_type,
        entity_id_a: suggestion.keeper.id,
        entity_type_b: suggestion.candidate.entity_type,
        entity_id_b: suggestion.candidate.id,
      });
      return data as { dismissed: boolean };
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["entity-merge-suggestions"] });
    },
  });
}

// Entity types that the merge endpoint (MERGE_CONFIG) supports. Mirrors
// backend/app/api/entity_profiles.py. CVE/TTP/mitigation are not mergeable.
export const MERGEABLE_ENTITY_TYPES = ["threat_actor", "malware", "country", "tool", "vendor", "product"] as const;

// Frontend EntityType → list endpoint used to search for a merge target.
const ENTITY_SEARCH_ENDPOINTS: Record<string, string> = {
  threat_actor: "/threat-actors",
  malware: "/malware",
  country: "/countries",
  tool: "/tools",
  vendor: "/vendors",
  product: "/products",
};

export interface MergeCandidate {
  id: string;
  name: string;
  aliases?: string[] | null;
  description?: string | null;
  article_count?: number | null;
  mitre_id?: string | null;
}

/** Search entities of a single type by name, to pick a merge target. */
export function useEntitySearch(entityType: string, query: string, enabled: boolean) {
  const endpoint = ENTITY_SEARCH_ENDPOINTS[entityType];
  return useQuery<MergeCandidate[]>({
    queryKey: ["entity-search", entityType, query],
    queryFn: async () => {
      const { data } = await api.get<{ items: MergeCandidate[] }>(endpoint, {
        params: { search: query, limit: 20, sort_by: "article_count", sort_order: "desc" },
      });
      return data.items ?? [];
    },
    enabled: enabled && !!endpoint,
    staleTime: 30_000,
  });
}

// --- Convert entity type ---

export function useConvertEntity() {
  const qc = useQueryClient();
  const clearSelectedEntity = useIntelStore((s) => s.clearSelectedEntity);
  return useMutation({
    mutationFn: async ({
      entityId,
      targetType,
      targetIdentifier,
    }: {
      entityId: string;
      targetType: string;
      /** Required when targetType is "cve" (a CVE ID) or "ttp" (an ATT&CK technique ID). */
      targetIdentifier?: string;
    }) => {
      const { data } = await api.post<{ id: string; name: string; source_type: string; target_type: string; migrated_entry_links: number }>("/entities/convert", {
        entity_id: entityId,
        target_type: targetType,
        ...(targetIdentifier ? { target_identifier: targetIdentifier } : {}),
      });
      return data;
    },
    onSuccess: () => {
      // Convert can touch any of the 8 entity types — invalidate the full set
      // plus the shared workbench/pivot/dup caches.
      for (const key of ["threat-actors", "malware", "tools", "vendors", "products", "countries", "cves", "ttps"]) {
        qc.invalidateQueries({ queryKey: [key] });
      }
      qc.invalidateQueries({ queryKey: ["workbench"] });
      qc.invalidateQueries({ queryKey: ["pivot"] });
      qc.invalidateQueries({ queryKey: ["entity-duplicates"] });
      // The source entity no longer exists under its old type — drop the entry
      // links the reader highlighted it from.
      qc.invalidateQueries({ predicate: isEntryEntityQuery });
      clearSelectedEntity();
    },
  });
}

export function useDeleteMitigation() {
  const qc = useQueryClient();
  const clearSelectedEntity = useIntelStore((s) => s.clearSelectedEntity);
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/entities/mitigations/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["mitigations"] });
      qc.invalidateQueries({ queryKey: ["workbench"] });
      clearSelectedEntity();
    },
  });
}

// --- Wikipedia ---

export function useFetchWikipedia() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ entityType, entityId, title }: { entityType: string; entityId: string; title?: string }) => {
      const { data } = await api.post<{
        wikipedia_url: string;
        wikipedia_title: string;
        wikipedia_content: string;
        wikipedia_image_url: string | null;
        entity_id: string;
        entity_type: string;
      }>(`/entities/${entityType}/${entityId}/wikipedia`, title ? { title } : undefined);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["pivot", vars.entityType, vars.entityId] });
    },
  });
}

// --- Rescan ---

/** Queue a re-scan of all existing entries for mentions of this entity (background job). */
export function useRescanEntity() {
  return useMutation({
    mutationFn: async ({ entityType, entityId }: { entityType: string; entityId: string }) => {
      const { data } = await api.post<{ queued: boolean; entity_type: string; entity_id: string }>(
        `/entities/${entityType}/${entityId}/rescan`,
      );
      return data;
    },
  });
}

// --- ATT&CK / detection gaps ---

export function useEntityAttackLayer(entityType: string | undefined, entityId: string | undefined) {
  return useQuery({
    queryKey: ["entity-attack-layer", entityType, entityId],
    queryFn: async () => {
      const { data } = await api.get(`/entities/${entityType}/${entityId}/attack-layer`);
      return data;
    },
    enabled: !!entityType && !!entityId,
  });
}

export function useEntityDetectionGaps(entityType: string | undefined, entityId: string | undefined) {
  return useQuery({
    queryKey: ["entity-detection-gaps", entityType, entityId],
    queryFn: async () => {
      const { data } = await api.get<CampaignDetectionGaps>(`/entities/${entityType}/${entityId}/detection-gaps`);
      return data;
    },
    enabled: !!entityType && !!entityId,
  });
}

export interface EntityCampaignRef {
  id: string;
  name: string;
  status: string;
  role: string;
}

/** Campaigns this entity belongs to — the Snapshot's Campaigns row. */
export function useEntityCampaigns(entityType: string | undefined, entityId: string | undefined) {
  return useQuery({
    queryKey: ["entity-campaigns", entityType, entityId],
    queryFn: async () => {
      const { data } = await api.get<EntityCampaignRef[]>(`/campaigns/by-entity/${entityType}/${entityId}`);
      return data;
    },
    enabled: !!entityType && !!entityId,
    staleTime: 5 * 60 * 1000,
  });
}

export interface AttackTechniqueRow {
  id: string;
  technique_id: string;
  technique_name: string | null;
  tactic: string | null;
  articles: number;
  last_seen: string | null;
}

/** Evidence-ranked technique list for the ATT&CK tab (actor/malware only). */
export function useEntityAttackTechniques(entityType: string | undefined, entityId: string | undefined) {
  return useQuery({
    queryKey: ["entity-attack-techniques", entityType, entityId],
    queryFn: async () => {
      const { data } = await api.get<{ items: AttackTechniqueRow[] }>(
        `/entities/${entityType}/${entityId}/attack-techniques`,
      );
      return data.items;
    },
    enabled: !!entityType && !!entityId,
    staleTime: 5 * 60 * 1000,
  });
}

export interface ActorVictimRow {
  id: string;
  name: string;
  sector: string | null;
  sector_label: string | null;
  country_name: string | null;
  country_code: string | null;
  last_seen_at: string | null;
  disclosure_count: number;
}

/** Leak-site victims for a ransomware actor — the Overview's victims strip.
 * 404s (tracker disabled / not a group) resolve to an empty list. */
export function useActorVictims(entityId: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: ["actor-victims", entityId],
    queryFn: async () => {
      try {
        const { data } = await api.get<{ items: ActorVictimRow[]; total: number }>(
          `/ransomware/groups/${entityId}/victims`,
          { params: { limit: 5 } },
        );
        return data;
      } catch {
        return { items: [], total: 0 };
      }
    },
    enabled: enabled && !!entityId,
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
}

export interface ActorVictimStats {
  total: number;
  last_30d: number;
  prev_30d: number;
}

/** Windowed victim counts for the Snapshot's "Leak-site victims · 30d" row.
 * Same 404 tolerance as useActorVictims — null means "no tracker data". */
export function useActorVictimStats(entityId: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: ["actor-victim-stats", entityId],
    queryFn: async (): Promise<ActorVictimStats | null> => {
      try {
        const { data } = await api.get<ActorVictimStats>(`/ransomware/groups/${entityId}/victims/stats`);
        return data;
      } catch {
        return null;
      }
    },
    enabled: enabled && !!entityId,
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
}

export interface EntityStoryThread {
  slug: string;
  title: string;
  summary: string | null;
  status: string;
  entry_count: number;
  source_count: number;
  first_seen: string | null;
  last_seen: string | null;
  entity_entry_count: number;
  latest_beat: { headline: string; occurred_at: string | null } | null;
}

/** Story threads this entity's articles belong to. status "open" feeds the
 * Active Story card; "any" feeds the expanded timeline's story markers. */
export function useEntityStoryThreads(
  entityType: string | undefined,
  entityId: string | undefined,
  opts: { limit?: number; status?: string; enabled?: boolean } = {},
) {
  const { limit = 2, status = "open", enabled = true } = opts;
  return useQuery({
    queryKey: ["entity-story-threads", entityType, entityId, status, limit],
    queryFn: async () => {
      const { data } = await api.get<{ items: EntityStoryThread[] }>(
        `/entities/${entityType}/${entityId}/story-threads`,
        { params: { limit, status } },
      );
      return data.items;
    },
    enabled: enabled && !!entityType && !!entityId,
    staleTime: 5 * 60 * 1000,
  });
}

export type MentionsWindow = "24h" | "7d" | "30d" | "60d" | "90d" | "all";

export const MENTIONS_WINDOWS: MentionsWindow[] = ["24h", "7d", "30d", "60d", "90d", "all"];

export interface MentionsTimeseriesPoint {
  date: string;
  count: number;
  feeds: number;
}

export interface MentionsTimeseries {
  window: MentionsWindow;
  bucket: "hour" | "day" | "week";
  total_feeds: number;
  /** Mentions in the window immediately before this one; null for "all". */
  previous_total: number | null;
  /** The busiest feed's share of this window's mentions (newsletter-echo proxy); null when empty. */
  top_feed_share: number | null;
  points: MentionsTimeseriesPoint[];
}

export function useEntityMentionsTimeseries(
  entityType: string | undefined,
  entityId: string | undefined,
  window: MentionsWindow = "90d",
) {
  return useQuery({
    queryKey: ["entity-mentions-timeseries", entityType, entityId, window],
    queryFn: async () => {
      const { data } = await api.get<MentionsTimeseries>(
        `/entities/${entityType}/${entityId}/mentions-timeseries`,
        { params: { window } },
      );
      return data;
    },
    enabled: !!entityType && !!entityId,
    staleTime: 5 * 60 * 1000,
    // Keep the previous window's series on screen while the next one loads —
    // switching ranges shouldn't flash the empty state.
    placeholderData: (prev) => prev,
  });
}

export interface TopEntryItem {
  entry_id: string;
  title: string;
  published_at: string | null;
  feed_title: string | null;
  signal?: number | null;
}

export function useEntityTopEntries(
  entityType: string | undefined,
  entityId: string | undefined,
  days = 30,
) {
  return useQuery({
    queryKey: ["entity-top-entries", entityType, entityId, days],
    queryFn: async () => {
      const { data } = await api.get<{ items: TopEntryItem[] }>(
        `/entities/${entityType}/${entityId}/top-entries`,
        { params: { days } },
      );
      return data.items;
    },
    enabled: !!entityType && !!entityId,
    staleTime: 5 * 60 * 1000,
  });
}

/** Articles mentioning the entity inside one timeline bucket. */
export function useEntityEntriesWindow(
  entityType: string | undefined,
  entityId: string | undefined,
  start: string | undefined,
  end: string | undefined,
) {
  return useQuery({
    queryKey: ["entity-entries-window", entityType, entityId, start, end],
    queryFn: async () => {
      const { data } = await api.get<{ items: TopEntryItem[] }>(
        `/entities/${entityType}/${entityId}/entries-window`,
        { params: { start, end } },
      );
      return data.items;
    },
    enabled: !!entityType && !!entityId && !!start && !!end,
    staleTime: 5 * 60 * 1000,
  });
}

export function useClearWikipedia() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ entityType, entityId }: { entityType: string; entityId: string }) => {
      const { data } = await api.delete<{
        entity_id: string;
        entity_type: string;
        wikipedia_cleared: boolean;
      }>(`/entities/${entityType}/${entityId}/wikipedia`);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["pivot", vars.entityType, vars.entityId] });
    },
  });
}

export interface WikipediaSearchResult {
  title: string;
  snippet: string;
  url: string;
}

export function useWikipediaSearch(entityType: string, entityId: string, query: string) {
  return useQuery({
    queryKey: ["wikipedia-search", entityType, entityId, query],
    queryFn: async () => {
      const { data } = await api.get<{ results: WikipediaSearchResult[] }>(
        `/entities/${entityType}/${entityId}/wikipedia/search`,
        { params: { q: query } },
      );
      return data.results;
    },
    enabled: query.trim().length >= 2,
    staleTime: 60_000,
  });
}
