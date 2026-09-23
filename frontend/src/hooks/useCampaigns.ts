import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type {
  Campaign,
  CampaignCountryResponse,
  CampaignCountrySuggestion,
  CampaignCreate,
  CampaignDetectionGaps,
  CampaignEntityResponse,
  CampaignSavedSearch,
  CampaignSavedSearchSyncResult,
  CampaignSource,
  CampaignSourceSuggestion,
  CampaignStats,
  CampaignSuggestion,
  CampaignTimelineEntry,
  CampaignUpdate,
  PaginatedResponse,
} from "@/api/types";

// --- CRUD ---

export function useCampaigns(params?: { status?: string; limit?: number; offset?: number; sort_by?: string; sort_order?: string }) {
  return useQuery({
    queryKey: ["campaigns", params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<Campaign>>("/campaigns", { params });
      return data;
    },
  });
}

export function useCampaign(id: string | undefined) {
  return useQuery({
    queryKey: ["campaign", id],
    queryFn: async () => {
      const { data } = await api.get<Campaign>(`/campaigns/${id}`);
      return data;
    },
    enabled: !!id,
  });
}

export function useCreateCampaign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: CampaignCreate) => {
      const { data } = await api.post<Campaign>("/campaigns", body);
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["campaigns"] }),
  });
}

export function useUpdateCampaign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: CampaignUpdate & { id: string }) => {
      const { data } = await api.patch<Campaign>(`/campaigns/${id}`, body);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["campaigns"] });
      qc.invalidateQueries({ queryKey: ["campaign", vars.id] });
    },
  });
}

export function useDeleteCampaign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/campaigns/${id}`);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["campaigns"] }),
  });
}

// --- Entries & Entities ---

export function useCampaignsForEntry(entryId: string | undefined) {
  return useQuery({
    queryKey: ["campaigns-for-entry", entryId],
    queryFn: async () => {
      const { data } = await api.get<string[]>(`/campaigns/by-entry/${entryId}`);
      return data;
    },
    enabled: !!entryId,
  });
}

export function useAddCampaignEntry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ campaignId, entryId, notes }: { campaignId: string; entryId: string; notes?: string }) => {
      const { data } = await api.post(`/campaigns/${campaignId}/entries`, {
        entry_id: entryId,
        notes,
      });
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["campaign", vars.campaignId] });
      qc.invalidateQueries({ queryKey: ["campaign-timeline", vars.campaignId] });
      qc.invalidateQueries({ queryKey: ["campaign-suggestions", vars.campaignId] });
      qc.invalidateQueries({ queryKey: ["campaigns-for-entry", vars.entryId] });
    },
  });
}

export function useAddCampaignEntity() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      campaignId,
      entityType,
      entityId,
      role,
    }: {
      campaignId: string;
      entityType: string;
      entityId: string;
      role?: string;
    }) => {
      const { data } = await api.post(`/campaigns/${campaignId}/entities`, {
        entity_type: entityType,
        entity_id: entityId,
        role: role || "related",
      });
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["campaign", vars.campaignId] });
    },
  });
}

// --- Extension endpoints ---

export function useCampaignTimeline(campaignId: string | undefined) {
  return useQuery({
    queryKey: ["campaign-timeline", campaignId],
    queryFn: async () => {
      const { data } = await api.get<CampaignTimelineEntry[]>(
        `/campaigns/${campaignId}/timeline`
      );
      return data;
    },
    enabled: !!campaignId,
  });
}

export function useCampaignAttackLayer(campaignId: string | undefined) {
  return useQuery({
    queryKey: ["campaign-attack-layer", campaignId],
    queryFn: async () => {
      const { data } = await api.get(`/campaigns/${campaignId}/attack-layer`);
      return data;
    },
    enabled: !!campaignId,
  });
}

/** Add several entries at once — a whole story is one action, not nine. */
export function useAddCampaignEntries() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ campaignId, entryIds }: { campaignId: string; entryIds: string[] }) => {
      const { data } = await api.post<{ added: number; skipped: number }>(
        `/campaigns/${campaignId}/entries/bulk`,
        { entry_ids: entryIds }
      );
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["campaign", vars.campaignId] });
      qc.invalidateQueries({ queryKey: ["campaign-timeline", vars.campaignId] });
      qc.invalidateQueries({ queryKey: ["campaign-suggestions", vars.campaignId] });
      qc.invalidateQueries({ queryKey: ["campaign-stats", vars.campaignId] });
    },
  });
}

export function useCampaignSuggestions(
  campaignId: string | undefined,
  params?: { min_overlap?: number; limit?: number }
) {
  return useQuery({
    queryKey: ["campaign-suggestions", campaignId, params],
    queryFn: async () => {
      const { data } = await api.get<CampaignSuggestion[]>(
        `/campaigns/${campaignId}/suggest`,
        { params }
      );
      return data;
    },
    enabled: !!campaignId,
  });
}

// --- Campaign Saved Searches ---

export function useCampaignSavedSearches(campaignId: string | undefined) {
  return useQuery({
    queryKey: ["campaign-saved-searches", campaignId],
    queryFn: async () => {
      const { data } = await api.get<CampaignSavedSearch[]>(
        `/campaigns/${campaignId}/saved-searches`
      );
      return data;
    },
    enabled: !!campaignId,
  });
}

export function useAddCampaignSavedSearch() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      campaignId,
      savedSearchId,
      autoSync,
    }: {
      campaignId: string;
      savedSearchId: string;
      autoSync?: boolean;
    }) => {
      const { data } = await api.post<CampaignSavedSearch>(
        `/campaigns/${campaignId}/saved-searches`,
        { saved_search_id: savedSearchId, auto_sync: autoSync ?? true }
      );
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["campaign-saved-searches", vars.campaignId] });
      qc.invalidateQueries({ queryKey: ["campaign", vars.campaignId] });
    },
  });
}

export function useUpdateCampaignSavedSearch() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      campaignId,
      cssId,
      autoSync,
    }: {
      campaignId: string;
      cssId: string;
      autoSync: boolean;
    }) => {
      const { data } = await api.patch<CampaignSavedSearch>(
        `/campaigns/${campaignId}/saved-searches/${cssId}`,
        { auto_sync: autoSync }
      );
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["campaign-saved-searches", vars.campaignId] });
    },
  });
}

export function useRemoveCampaignSavedSearch() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      campaignId,
      cssId,
    }: {
      campaignId: string;
      cssId: string;
    }) => {
      await api.delete(`/campaigns/${campaignId}/saved-searches/${cssId}`);
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["campaign-saved-searches", vars.campaignId] });
      qc.invalidateQueries({ queryKey: ["campaign", vars.campaignId] });
    },
  });
}

export function useSyncCampaignSavedSearch() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      campaignId,
      cssId,
    }: {
      campaignId: string;
      cssId: string;
    }) => {
      const { data } = await api.post<CampaignSavedSearchSyncResult>(
        `/campaigns/${campaignId}/saved-searches/${cssId}/sync`
      );
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["campaign-saved-searches", vars.campaignId] });
      qc.invalidateQueries({ queryKey: ["campaign", vars.campaignId] });
      qc.invalidateQueries({ queryKey: ["campaign-timeline", vars.campaignId] });
    },
  });
}

// --- Detection Gaps ---

export function useCampaignDetectionGaps(campaignId: string | undefined) {
  return useQuery({
    queryKey: ["campaign-detection-gaps", campaignId],
    queryFn: async () => {
      const { data } = await api.get<CampaignDetectionGaps>(
        `/campaigns/${campaignId}/detection-gaps`
      );
      return data;
    },
    enabled: !!campaignId,
  });
}

// --- Campaign Entities ---

export function useCampaignEntities(
  campaignId: string | undefined,
  entityType?: string
) {
  return useQuery({
    queryKey: ["campaign-entities", campaignId, entityType],
    queryFn: async () => {
      const { data } = await api.get<CampaignEntityResponse[]>(
        `/campaigns/${campaignId}/entities`,
        { params: entityType ? { entity_type: entityType } : undefined }
      );
      return data;
    },
    enabled: !!campaignId,
  });
}

export function useRemoveCampaignEntity() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      campaignId,
      entityId,
    }: {
      campaignId: string;
      entityId: string;
    }) => {
      await api.delete(`/campaigns/${campaignId}/entities/${entityId}`);
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["campaign-entities", vars.campaignId] });
      qc.invalidateQueries({ queryKey: ["campaign", vars.campaignId] });
    },
  });
}

// --- Campaign Statistics ---

export function useCampaignStats(campaignId: string | undefined) {
  return useQuery({
    queryKey: ["campaign-stats", campaignId],
    queryFn: async () => {
      const { data } = await api.get<CampaignStats>(
        `/campaigns/${campaignId}/stats`
      );
      return data;
    },
    enabled: !!campaignId,
  });
}

// --- Campaign Countries ---

export function useCampaignCountries(campaignId: string | undefined) {
  return useQuery({
    queryKey: ["campaign-countries", campaignId],
    queryFn: async () => {
      const { data } = await api.get<CampaignCountryResponse[]>(
        `/campaigns/${campaignId}/countries`
      );
      return data;
    },
    enabled: !!campaignId,
  });
}

export function useCampaignCountrySuggestions(campaignId: string | undefined) {
  return useQuery({
    queryKey: ["campaign-country-suggestions", campaignId],
    queryFn: async () => {
      const { data } = await api.get<CampaignCountrySuggestion[]>(
        `/campaigns/${campaignId}/countries/suggested`
      );
      return data;
    },
    enabled: !!campaignId,
  });
}

export function useAddCampaignCountry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      campaignId,
      countryId,
      role,
    }: {
      campaignId: string;
      countryId: string;
      role: string;
    }) => {
      const { data } = await api.post(`/campaigns/${campaignId}/countries`, {
        country_id: countryId,
        role,
      });
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["campaign-countries", vars.campaignId] });
      qc.invalidateQueries({ queryKey: ["campaign-country-suggestions", vars.campaignId] });
    },
  });
}

export function useRemoveCampaignCountry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      campaignId,
      countryId,
    }: {
      campaignId: string;
      countryId: string;
    }) => {
      await api.delete(`/campaigns/${campaignId}/countries/${countryId}`);
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["campaign-countries", vars.campaignId] });
      qc.invalidateQueries({ queryKey: ["campaign-country-suggestions", vars.campaignId] });
    },
  });
}

// --- Auto-Detect Campaigns ---

/** A story a candidate was seeded from. */
export interface CampaignCandidateThread {
  slug: string;
  title: string;
  entry_count: number;
  first_seen: string | null;
  last_seen: string | null;
}

export interface CampaignCandidate {
  suggested_name: string;
  pivot_entity: { type: string; id: string; name: string };
  /** Entries the candidate would seed the campaign with. */
  entry_count: number;
  entry_ids: string[];
  sample_entries: Array<{ id: string; title: string; published_at: string | null }>;
  /** "story_threads" when the candidate came from clustered coverage. */
  evidence?: "story_threads" | "entity_volume";
  thread_count?: number;
  span_days?: number;
  /** Every entry mentioning the entity — usually far wider than the seed. */
  wider_entry_count?: number;
  threads?: CampaignCandidateThread[];
}

export function useAutoDetectCampaigns() {
  return useMutation({
    mutationFn: async (params?: { min_entries?: number; days?: number; limit?: number }) => {
      const { data } = await api.post("/campaigns/auto-detect", null, { params, timeout: 60000 });
      return data as CampaignCandidate[];
    },
  });
}

// --- Campaign Sources (entities and stories a campaign follows) ---

export function useCampaignSources(campaignId: string | undefined) {
  return useQuery({
    queryKey: ["campaign-sources", campaignId],
    queryFn: async () => {
      const { data } = await api.get<CampaignSource[]>(`/campaigns/${campaignId}/sources`);
      return data;
    },
    enabled: !!campaignId,
  });
}

export function useSuggestedCampaignSources(campaignId: string | undefined) {
  return useQuery({
    queryKey: ["campaign-sources-suggested", campaignId],
    queryFn: async () => {
      const { data } = await api.get<CampaignSourceSuggestion[]>(
        `/campaigns/${campaignId}/sources/suggested`
      );
      return data;
    },
    enabled: !!campaignId,
  });
}

/** Everything a source touches: the campaign's articles, its rail, its suggestions. */
function invalidateCampaignIntake(qc: ReturnType<typeof useQueryClient>, campaignId: string) {
  qc.invalidateQueries({ queryKey: ["campaign-sources", campaignId] });
  qc.invalidateQueries({ queryKey: ["campaign-sources-suggested", campaignId] });
  qc.invalidateQueries({ queryKey: ["pivot", "campaign", campaignId] });
  qc.invalidateQueries({ queryKey: ["entity-timeline", "campaign", campaignId] });
  qc.invalidateQueries({ queryKey: ["campaign-stats", campaignId] });
  qc.invalidateQueries({ queryKey: ["campaign-suggestions", campaignId] });
}

export function useAddCampaignSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      campaignId,
      kind,
      entityType,
      refId,
    }: {
      campaignId: string;
      kind: "entity" | "story";
      entityType?: string | null;
      refId: string;
    }) => {
      const { data } = await api.post<CampaignSource>(`/campaigns/${campaignId}/sources`, {
        kind,
        entity_type: entityType ?? null,
        ref_id: refId,
      });
      return data;
    },
    onSuccess: (_, vars) => invalidateCampaignIntake(qc, vars.campaignId),
  });
}

export function useUpdateCampaignSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      campaignId,
      sourceId,
      autoSync,
    }: {
      campaignId: string;
      sourceId: string;
      autoSync: boolean;
    }) => {
      const { data } = await api.patch<CampaignSource>(
        `/campaigns/${campaignId}/sources/${sourceId}`,
        { auto_sync: autoSync }
      );
      return data;
    },
    onSuccess: (_, vars) => invalidateCampaignIntake(qc, vars.campaignId),
  });
}

export function useSyncCampaignSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ campaignId, sourceId }: { campaignId: string; sourceId: string }) => {
      const { data } = await api.post<{ entries_added: number; total_entries_added: number }>(
        `/campaigns/${campaignId}/sources/${sourceId}/sync`
      );
      return data;
    },
    onSuccess: (_, vars) => invalidateCampaignIntake(qc, vars.campaignId),
  });
}

export function useRemoveCampaignSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ campaignId, sourceId }: { campaignId: string; sourceId: string }) => {
      await api.delete(`/campaigns/${campaignId}/sources/${sourceId}`);
    },
    onSuccess: (_, vars) => invalidateCampaignIntake(qc, vars.campaignId),
  });
}
