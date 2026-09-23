import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import api from "@/api/client";
import type {
  PaginatedResponse,
  ExtractionResponse,
  TTP,
  TTPRelatedTechniques,
  CVE,
  CWEResponse,
  CWEFamilyResponse,
  CVEWeaknessRow,
  CWEVendorRow,
  CWEAffectedVendorRow,
  ThreatActor,
  MalwareFamily,
  Country,
  DetectionRule,
  DetectionRuleListItem,
  Mitigation,
  ObservableCandidateRow,
  ObservableEntryPayload,
  ObservableResponse,
  OffensiveTool,
  Vendor,
  Product,
} from "@/api/types";

export interface ExtractedURL {
  url: string;
  context: string;
}

export function useEntryURLs(entryId: string | undefined) {
  return useQuery({
    queryKey: ["entry-urls", entryId],
    queryFn: async () => {
      const { data } = await api.get<ExtractedURL[]>(`/entries/${entryId}/urls`);
      return data;
    },
    enabled: !!entryId,
  });
}

export function useCreateThreatActor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      name: string;
      aliases?: string[];
      description?: string;
      country?: string;
      motivation?: string;
      entry_id?: string;
      force?: boolean;
    }) => {
      const { data } = await api.post("/entities/threat-actors", body);
      return data as ThreatActor & { id: string };
    },
    onSuccess: (_, vars) => {
      if (vars.entry_id) qc.invalidateQueries({ queryKey: ["entry-actors", vars.entry_id] });
      qc.invalidateQueries({ queryKey: ["threat-actors"] });
    },
  });
}

export function useCreateMalware() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      name: string;
      aliases?: string[];
      description?: string;
      malware_type?: string;
      entry_id?: string;
      force?: boolean;
    }) => {
      const { data } = await api.post("/entities/malware", body);
      return data as MalwareFamily & { id: string };
    },
    onSuccess: (_, vars) => {
      if (vars.entry_id) qc.invalidateQueries({ queryKey: ["entry-malware", vars.entry_id] });
      qc.invalidateQueries({ queryKey: ["malware"] });
    },
  });
}

export function useCreateCVE() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      cve_id: string;
      description?: string;
      severity?: string;
      cvss_score?: number;
      affected_products?: string[];
      exploit_status?: string;
      exploit_availability?: string;
      entry_id?: string;
    }) => {
      const { data } = await api.post("/entities/cves", body);
      return data as CVE & { id: string };
    },
    onSuccess: (_, vars) => {
      if (vars.entry_id) qc.invalidateQueries({ queryKey: ["entry-cves", vars.entry_id] });
      qc.invalidateQueries({ queryKey: ["cves"] });
    },
  });
}

export function useCreateTTP() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      technique_id: string;
      technique_name: string;
      tactic?: string;
      description?: string;
      platforms?: string[];
      data_sources?: string[];
      is_subtechnique?: boolean;
      entry_id?: string;
    }) => {
      const { data } = await api.post("/entities/ttps", body);
      return data as TTP & { id: string };
    },
    onSuccess: (_, vars) => {
      if (vars.entry_id) qc.invalidateQueries({ queryKey: ["entry-ttps", vars.entry_id] });
      qc.invalidateQueries({ queryKey: ["ttps"] });
    },
  });
}

export function useCreateCountry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      name: string;
      iso_code?: string;
      aliases?: string[];
      region?: string;
      description?: string;
      entry_id?: string;
    }) => {
      const { data } = await api.post("/entities/countries", body);
      return data as Country & { id: string };
    },
    onSuccess: (_, vars) => {
      if (vars.entry_id) qc.invalidateQueries({ queryKey: ["entry-countries", vars.entry_id] });
      qc.invalidateQueries({ queryKey: ["countries"] });
    },
  });
}

export function useCreateMitigation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      name: string;
      mitre_id?: string;
      description?: string;
      mitre_url?: string;
      entry_id?: string;
    }) => {
      const { data } = await api.post("/entities/mitigations", body);
      return data as Mitigation & { id: string };
    },
    onSuccess: (_, vars) => {
      if (vars.entry_id) qc.invalidateQueries({ queryKey: ["entry-mitigations", vars.entry_id] });
      qc.invalidateQueries({ queryKey: ["mitigations"] });
    },
  });
}

export function useCreateOffensiveTool() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      name: string;
      aliases?: string[];
      description?: string;
      tool_type?: string;
      github_url?: string;
      entry_id?: string;
      force?: boolean;
    }) => {
      const { data } = await api.post("/entities/tools", body);
      return data as OffensiveTool & { id: string };
    },
    onSuccess: (_, vars) => {
      if (vars.entry_id) qc.invalidateQueries({ queryKey: ["entry-tools", vars.entry_id] });
      qc.invalidateQueries({ queryKey: ["tools"] });
    },
  });
}

// --- TTPs ---

export function useEntryTTPs(entryId: string | undefined) {
  return useQuery({
    queryKey: ["entry-ttps", entryId],
    queryFn: async () => {
      const { data } = await api.get<TTP[]>(`/entries/${entryId}/ttps`);
      return data;
    },
    enabled: !!entryId,
  });
}

export interface KillChainPhase {
  tactic: string | null;
  label: string;
  order: number;
  techniques: { technique_id: string; technique_name: string; tactic: string | null; confidence: string | null }[];
}

/** Entry TTPs ordered as an attack chain (kill-chain phases) — plan item 3.9.4. */
export function useEntryKillChain(entryId: string | undefined) {
  return useQuery({
    queryKey: ["entry-kill-chain", entryId],
    queryFn: async () => {
      const { data } = await api.get<{ phases: KillChainPhase[] }>(`/entries/${entryId}/kill-chain`);
      return data.phases;
    },
    enabled: !!entryId,
  });
}

export interface ArticleMetadata {
  report_type: string | null;
  victim_organizations: string[];
  timeline: { disclosure_date: string | null; compromise_date: string | null; patch_date: string | null };
  patch: { status: string; reference: string | null };
}

/** Report type, victim orgs, timeline anchors, patch availability — plan items 3.9.6–3.9.9. */
export function useEntryArticleMetadata(entryId: string | undefined) {
  return useQuery({
    queryKey: ["entry-article-metadata", entryId],
    queryFn: async () => {
      const { data } = await api.get<ArticleMetadata | null>(`/entries/${entryId}/article-metadata`);
      return data;
    },
    enabled: !!entryId,
  });
}

export function useExtractTTPs() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      entryId,
      useAi = true,
    }: {
      entryId: string;
      useAi?: boolean;
    }) => {
      const { data } = await api.post<ExtractionResponse<TTP>>(
        `/entries/${entryId}/extract-ttps?use_ai=${useAi}`
      );
      return data;
    },
    onSuccess: (_, vars) =>
      qc.invalidateQueries({ queryKey: ["entry-ttps", vars.entryId] }),
  });
}

export function useNavigatorLayer(entryId: string | undefined) {
  return useQuery({
    queryKey: ["navigator-layer", entryId],
    queryFn: async () => {
      const { data } = await api.get(`/entries/${entryId}/ttps/navigator`);
      return data;
    },
    enabled: !!entryId,
  });
}

export function useTTPs(params?: {
  search?: string;
  tactic?: string;
  sort_by?: string;
  sort_order?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["ttps", params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<TTP>>("/ttps", {
        params,
      });
      return data;
    },
  });
}

// --- CVEs ---

export function useEntryCVEs(entryId: string | undefined) {
  return useQuery({
    queryKey: ["entry-cves", entryId],
    queryFn: async () => {
      const { data } = await api.get<CVE[]>(`/entries/${entryId}/cves`);
      return data;
    },
    enabled: !!entryId,
  });
}

export function useExtractCVEs() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      entryId,
      enrich = true,
    }: {
      entryId: string;
      enrich?: boolean;
    }) => {
      const { data } = await api.post<CVE[]>(
        `/entries/${entryId}/extract-cves?enrich=${enrich}`
      );
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["cves"] });
      qc.invalidateQueries({ queryKey: ["entry-cves", vars.entryId] });
    },
  });
}

// Re-export ExtractionResponse for components
export type { ExtractionResponse } from "@/api/types";

export function useCVEs(params?: {
  search?: string;
  severity?: string;
  sort_by?: string;
  sort_order?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["cves", params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<CVE>>("/cves", {
        params,
      });
      return data;
    },
  });
}

export function useCVE(cveId: string | undefined) {
  return useQuery({
    queryKey: ["cve", cveId],
    queryFn: async () => {
      const { data } = await api.get<CVE>(`/cves/${cveId}`);
      return data;
    },
    enabled: !!cveId,
  });
}

export function useTrendingCVEs(limit = 10) {
  return useQuery({
    queryKey: ["cves-trending", limit],
    queryFn: async () => {
      const { data } = await api.get<CVE[]>("/cves/trending", {
        params: { limit },
      });
      return data;
    },
  });
}

// --- Threat Actors ---

export function useEntryThreatActors(entryId: string | undefined) {
  return useQuery({
    queryKey: ["entry-threat-actors", entryId],
    queryFn: async () => {
      const { data } = await api.get<ThreatActor[]>(`/entries/${entryId}/threat-actors`);
      return data;
    },
    enabled: !!entryId,
  });
}

export function useExtractThreatActors() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (entryId: string) => {
      const { data } = await api.post<ExtractionResponse<ThreatActor>>(
        `/entries/${entryId}/extract-threat-actors`
      );
      return data;
    },
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["threat-actors"] }),
  });
}

export function useThreatActors(params?: {
  search?: string;
  sort_by?: string;
  sort_order?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["threat-actors", params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<ThreatActor>>(
        "/threat-actors",
        { params }
      );
      return data;
    },
  });
}

export function useThreatActor(actorId: string | undefined) {
  return useQuery({
    queryKey: ["threat-actor", actorId],
    queryFn: async () => {
      const { data } = await api.get<ThreatActor>(
        `/threat-actors/${actorId}`
      );
      return data;
    },
    enabled: !!actorId,
  });
}

// --- Malware ---

export function useEntryMalware(entryId: string | undefined) {
  return useQuery({
    queryKey: ["entry-malware", entryId],
    queryFn: async () => {
      const { data } = await api.get<MalwareFamily[]>(`/entries/${entryId}/malware`);
      return data;
    },
    enabled: !!entryId,
  });
}

export function useExtractMalware() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (entryId: string) => {
      const { data } = await api.post<ExtractionResponse<MalwareFamily>>(
        `/entries/${entryId}/extract-malware`
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["malware"] });
      qc.invalidateQueries({ queryKey: ["entry-malware"] });
    },
  });
}

export function useMalwareFamilies(params?: {
  search?: string;
  malware_type?: string;
  sort_by?: string;
  sort_order?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["malware", params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<MalwareFamily>>(
        "/malware",
        { params }
      );
      return data;
    },
  });
}

// --- Countries ---

export function useEntryCountries(entryId: string | undefined) {
  return useQuery({
    queryKey: ["entry-countries", entryId],
    queryFn: async () => {
      const { data } = await api.get<Country[]>(`/entries/${entryId}/countries`);
      return data;
    },
    enabled: !!entryId,
  });
}

export function useExtractCountries() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (entryId: string) => {
      const { data } = await api.post<ExtractionResponse<Country>>(
        `/entries/${entryId}/extract-countries`
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["countries"] });
      qc.invalidateQueries({ queryKey: ["entry-countries"] });
    },
  });
}

export function useCountries(params?: {
  search?: string;
  region?: string;
  sort_by?: string;
  sort_order?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["countries", params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<Country>>(
        "/countries",
        { params }
      );
      return data;
    },
  });
}

export function useCountry(countryId: string | undefined) {
  return useQuery({
    queryKey: ["country", countryId],
    queryFn: async () => {
      const { data } = await api.get<Country>(
        `/countries/${countryId}`
      );
      return data;
    },
    enabled: !!countryId,
  });
}

// --- Autolink Entry ---

export function useAutolinkEntry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (entryId: string) => {
      const { data } = await api.post<{ linked: number }>(`/entries/${entryId}/autolink`);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["entry-threat-actors"] });
      qc.invalidateQueries({ queryKey: ["entry-malware"] });
      qc.invalidateQueries({ queryKey: ["entry-countries"] });
qc.invalidateQueries({ queryKey: ["entry-cves"] });
      qc.invalidateQueries({ queryKey: ["entry-ttps"] });
    },
  });
}

// --- Unlink Entity from Entry ---

type EntityType =
  | "ttp"
  | "cve"
  | "cwe"
  | "threat_actor"
  | "malware"
  | "country"
  | "mitigation"
  | "tool"
  | "vendor"
  | "product"
  | "observable";

const ENTITY_URL_SEGMENT: Record<EntityType, string> = {
  ttp: "ttps",
  cve: "cves",
  cwe: "cwes",
  threat_actor: "threat-actors",
  malware: "malware",
  country: "countries",
  mitigation: "mitigations",
  tool: "tools",
  vendor: "vendors",
  product: "products",
  observable: "observables",
};

const ENTITY_QUERY_KEY: Record<EntityType, string> = {
  ttp: "entry-ttps",
  cve: "entry-cves",
  cwe: "entry-cwes",
  threat_actor: "entry-threat-actors",
  malware: "entry-malware",
  country: "entry-countries",
  mitigation: "entry-mitigations",
  tool: "entry-tools",
  vendor: "entry-vendors",
  product: "entry-products",
  observable: "entry-observables",
};

export function useUnlinkEntity() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      entryId,
      entityId,
      entityType,
    }: {
      entryId: string;
      entityId: string;
      entityType: EntityType;
    }) => {
      const segment = ENTITY_URL_SEGMENT[entityType];
      await api.delete(`/entries/${entryId}/${segment}/${entityId}`);
    },
    onSuccess: (_, vars) => {
      const queryKey = ENTITY_QUERY_KEY[vars.entityType];
      qc.invalidateQueries({ queryKey: [queryKey, vars.entryId] });
      // Also invalidate global entity lists and pivot (profile pages)
      const globalKey = ENTITY_URL_SEGMENT[vars.entityType];
      qc.invalidateQueries({ queryKey: [globalKey] });
      qc.invalidateQueries({ queryKey: ["pivot", vars.entityType, vars.entityId] });
      qc.invalidateQueries({ queryKey: ["entity-timeline", vars.entityType, vars.entityId] });
      // Invalidate graph views so they rebuild after unlink
      qc.invalidateQueries({ queryKey: ["entity-graph", vars.entityType, vars.entityId] });
      qc.invalidateQueries({ queryKey: ["entry-graph", vars.entryId] });
    },
  });
}

export function useLinkEntity() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      entryId,
      entityId,
      entityType,
      selectedText,
    }: {
      entryId: string;
      entityId: string;
      entityType: EntityType;
      selectedText?: string;
    }) => {
      const { data } = await api.post(`/entries/${entryId}/link-entity`, {
        entity_type: entityType,
        entity_id: entityId,
        selected_text: selectedText,
      });
      return data;
    },
    onSuccess: (_, vars) => {
      const queryKey = ENTITY_QUERY_KEY[vars.entityType];
      qc.invalidateQueries({ queryKey: [queryKey, vars.entryId] });
      const globalKey = ENTITY_URL_SEGMENT[vars.entityType];
      qc.invalidateQueries({ queryKey: [globalKey] });
      qc.invalidateQueries({ queryKey: ["pivot", vars.entityType, vars.entityId] });
      qc.invalidateQueries({ queryKey: ["entity-timeline", vars.entityType, vars.entityId] });
      qc.invalidateQueries({ queryKey: ["entity-graph", vars.entityType, vars.entityId] });
      qc.invalidateQueries({ queryKey: ["entry-graph", vars.entryId] });
    },
  });
}

// --- Detection Rules ---

export function useGenerateDetectionRules() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      entryId,
      ruleTypes,
    }: {
      entryId: string;
      ruleTypes: string[];
    }) => {
      const { data } = await api.post<DetectionRule[]>(
        `/entries/${entryId}/generate-rules`,
        { rule_types: ruleTypes }
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["detection-rules"] });
    },
  });
}

/** Entity-scoped rule generation — the profile Detection tab's "Generate rule"
 * CTA. The backend builds context from the entity + its recent linked articles. */
export function useGenerateEntityRules() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      entityType,
      entityId,
      ruleTypes,
    }: {
      entityType: EntityType;
      entityId: string;
      ruleTypes: string[];
    }) => {
      const { data } = await api.post<DetectionRule[]>(
        `/intelligence/entities/${entityType}/${entityId}/generate-rules`,
        { rule_types: ruleTypes }
      );
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["detection-rules"] });
      qc.invalidateQueries({ queryKey: ["pivot", vars.entityType, vars.entityId] });
      qc.invalidateQueries({ queryKey: ["entity-timeline", vars.entityType, vars.entityId] });
      qc.invalidateQueries({ queryKey: ["technique-coverage"] });
    },
  });
}

export function useDetectionRules(params?: {
  rule_type?: string;
  entry_id?: string;
  is_draft?: boolean;
  search?: string;
  severity?: string;
  sort_by?: string;
  sort_order?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["detection-rules", params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<DetectionRuleListItem>>(
        "/detection-rules",
        { params }
      );
      return data;
    },
  });
}

export function useDetectionRule(ruleId: string | undefined) {
  return useQuery({
    queryKey: ["detection-rule", ruleId],
    queryFn: async () => {
      const { data } = await api.get<DetectionRule>(
        `/detection-rules/${ruleId}`
      );
      return data;
    },
    enabled: !!ruleId,
  });
}

export function useUpdateDetectionRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      id,
      ...body
    }: {
      id: string;
      title?: string;
      description?: string;
      rule_content?: string;
      rule_type?: string;
      severity?: string;
      tags?: string[];
      is_draft?: boolean;
      log_sources?: Record<string, unknown> | null;
      mitre_tactics?: string[];
      data_sources?: string[];
      source_ttps?: string[];
      notes?: string;
      source_entries?: string[];
      source_actors?: string[];
      source_campaigns?: string[];
      change_description?: string;
      metadata?: Record<string, unknown>;
    }) => {
      const { data } = await api.put<DetectionRule>(
        `/detection-rules/${id}`,
        body
      );
      return data;
    },
    onSuccess: (data, vars) => {
      qc.setQueryData(["detection-rule", vars.id], data);
      qc.invalidateQueries({ queryKey: ["detection-rules"] });
      qc.invalidateQueries({ queryKey: ["detection-rule-versions", vars.id] });
    },
  });
}

export function useDeleteDetectionRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/detection-rules/${id}`);
    },
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["detection-rules"] }),
  });
}

// --- Bulk Extraction ---

export interface BulkExtractRequest {
  entry_ids?: string[];
  feed_id?: string;
  category_id?: string;
  tag?: string;
  extract_types?: string[];
  use_ai?: boolean;
  limit?: number;
}

export function useBulkExtract() {
  return useMutation({
    mutationFn: async (request: BulkExtractRequest) => {
      const { data } = await api.post<{ task_id: string; entry_count: number }>(
        "/intelligence/bulk-extract",
        request
      );
      return data;
    },
  });
}

export interface BulkTranslateRequest {
  entry_ids?: string[];
  feed_id?: string;
  category_id?: string;
  tag?: string;
  target_language?: string;
  limit?: number;
}

export function useBulkTranslate() {
  return useMutation({
    mutationFn: async (request: BulkTranslateRequest) => {
      const { data } = await api.post<{ entry_count: number; target_language: string }>(
        "/intelligence/bulk-translate",
        request
      );
      return data;
    },
  });
}

// --- Mitigations ---

export function useEntryMitigations(entryId: string | undefined) {
  return useQuery({
    queryKey: ["entry-mitigations", entryId],
    queryFn: async () => {
      const { data } = await api.get<Mitigation[]>(`/entries/${entryId}/mitigations`);
      return data;
    },
    enabled: !!entryId,
  });
}

export function useEntryCWEs(entryId: string | undefined) {
  return useQuery({
    queryKey: ["entry-cwes", entryId],
    queryFn: async () => {
      const { data } = await api.get<CWEResponse[]>(`/entries/${entryId}/cwes`);
      return data;
    },
    enabled: !!entryId,
  });
}

export function useEntryObservables(entryId: string | undefined) {
  return useQuery({
    // Key matches ENTITY_QUERY_KEY["observable"] so useUnlinkEntity invalidates it.
    queryKey: ["entry-observables", entryId],
    queryFn: async () => {
      const { data } = await api.get<ObservableEntryPayload>(`/entries/${entryId}/observables`);
      return data;
    },
    enabled: !!entryId,
  });
}

export function useObservable(observableId: string | undefined) {
  return useQuery({
    queryKey: ["observable", observableId],
    queryFn: async () => {
      const { data } = await api.get<ObservableResponse>(`/observables/${observableId}`);
      return data;
    },
    enabled: !!observableId,
  });
}

export function useObservableCandidates(enabled: boolean, kind?: string) {
  return useQuery({
    queryKey: ["observable-candidates", kind ?? "all"],
    queryFn: async () => {
      const { data } = await api.get<ObservableCandidateRow[]>("/observables/candidates", {
        params: kind && kind !== "all" ? { kind } : undefined,
      });
      return data;
    },
    enabled,
  });
}

export function usePromoteObservable() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      entryId,
      kind,
      value,
      surfaceForm,
    }: {
      entryId: string;
      kind: string;
      value: string;
      surfaceForm?: string;
    }) => {
      const { data } = await api.post<ObservableResponse>(`/entries/${entryId}/observables/promote`, {
        kind,
        value,
        surface_form: surfaceForm,
      });
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["entry-observables", vars.entryId] });
      qc.invalidateQueries({ queryKey: ["observables"] });
      qc.invalidateQueries({ queryKey: ["observable-candidates"] });
      // The Engine extraction tab lists ledger rows too.
      qc.invalidateQueries({ queryKey: ["extraction"] });
    },
    onError: (err) => {
      const detail = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
      toast.error(detail ?? "Promote failed");
    },
  });
}

/** Drop one candidate from one entry's nomination list — entry-local, any
 * analyst; never-capture (admin) is the global rung. */
export function useDismissObservableCandidate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ entryId, kind, value }: { entryId: string; kind: string; value: string }) => {
      await api.post(`/entries/${entryId}/observables/dismiss`, { kind, value });
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["entry-observables", vars.entryId] });
      qc.invalidateQueries({ queryKey: ["observable-candidates"] });
    },
    onError: () => toast.error("Dismiss failed"),
  });
}

export function useUpdateObservable() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      observableId,
      ...payload
    }: {
      observableId: string;
      label?: string;
      role?: string;
      description?: string;
      confidence_pinned?: boolean;
    }) => {
      const { data } = await api.patch<ObservableResponse>(`/observables/${observableId}`, payload);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["observable", vars.observableId] });
      qc.invalidateQueries({ queryKey: ["observables"] });
    },
  });
}

export function useDenyObservable() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (observableId: string) => {
      const { data } = await api.post<ObservableResponse>(`/observables/${observableId}/deny`);
      return data;
    },
    onSuccess: (_, observableId) => {
      qc.invalidateQueries({ queryKey: ["observable", observableId] });
      qc.invalidateQueries({ queryKey: ["observables"] });
      // A tombstoned value must leave the reader panel and inline highlights.
      qc.invalidateQueries({ queryKey: ["entry-observables"] });
      qc.invalidateQueries({ queryKey: ["extraction"] });
    },
  });
}

/** Hard-delete a ledger row: the sightings and relationships go with it and no
 *  tombstone is left, so a future capture door may create the value again.
 *  Use {@link useDenyObservable} when the value must stay out for good. */
export function useDeleteObservable() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (observableId: string) => {
      await api.delete(`/observables/${observableId}`);
      return observableId;
    },
    onSuccess: (observableId) => {
      qc.removeQueries({ queryKey: ["observable", observableId] });
      qc.invalidateQueries({ queryKey: ["observables"] });
      qc.invalidateQueries({ queryKey: ["entry-observables"] });
      qc.invalidateQueries({ queryKey: ["extraction"] });
    },
  });
}

export function useNeverCaptureObservable() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ kind, value }: { kind: string; value: string }) => {
      const { data } = await api.post<ObservableResponse>("/observables/never-capture", { kind, value });
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["observable-candidates"] });
      qc.invalidateQueries({ queryKey: ["observables"] });
      qc.invalidateQueries({ queryKey: ["entry-observables"] });
      qc.invalidateQueries({ queryKey: ["extraction"] });
    },
  });
}

export function useExtractMitigations() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ entryId, useAi = true }: { entryId: string; useAi?: boolean }) => {
      const { data } = await api.post<ExtractionResponse<Mitigation>>(
        `/entries/${entryId}/extract-mitigations?use_ai=${useAi}`
      );
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["entry-mitigations", vars.entryId] });
      qc.invalidateQueries({ queryKey: ["mitigations"] });
    },
  });
}

export function useMitigations(params?: {
  search?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["mitigations", params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<Mitigation>>("/mitigations", { params });
      return data;
    },
  });
}

export function useTTPMitigations(ttpId: string | undefined) {
  return useQuery({
    queryKey: ["ttp-mitigations", ttpId],
    queryFn: async () => {
      const { data } = await api.get<Mitigation[]>(`/ttps/${ttpId}/mitigations`);
      return data;
    },
    enabled: !!ttpId,
  });
}

export function useTTPRelatedTechniques(ttpId: string | undefined) {
  return useQuery({
    queryKey: ["ttp-related-techniques", ttpId],
    queryFn: async () => {
      const { data } = await api.get<TTPRelatedTechniques>(`/ttps/${ttpId}/related-techniques`);
      return data;
    },
    enabled: !!ttpId,
  });
}

// --- CWE (Weaknesses) ---

/** One weakness, by UUID or catalog id ("CWE-416"). */
export function useCWE(cweId: string | undefined) {
  return useQuery({
    queryKey: ["cwe", cweId],
    queryFn: async () => {
      const { data } = await api.get<CWEResponse>(`/cwes/${cweId}`);
      return data;
    },
    enabled: !!cweId,
  });
}

/** Where a weakness sits on the abstraction ladder — lineage, children, siblings. */
export function useCWEFamily(cweId: string | undefined) {
  return useQuery({
    queryKey: ["cwe-family", cweId],
    queryFn: async () => {
      const { data } = await api.get<CWEFamilyResponse>(`/cwes/${cweId}/family`);
      return data;
    },
    enabled: !!cweId,
  });
}

/** Vendors shipping the most CVEs with this weakness. */
export function useCWEVendors(cweId: string | undefined, limit = 6) {
  return useQuery({
    queryKey: ["cwe-vendors", cweId, limit],
    queryFn: async () => {
      const { data } = await api.get<CWEAffectedVendorRow[]>(`/cwes/${cweId}/vendors`, { params: { limit } });
      return data;
    },
    enabled: !!cweId,
  });
}

/** Every NVD weakness assignment on a CVE, unresolved sentinels included. */
export function useCVEWeaknesses(cveId: string | undefined) {
  return useQuery({
    queryKey: ["cve-weaknesses", cveId],
    queryFn: async () => {
      const { data } = await api.get<CVEWeaknessRow[]>(`/cves/${cveId}/weaknesses`);
      return data;
    },
    enabled: !!cveId,
  });
}

/** A vendor's or product's weakness mix, derived through cve_affected. */
export function useEntityWeaknessProfile(
  kind: "vendor" | "product" | undefined,
  entityId: string | undefined,
  limit = 6,
) {
  return useQuery({
    queryKey: ["entity-weaknesses", kind, entityId, limit],
    queryFn: async () => {
      const { data } = await api.get<CWEVendorRow[]>(`/${kind}s/${entityId}/weaknesses`, {
        params: { limit },
      });
      return data;
    },
    enabled: !!kind && !!entityId,
  });
}

// --- Offensive Tools ---

export function useEntryTools(entryId: string | undefined) {
  return useQuery({
    queryKey: ["entry-tools", entryId],
    queryFn: async () => {
      const { data } = await api.get<OffensiveTool[]>(`/entries/${entryId}/tools`);
      return data;
    },
    enabled: !!entryId,
  });
}

export function useExtractTools() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (entryId: string) => {
      const { data } = await api.post<ExtractionResponse<OffensiveTool>>(
        `/entries/${entryId}/extract-tools`
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tools"] });
      qc.invalidateQueries({ queryKey: ["entry-tools"] });
    },
  });
}

export function useOffensiveTools(params?: {
  search?: string;
  tool_type?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["tools", params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<OffensiveTool>>("/tools", { params });
      return data;
    },
  });
}

// --- Vendors ---

export function useCreateVendor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      name: string;
      aliases?: string[];
      description?: string;
      website?: string;
      vendor_type?: string;
      entry_id?: string;
      force?: boolean;
    }) => {
      const { data } = await api.post("/entities/vendors", body);
      return data as Vendor & { id: string };
    },
    onSuccess: (_, vars) => {
      if (vars.entry_id) qc.invalidateQueries({ queryKey: ["entry-vendors", vars.entry_id] });
      qc.invalidateQueries({ queryKey: ["vendors"] });
    },
  });
}

export function useEntryVendors(entryId: string | undefined) {
  return useQuery({
    queryKey: ["entry-vendors", entryId],
    queryFn: async () => {
      const { data } = await api.get<Vendor[]>(`/entries/${entryId}/vendors`);
      return data;
    },
    enabled: !!entryId,
  });
}

export function useVendors(params?: {
  search?: string;
  vendor_type?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["vendors", params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<Vendor>>("/vendors", { params });
      return data;
    },
  });
}

export function useVendor(vendorId: string | undefined) {
  return useQuery({
    queryKey: ["vendor", vendorId],
    queryFn: async () => {
      const { data } = await api.get<Vendor>(`/vendors/${vendorId}`);
      return data;
    },
    enabled: !!vendorId,
  });
}

export function useVendorProducts(vendorId: string | undefined) {
  return useQuery({
    queryKey: ["vendor-products", vendorId],
    queryFn: async () => {
      const { data } = await api.get<Product[]>(`/vendors/${vendorId}/products`);
      return data;
    },
    enabled: !!vendorId,
  });
}

// --- Products ---

export function useCreateProduct() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      name: string;
      aliases?: string[];
      description?: string;
      product_type?: string;
      website?: string;
      vendor_id?: string;
      entry_id?: string;
      force?: boolean;
    }) => {
      const { data } = await api.post("/entities/products", body);
      return data as Product & { id: string };
    },
    onSuccess: (_, vars) => {
      if (vars.entry_id) qc.invalidateQueries({ queryKey: ["entry-products", vars.entry_id] });
      qc.invalidateQueries({ queryKey: ["products"] });
    },
  });
}

export function useEntryProducts(entryId: string | undefined) {
  return useQuery({
    queryKey: ["entry-products", entryId],
    queryFn: async () => {
      const { data } = await api.get<Product[]>(`/entries/${entryId}/products`);
      return data;
    },
    enabled: !!entryId,
  });
}

export function useProducts(params?: {
  search?: string;
  product_type?: string;
  vendor_id?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["products", params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<Product>>("/products", { params });
      return data;
    },
  });
}

export function useProduct(productId: string | undefined) {
  return useQuery({
    queryKey: ["product", productId],
    queryFn: async () => {
      const { data } = await api.get<Product>(`/products/${productId}`);
      return data;
    },
    enabled: !!productId,
  });
}

// --- Resolve entity names ---

export function useEntityNames(entityIds: Record<string, string[]>) {
  const hasIds = Object.values(entityIds).some((ids) => ids.length > 0);
  return useQuery({
    queryKey: ["entity-names", entityIds],
    queryFn: async () => {
      const { data } = await api.post<Record<string, Array<{ id: string; name: string }>>>(
        "/intelligence/resolve-names",
        entityIds
      );
      return data;
    },
    enabled: hasIds,
    staleTime: 60_000,
  });
}

