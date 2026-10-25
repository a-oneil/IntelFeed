import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import api from "@/api/client";

export type ExtractionStatus = "linked" | "review" | "orphan" | "dupe" | "stale";
export type ExtractionType = "threat_actor" | "malware" | "tool" | "cve" | "ttp" | "observable";

export interface ExtractionEntity {
  id: string;
  entity_type: ExtractionType;
  name: string;
  aliases: string[];
  article_count: number;
  created_confidence: string | null;
  needs_review: boolean;
  created_from_entry_id: string | null;
  source_entry_title: string | null;
  first_seen_at: string;
  status: ExtractionStatus;
  duplicate_of: string | null;
  /** The sibling it most resembles — the merge target for one-click Merge. */
  duplicate_of_id: string | null;
}

export interface ExtractionListResponse {
  items: ExtractionEntity[];
  total: number;
  limit: number;
  offset: number;
}

export interface ExtractionStats {
  total_created: number;
  created_window: number;
  created_prev_window: number;
  needs_review: number;
  orphaned: number;
  likely_duplicates: number;
  auto_confirmed: number;
  by_type: Partial<Record<ExtractionType, number>>;
  window: string;
}

export interface ExtractionParams {
  types?: ExtractionType[];
  status?: "all" | ExtractionStatus;
  window?: "24h" | "7d" | "30d" | "all";
  q?: string;
  source_entry_id?: string;
  sort_by?: "created" | "entries" | "confidence" | "name";
  sort_order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

// entity_type → REST slug used by the per-type delete/update endpoints.
// Observables are absent on purpose: a ledger row has no /entities/… resource
// (it is removed by tombstone, see useDeleteExtractionEntity).
const DELETE_SLUGS: Partial<Record<ExtractionType, string>> = {
  threat_actor: "threat-actors",
  malware: "malware",
  tool: "tools",
  cve: "cves",
  ttp: "ttps",
};


// Only these types support the /entities/{type}/merge endpoint.
export const MERGEABLE_TYPES = new Set<ExtractionType>(["threat_actor", "malware", "tool"]);

// Types whose canonical name is editable and that carry a free-text alias list.
// CVE/TTP identities are their external ids (CVE-…, T…) and cannot be renamed
// or aliased from here.
export const NAMEABLE_TYPES = new Set<ExtractionType>(["threat_actor", "malware", "tool"]);
export const ALIAS_TYPES = new Set<ExtractionType>(["threat_actor", "malware", "tool"]);

// Types /entities/convert can reclassify *from*. Observables aren't entities
// with a name to re-home — an IP is an IP — so their rows get no convert menu.
export const CONVERTIBLE_TYPES = new Set<ExtractionType>(["threat_actor", "malware", "tool", "cve", "ttp"]);

// Every type /entities/convert understands, for the per-row "Convert to…" menu.
// cve/ttp need an external identifier when they are the *target*.
export const CONVERT_TARGETS: { key: string; label: string; needsIdentifier?: "cve" | "ttp" }[] = [
  { key: "threat_actor", label: "Threat Actor" },
  { key: "malware", label: "Malware Family" },
  { key: "tool", label: "Tool" },
  { key: "vendor", label: "Vendor" },
  { key: "product", label: "Product" },
  { key: "country", label: "Country" },
  { key: "cve", label: "CVE", needsIdentifier: "cve" },
  { key: "ttp", label: "TTP (ATT&CK technique)", needsIdentifier: "ttp" },
];

export const TYPE_LABELS: Record<ExtractionType, string> = {
  threat_actor: "Actor",
  malware: "Malware",
  tool: "Tool",
  cve: "CVE",
  ttp: "TTP",
  observable: "Observable",
};

export function useExtractionStats(window: ExtractionParams["window"] = "7d") {
  return useQuery({
    queryKey: ["extraction", "stats", window],
    queryFn: async () => {
      const { data } = await api.get<ExtractionStats>("/engine/extraction/stats", { params: { window } });
      return data;
    },
  });
}

export function useExtractionEntities(params: ExtractionParams, enabled = true) {
  const query = {
    ...params,
    types: params.types?.length ? params.types.join(",") : undefined,
  };
  return useQuery({
    queryKey: ["extraction", "entities", query],
    queryFn: async () => {
      const { data } = await api.get<ExtractionListResponse>("/engine/extraction/entities", { params: query });
      return data;
    },
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useInvalidateExtraction() {
  const qc = useQueryClient();
  return () => {
    qc.invalidateQueries({ queryKey: ["extraction"] });
    // Observable rows are shared with the ledger browser, which keys its own
    // queries — a deny/confirm here has to refresh both surfaces.
    qc.invalidateQueries({ queryKey: ["observables"] });
  };
}

export function useConfirmExtraction() {
  const invalidate = useInvalidateExtraction();
  return useMutation({
    mutationFn: async ({ entityType, ids }: { entityType: ExtractionType; ids: string[] }) => {
      const { data } = await api.post<{ confirmed: number }>("/engine/extraction/confirm", {
        entity_type: entityType,
        ids,
      });
      return data;
    },
    onSuccess: invalidate,
  });
}

/** "These two are different things" — the pair stops counting as a likely duplicate. */
export function useNotDuplicate() {
  const invalidate = useInvalidateExtraction();
  return useMutation({
    mutationFn: async ({ entityType, id, otherId }: { entityType: ExtractionType; id: string; otherId: string }) => {
      await api.post("/engine/extraction/not-duplicate", { entity_type: entityType, id, other_id: otherId });
    },
    onSuccess: invalidate,
  });
}

export function useDeleteExtractionEntity() {
  const invalidate = useInvalidateExtraction();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ entityType, id, entryId }: { entityType: ExtractionType; id: string; entryId?: string }) => {
      // From a per-entry drawer, removing an observable means removing THIS
      // article's sighting — never a global tombstone (that is the ledger's
      // deny action, with its own confirm). The row itself stays.
      if (entityType === "observable") {
        if (!entryId) throw new Error("Removing an observable from a drawer needs its entry id");
        await api.delete(`/entries/${entryId}/observables/${id}`);
        return;
      }
      const slug = DELETE_SLUGS[entityType];
      if (!slug) throw new Error(`No delete endpoint for entity type "${entityType}"`);
      await api.delete(`/entities/${slug}/${id}`);
    },
    onSuccess: (_, vars) => {
      invalidate();
      if (vars.entryId) qc.invalidateQueries({ queryKey: ["entry-observables", vars.entryId] });
    },
  });
}

/** Delete from Review › New entities: drops the entities AND adds their names to
 *  the analyst do-not-recreate denylist, so the one-pass extractor and the
 *  autolinker stop re-minting them. The plain per-entity delete above (used by
 *  the entry drawer) deliberately does not deny.
 *
 *  Observables have no name denylist: `deny` (the default) tombstones the
 *  ledger rows in place; `deny: false` hard-deletes them, leaving the values
 *  free to be captured again. Other types ignore the flag. */
export function useDeleteExtractionEntities() {
  const invalidate = useInvalidateExtraction();
  return useMutation({
    mutationFn: async ({ entityType, ids, deny = true }: { entityType: ExtractionType; ids: string[]; deny?: boolean }) => {
      const { data } = await api.post<{ deleted: number; denied: number }>("/engine/extraction/delete", {
        entity_type: entityType,
        ids,
        deny,
      });
      return data;
    },
    onSuccess: invalidate,
  });
}

export function useMergeExtractionEntities() {
  const invalidate = useInvalidateExtraction();
  return useMutation({
    mutationFn: async ({
      entityType,
      keeperId,
      mergeIds,
    }: {
      entityType: ExtractionType;
      keeperId: string;
      mergeIds: string[];
    }) => {
      const { data } = await api.post(`/entities/${entityType}/merge`, {
        keeper_id: keeperId,
        merge_ids: mergeIds,
      });
      return data;
    },
    onSuccess: invalidate,
  });
}

/** Rename / re-alias an AI-created entity via its per-type PUT endpoint. */
export function useUpdateExtractionEntity() {
  const invalidate = useInvalidateExtraction();
  return useMutation({
    mutationFn: async ({
      entityType,
      id,
      name,
      aliases,
    }: {
      entityType: ExtractionType;
      id: string;
      name?: string;
      aliases?: string[];
    }) => {
      const body: Record<string, unknown> = {};
      if (name !== undefined) body.name = name;
      if (aliases !== undefined) body.aliases = aliases;
      const { data } = await api.put(`/entities/${DELETE_SLUGS[entityType]}/${id}`, body);
      return data;
    },
    onSuccess: invalidate,
  });
}

/** Reclassify an AI-created entity to another type via /entities/convert. */
export function useConvertExtractionEntity() {
  const invalidate = useInvalidateExtraction();
  return useMutation({
    mutationFn: async ({
      id,
      targetType,
      targetIdentifier,
    }: {
      id: string;
      targetType: string;
      targetIdentifier?: string;
    }) => {
      const { data } = await api.post("/entities/convert", {
        entity_id: id,
        target_type: targetType,
        ...(targetIdentifier ? { target_identifier: targetIdentifier } : {}),
      });
      return data;
    },
    onSuccess: invalidate,
  });
}

// --- Do-not-recreate list ---------------------------------------------------

export interface DenylistEntry {
  id: string;
  /** "any" is a wildcard: the name is banned for every entity type. */
  entity_type: ExtractionType | "any";
  display_name: string;
  normalized_name: string;
  reason: string | null;
  source: string;
  created_at: string;
}

export interface DenylistParams {
  q?: string;
  entity_type?: ExtractionType | "any";
  source?: string;
  limit?: number;
  offset?: number;
}

export function useDenylist(params: DenylistParams) {
  return useQuery({
    queryKey: ["extraction", "denylist", params],
    queryFn: async () => {
      const { data } = await api.get<{
        items: DenylistEntry[];
        total: number;
        limit: number;
        offset: number;
      }>("/engine/extraction/denylist", { params });
      return data;
    },
    placeholderData: keepPreviousData,
  });
}

export function useAddDenylistEntry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ entityType, name }: { entityType: ExtractionType | "any"; name: string }) => {
      const { data } = await api.post<DenylistEntry>("/engine/extraction/denylist", {
        entity_type: entityType,
        name,
      });
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["extraction", "denylist"] }),
  });
}

export function useRemoveDenylistEntry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/engine/extraction/denylist/${id}`);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["extraction", "denylist"] }),
  });
}
