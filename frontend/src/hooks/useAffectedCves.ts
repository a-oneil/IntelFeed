/**
 * Hooks for the authoritative CVE↔vendor/product affects-links (cve_affected).
 * Distinct from co-mention pivot data — these are NVD CPE-derived links.
 */
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import api from "@/api/client";

export interface AffectedProductRef {
  id: string | null;
  name: string | null;
  cpe_product: string;
  version_start: string | null;
  version_end: string | null;
}

/** Entity kinds with an authoritative CVE list. vendor/product come from
 * cve_affected (NVD CPE); cwe comes from cve_weaknesses (NVD weakness block). */
export type AffectedKind = "vendor" | "product" | "cwe";

export interface AffectedCVEItem {
  id: string;
  cve_id: string;
  severity: string | null;
  cvss_score: string | number | null;
  epss_score: number | null;
  is_kev: boolean;
  exploited: boolean;
  description: string | null;
  published_at: string | null;
  vendor_level: boolean;
  /** cwe mode only: which weakness in the subtree actually matched. */
  matched_cwe: string | null;
  matched_cwe_name: string | null;
  products: AffectedProductRef[];
}

export interface AffectedCVECounts {
  severity: Record<string, number>;
  kev: number;
  exploited: number;
}

export interface AffectedByProduct {
  id: string;
  name: string;
  count: number;
}

export interface AffectedCVEsResponse {
  items: AffectedCVEItem[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
  counts: AffectedCVECounts;
  by_product: AffectedByProduct[];
  vendor_level_count: number;
  /** cwe mode: catalog rows the query spanned. 1 means this weakness is a leaf. */
  subtree_size?: number | null;
}

export type AffectedSort = "cvss" | "epss" | "recent";

export interface AffectedCveFilters {
  severity?: string[];
  kev?: boolean;
  exploited?: boolean;
  /** vendor rollup only — restrict to one product */
  productId?: string;
  /** vendor rollup only — CVEs with no resolved product under the vendor */
  vendorLevel?: boolean;
  /** cwe only — false narrows to CVEs tagged with this exact weakness */
  includeDescendants?: boolean;
  sort?: AffectedSort;
}

const PAGE_SIZE = 50;

function buildParams(filters: AffectedCveFilters, offset: number): Record<string, string | number | boolean> {
  const params: Record<string, string | number | boolean> = {
    limit: PAGE_SIZE,
    offset,
    sort: filters.sort ?? "cvss",
  };
  if (filters.severity?.length) params.severity = filters.severity.join(",");
  if (filters.kev) params.kev = true;
  if (filters.exploited) params.exploited = true;
  if (filters.productId) params.product_id = filters.productId;
  if (filters.vendorLevel) params.vendor_level = true;
  if (filters.includeDescendants === false) params.include_descendants = false;
  return params;
}

export function useAffectedCves(
  kind: AffectedKind,
  entityId: string | undefined,
  filters: AffectedCveFilters,
) {
  return useInfiniteQuery({
    queryKey: ["affected-cves", kind, entityId, filters],
    queryFn: async ({ pageParam }) => {
      const { data } = await api.get<AffectedCVEsResponse>(`/${kind}s/${entityId}/affected-cves`, {
        params: buildParams(filters, pageParam),
      });
      return data;
    },
    initialPageParam: 0,
    getNextPageParam: (lastPage) => (lastPage.has_more ? lastPage.offset + lastPage.limit : undefined),
    enabled: !!entityId,
  });
}

/** Lightweight unfiltered total — feeds the Vulnerabilities tab count badge. */
export function useAffectedCveCount(kind: AffectedKind | undefined, entityId: string | undefined) {
  return useQuery({
    queryKey: ["affected-cves-count", kind, entityId],
    queryFn: async () => {
      const { data } = await api.get<AffectedCVEsResponse>(`/${kind}s/${entityId}/affected-cves`, {
        params: { limit: 1, offset: 0 },
      });
      return data;
    },
    enabled: !!kind && !!entityId,
  });
}

export interface CVEAffectedEntityRow {
  cpe_vendor: string;
  cpe_product: string;
  vendor_id: string | null;
  vendor_name: string | null;
  product_id: string | null;
  product_name: string | null;
  version_start: string | null;
  version_end: string | null;
}

/** Parsed CPE pairs for a CVE with entity resolution — the profile's Affected panel. */
export function useCveAffectedRows(cveId: string | undefined) {
  return useQuery({
    queryKey: ["cve-affected-rows", cveId],
    queryFn: async () => {
      const { data } = await api.get<CVEAffectedEntityRow[]>(`/cves/${cveId}/affected`);
      return data;
    },
    enabled: !!cveId,
  });
}

/** "2013 SP1 → 2019", "≥ 10.0", "≤ 16.0.5439", or null. */
export function formatVersionRange(start: string | null, end: string | null): string | null {
  if (start && end) return `${start} → ${end}`;
  if (start) return `≥ ${start}`;
  if (end) return `≤ ${end}`;
  return null;
}
