import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";

interface DateRangeParams {
  date_from?: string;
  date_to?: string;
  limit?: number;
}

export interface TrendingVendorItem {
  id: string;
  name: string;
  vendor_type: string | null;
  entry_count: number;
}

export interface TrendingProductItem {
  id: string;
  name: string;
  product_type: string | null;
  vendor_name: string | null;
  entry_count: number;
}

export interface TargetedCountryItem {
  id: string;
  name: string;
  iso_code: string | null;
  region: string | null;
  entry_count: number;
}

export interface ActiveCampaignItem {
  id: string;
  name: string;
  status: string;
  tlp_marking: string;
  entry_count: number;
  updated_at: string | null;
}

export function useTrendingVendors(params?: DateRangeParams) {
  return useQuery({
    queryKey: ["widgets", "trending-vendors", params],
    queryFn: async () => {
      const res = await api.get<TrendingVendorItem[]>("/widgets/trending-vendors", { params });
      return res.data;
    },
  });
}

export function useTrendingProducts(params?: DateRangeParams) {
  return useQuery({
    queryKey: ["widgets", "trending-products", params],
    queryFn: async () => {
      const res = await api.get<TrendingProductItem[]>("/widgets/trending-products", { params });
      return res.data;
    },
  });
}

export function useTargetedCountries(params?: DateRangeParams) {
  return useQuery({
    queryKey: ["widgets", "targeted-countries", params],
    queryFn: async () => {
      const res = await api.get<TargetedCountryItem[]>("/widgets/targeted-countries", { params });
      return res.data;
    },
  });
}

export function useActiveCampaigns(params?: DateRangeParams) {
  return useQuery({
    queryKey: ["widgets", "active-campaigns", params],
    queryFn: async () => {
      const res = await api.get<ActiveCampaignItem[]>("/widgets/active-campaigns", { params });
      return res.data;
    },
  });
}
