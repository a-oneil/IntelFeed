import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type {
  PaginatedResponse,
  IntelReport,
  IntelReportCreate,
  IntelReportUpdate,
  IntelReportVersion,
  IntelReportFullGenerateRequest,
  IntelReportFullGenerateResponse,
  ReportTemplate,
  SectionGenerateResponse,
  ExposureGenerateRequest,
} from "@/api/types";

export function useIntelReports(params?: {
  status?: string;
  template_type?: string;
  sort_by?: string;
  sort_order?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["intel-reports", params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<IntelReport>>(
        "/intel-reports",
        { params }
      );
      return data;
    },
  });
}

export function useIntelReport(id: string | undefined) {
  return useQuery({
    queryKey: ["intel-report", id],
    queryFn: async () => {
      const { data } = await api.get<IntelReport>(`/intel-reports/${id}`);
      return data;
    },
    enabled: !!id,
  });
}

export function useCreateIntelReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: IntelReportCreate) => {
      const { data } = await api.post<IntelReport>("/intel-reports", body);
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intel-reports"] }),
  });
}

export function useUpdateIntelReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: IntelReportUpdate & { id: string }) => {
      const { data } = await api.put<IntelReport>(`/intel-reports/${id}`, body);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["intel-reports"] });
      qc.invalidateQueries({ queryKey: ["intel-report", vars.id] });
    },
  });
}

export function useDeleteIntelReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/intel-reports/${id}`);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intel-reports"] }),
  });
}

export function useIntelReportVersions(id: string | undefined) {
  return useQuery({
    queryKey: ["intel-report-versions", id],
    queryFn: async () => {
      const { data } = await api.get<IntelReportVersion[]>(
        `/intel-reports/${id}/versions`
      );
      return data;
    },
    enabled: !!id,
  });
}

export function useGenerateIntelReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      template_type: string;
      entry_ids?: string[];
      entity_ids?: Record<string, string[]>;
      title?: string;
    }) => {
      const { data } = await api.post<IntelReport>(
        "/intel-reports/generate",
        body
      );
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intel-reports"] }),
  });
}

export function usePublishIntelReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await api.post<IntelReport>(`/intel-reports/${id}/publish`);
      return data;
    },
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ["intel-reports"] });
      qc.invalidateQueries({ queryKey: ["intel-report", id] });
      qc.invalidateQueries({ queryKey: ["intel-report-versions", id] });
    },
  });
}

export function useArchiveIntelReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await api.post<IntelReport>(`/intel-reports/${id}/archive`);
      return data;
    },
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ["intel-reports"] });
      qc.invalidateQueries({ queryKey: ["intel-report", id] });
    },
  });
}

export function useExportIntelReport() {
  return useMutation({
    mutationFn: async ({ id, format, title }: { id: string; format: string; title?: string }) => {
      const resp = await api.get(`/intel-reports/${id}/export`, {
        params: { format },
        responseType: "blob",
      });
      const url = URL.createObjectURL(resp.data as Blob);
      const a = document.createElement("a");
      a.href = url;
      const safeName = (title || "report").slice(0, 50).replace(/[/\\]/g, "-");
      const ext = format === "markdown" ? "md" : format;
      a.download = `${safeName}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
    },
  });
}

export function useReportTemplates() {
  return useQuery({
    queryKey: ["report-templates"],
    queryFn: async () => {
      const { data } = await api.get<{ templates: ReportTemplate[] }>(
        "/intel-reports/templates"
      );
      return data.templates;
    },
  });
}

export function useGenerateFullReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: IntelReportFullGenerateRequest) => {
      const { data } = await api.post<IntelReportFullGenerateResponse>(
        "/intel-reports/generate-full",
        body
      );
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intel-reports"] }),
  });
}

export function useGenerateReportSection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      reportId,
      sectionName,
    }: {
      reportId: string;
      sectionName: string;
    }) => {
      const { data } = await api.post<SectionGenerateResponse>(
        `/intel-reports/${reportId}/sections/${sectionName}/generate`
      );
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["intel-report", vars.reportId] });
    },
  });
}

export function useGenerateReportFromCampaign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      campaign_id: string;
      template_type: string;
      title?: string;
      tlp_marking?: string;
      focus?: string;
      audience?: string;
    }) => {
      const { data } = await api.post<IntelReportFullGenerateResponse>(
        "/intel-reports/generate-from-campaign",
        body
      );
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intel-reports"] }),
  });
}

export function useCloneReportAsType() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      reportId,
      template_type,
      generate,
    }: {
      reportId: string;
      template_type: string;
      generate?: boolean;
    }) => {
      const { data } = await api.post<IntelReportFullGenerateResponse>(
        `/intel-reports/${reportId}/clone`,
        { template_type, generate: generate ?? true }
      );
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intel-reports"] }),
  });
}

export function useRegenerateAllSections() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (reportId: string) => {
      const { data } = await api.post<{ report_id: string; task_id: string }>(
        `/intel-reports/${reportId}/regenerate`
      );
      return data;
    },
    onSuccess: (_, reportId) => {
      qc.invalidateQueries({ queryKey: ["intel-report", reportId] });
    },
  });
}

export function useGenerateExposureReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: ExposureGenerateRequest) => {
      const { data } = await api.post<IntelReport>("/intel-reports/generate-exposure", body);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["intel-reports"] });
      qc.invalidateQueries({ queryKey: ["intel-profiles"] });
    },
  });
}

/** Append evidence to a draft report — the send-to-report gesture. */
export function useAttachToReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      reportId,
      entry_ids,
      entity_ids,
      note,
    }: {
      reportId: string;
      entry_ids?: string[];
      entity_ids?: Record<string, string[]>;
      note?: string;
    }) => {
      const { data } = await api.post<IntelReport>(`/intel-reports/${reportId}/attach`, {
        entry_ids: entry_ids ?? [],
        entity_ids: entity_ids ?? {},
        note: note ?? null,
      });
      return data;
    },
    onSuccess: (report) => {
      qc.invalidateQueries({ queryKey: ["intel-reports"] });
      qc.invalidateQueries({ queryKey: ["intel-report", report.id] });
    },
  });
}
