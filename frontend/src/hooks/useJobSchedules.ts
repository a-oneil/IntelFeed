import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import { CONSOLE_KEY } from "@/hooks/useEnrichment";

const SCHEDULES_KEY = ["job-schedules"];

/** The enrichment console shows each job's schedule too. */
function invalidateSchedules(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: SCHEDULES_KEY });
  qc.invalidateQueries({ queryKey: CONSOLE_KEY });
}

export interface JobScheduleDef {
  type: "interval" | "crontab";
  seconds?: number;
  minute?: string;
  hour?: string;
  day_of_week?: string;
  day_of_month?: string;
  month_of_year?: string;
}

export interface JobSchedule {
  name: string;
  task: string;
  description: string;
  category: string;
  uses_ai: boolean;
  /** System settings that tune this job, rendered inline on its row. */
  settings_keys?: string[];
  /** Enrichment jobs name the source that owns them. */
  source?: string | null;
  /** The owning source's display name ("NVD 2.0"). */
  source_label?: string | null;
  /** Last 30 days from job_runs. */
  runs_30d?: number;
  ok_30d?: number;
  /** How the last run ended: success | error | retry, or null when never run. */
  last_status?: string | null;
  last_error?: string | null;
  last_run_at?: string | null;
  enabled: boolean;
  default_schedule: JobScheduleDef;
  effective_schedule: JobScheduleDef;
  is_customized: boolean;
  human_schedule: string;
  human_default_schedule: string;
}

export interface JobSchedulesResponse {
  jobs: JobSchedule[];
  categories: Record<string, string>;
  category_order: string[];
}

export function useJobSchedules() {
  return useQuery({
    queryKey: SCHEDULES_KEY,
    queryFn: async () => {
      const { data } = await api.get<JobSchedulesResponse>("/job-schedules");
      return data;
    },
    staleTime: 30_000,
  });
}

export function useUpdateJobSchedule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      name,
      ...body
    }: {
      name: string;
      enabled?: boolean;
      schedule?: JobScheduleDef;
    }) => {
      const { data } = await api.patch(`/job-schedules/${name}`, body);
      return data;
    },
    onSuccess: () => invalidateSchedules(qc),
  });
}

export function useResetJobSchedule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (name: string) => {
      const { data } = await api.delete(`/job-schedules/${name}`);
      return data;
    },
    onSuccess: () => invalidateSchedules(qc),
  });
}

export function useRunJobNow() {
  return useMutation({
    mutationFn: async (name: string) => {
      const { data } = await api.post(`/job-schedules/${name}/run`);
      return data as { task_id: string; message: string };
    },
  });
}
