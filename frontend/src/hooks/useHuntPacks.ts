import { useCallback, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import api from "@/api/client";
import type { QueryLanguage } from "@/utils/queryLanguage";

/* ── Hunt packs ──────────────────────────────────────────────────────────────
   A starting point for a hunt, not a record of one: hypotheses and queries the analyst copies into their SIEM or downloads as ATHF hunt files. One service backs both places that show them: the Threats board drawer asks for its window (7d, 14d, 30d), the entity profile for "all" (everything reported). */

/** Everything reported: the profile's pack. */
export const PROFILE_SCOPE = "all";

/** Entity types a pack can be drafted for (mirrors hunt_pack.HUNT_TYPES). */
export const HUNT_TYPES = ["threat_actor", "malware", "cve", "ttp", "tool", "campaign"] as const;

export function huntsSupported(entityType: string): boolean {
  return (HUNT_TYPES as readonly string[]).includes(entityType);
}

export interface HuntTelemetry {
  source: string;
  have: boolean;
}

export interface HuntHypothesis {
  id: string;
  title: string;
  /** ATHF form: "Adversaries use [behavior] to [goal] on [target]". */
  hypothesis: string;
  tactic: string | null;
  techniques: string[];
  platform: string | null;
  data_sources: string[];
  /** data_sources checked against the enabled telemetry inventory. */
  telemetry: HuntTelemetry[];
  runnable: boolean;
  query: string;
  query_notes: string | null;
  false_positives: string | null;
  /** Why this hunt: the claim or quote it rests on. */
  evidence?: string | null;
  /** The log the query reads, and how it reaches the SIEM. */
  log_source?: string | null;
  /** The inventory source holding it; "" when none does. */
  source_name?: string | null;
  /** source_name is an enabled telemetry source (absent on packs without log_source). */
  source_have?: boolean | null;
  /** techniques with their catalog names and profile ids (null when not in the catalog). */
  technique_refs?: { technique_id: string; name: string | null; id: string | null }[];
}

export interface HuntPack {
  entity_type: string;
  entity_key: string;
  label: string;
  /** The scope it was drafted from: a board window or "all". */
  window: string;
  language: QueryLanguage;
  language_name: string;
  generated_at: string | null;
  model: string | null;
  entry_ids: string[];
  hypotheses: HuntHypothesis[];
}

export interface HuntPackResponse {
  /** drafting: the AI worker is writing one (pack holds the previous, if any). */
  status: "none" | "drafting" | "ready" | "failed";
  language: QueryLanguage;
  language_name: string;
  pack: HuntPack | null;
  started_at: string | null;
  error: string | null;
}

const base = (entityType: string, entityKey: string) =>
  `/hunt-packs/${entityType}/${encodeURIComponent(entityKey)}`;

export const huntPackKey = (entityType: string, entityKey: string, scope: string) => [
  "hunt-pack",
  entityType,
  entityKey,
  scope,
];

/** The entity's pack for a scope, polled every 4 seconds while a draft runs. The language is the user's preferred query language, applied server-side. */
export function useHuntPack(entityType: string, entityKey: string, scope: string, enabled = true) {
  return useQuery({
    queryKey: huntPackKey(entityType, entityKey, scope),
    queryFn: async () => {
      const { data } = await api.get<HuntPackResponse>(base(entityType, entityKey), { params: { scope } });
      return data;
    },
    enabled: enabled && huntsSupported(entityType) && Boolean(entityKey),
    staleTime: 60_000,
    refetchInterval: (query) => (query.state.data?.status === "drafting" ? 4_000 : false),
  });
}

/** Queue a draft (or redraft) on the AI worker. Returns at once with status "drafting"; useHuntPack polls until it settles. */
export function useDraftHuntPack() {
  const qc = useQueryClient();
  return useMutation({
    /** `more` keeps the pack and adds new hunts after it (Draft more). */
    mutationFn: async (vars: { entityType: string; entityKey: string; scope: string; more?: boolean }) => {
      const { data } = await api.post<HuntPackResponse>(base(vars.entityType, vars.entityKey), null, {
        params: { scope: vars.scope, ...(vars.more ? { more: true } : {}) },
      });
      return data;
    },
    onSuccess: (data, vars) => {
      qc.setQueryData(huntPackKey(vars.entityType, vars.entityKey, vars.scope), data);
    },
  });
}

function filenameFrom(disposition: string, fallback: string): string {
  const star = /filename\*=UTF-8''([^;]+)/i.exec(disposition)?.[1];
  if (star) {
    try {
      return decodeURIComponent(star);
    } catch {
      /* fall through to the ASCII name */
    }
  }
  return /filename="([^"]+)"/.exec(disposition)?.[1] ?? fallback;
}

function saveBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** Download one hypothesis as an ATHF hunt file (H-XXXX-<entity>-<hunt>.md). */
export async function downloadHuntFile(
  entityType: string,
  entityKey: string,
  scope: string,
  hypothesisId: string,
): Promise<void> {
  const res = await api.get<Blob>(`${base(entityType, entityKey)}/hunts/${hypothesisId}.md`, {
    params: { scope },
    responseType: "blob",
  });
  saveBlob(res.data, filenameFrom(String(res.headers?.["content-disposition"] ?? ""), `H-XXXX-${hypothesisId}.md`));
}

/** Download the hunt package zip. Never drafts: draft first, then download. */
export async function downloadHuntPackage(entityType: string, entityId: string, label: string): Promise<void> {
  const res = await api.get<Blob>(`${base(entityType, entityId)}/package.zip`, {
    responseType: "blob",
    timeout: 120_000,
  });
  const fallback = `${label.replace(/[^\w.-]+/g, "-").toLowerCase()}-hunt-package.zip`;
  saveBlob(res.data, filenameFrom(String(res.headers?.["content-disposition"] ?? ""), fallback));
}

/** The "Download hunt package" button: drafts the hunts first when none exist (or the last draft failed), waits for the AI worker, then downloads the zip. When hunts can't be drafted (no provider, nothing to hunt from, the draft failed) it says why and downloads the rest of the package anyway. */
export function useHuntPackageDownload(entityType: string, entityKey: string, label: string) {
  const supported = huntsSupported(entityType);
  const { data } = useHuntPack(entityType, entityKey, PROFILE_SCOPE, supported);
  const draft = useDraftHuntPack();
  const [pending, setPending] = useState(false);
  const [downloading, setDownloading] = useState(false);

  const fetchZip = useCallback(
    async (note?: string) => {
      setDownloading(true);
      try {
        await downloadHuntPackage(entityType, entityKey, label);
        if (note) toast.warning(note);
        else toast.success(`Hunt package for ${label} downloaded`);
      } catch {
        toast.error("Could not build the hunt package");
      } finally {
        setDownloading(false);
      }
    },
    [entityType, entityKey, label],
  );

  // A queued draft settled: download now, with or without hunts.
  useEffect(() => {
    if (!pending || !data || data.status === "drafting") return;
    setPending(false);
    if (data.status === "failed") void fetchZip(`Hunts couldn't be drafted (${data.error}). Downloaded without them.`);
    else void fetchZip();
  }, [pending, data, fetchZip]);

  const start = () => {
    if (data?.status === "ready" || data?.status === "drafting") {
      if (data.status === "drafting") setPending(true);
      else void fetchZip();
      return;
    }
    draft.mutate(
      { entityType, entityKey, scope: PROFILE_SCOPE },
      {
        onSuccess: () => setPending(true),
        onError: (err) => {
          const msg = (err as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error
            ?.message;
          void fetchZip(`${msg ?? "Hunts couldn't be drafted"} Downloaded without them.`);
        },
      },
    );
  };

  return {
    start,
    status: data?.status ?? "none",
    pack: data?.pack ?? null,
    startedAt: data?.started_at ?? null,
    error: data?.error ?? null,
    languageName: data?.language_name ?? null,
    busy: pending || downloading || draft.isPending || data?.status === "drafting",
    drafting: pending || draft.isPending || data?.status === "drafting",
    downloading,
  };
}
