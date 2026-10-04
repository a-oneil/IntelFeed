import { useCallback, useMemo, useState } from "react";
import type { Feed } from "@/api/types";

export type PaneId =
  | "overview"
  | "identity"
  | "source"
  | "pipeline"
  | "assessment"
  | "readers";

export type IntelMode = "full" | "selective" | "manual" | "none";

/**
 * Every editable field on a feed, flat, in one object.
 *
 * The previous modal held these in 30 separate useState calls, which is why
 * nothing could tell whether the form was dirty, which section a change
 * belonged to, or which keys were safe for a non-admin to send. One object
 * compared against its initial value answers all three.
 *
 * Everything that lives in `adapter_config` — including `auto_translate` and
 * youtube's `exclude_shorts` — goes in `adapter` rather than getting its own
 * field: the PUT merges `adapter_config` server-side, so there is no reason for
 * the per-type keys to be spelled out here.
 */
export interface FeedFormValues {
  custom_title: string;
  /** "" = Uncategorized. Sent as null, which the API now honours. */
  category_id: string;
  is_muted: boolean;
  url: string;
  feed_type: string;
  fetch_interval_minutes: number;
  /** "" = keep forever. Sent as null, which the API now honours. */
  retention_days: string;
  is_active: boolean;
  intel_extraction_mode: IntelMode;
  ai_analysis_enabled: boolean;
  auto_extract_on_ingest: boolean;
  extract_detection_rules: boolean;
  extract_tools: boolean;
  reliability_rating: string;
  timeliness_rating: string;
  relevance_rating: string;
  analyst_notes: string;
  adapter: Record<string, unknown>;
}

/** Which pane owns each field, so the rail can mark the ones with edits. */
const FIELD_PANE: Record<keyof FeedFormValues, PaneId> = {
  custom_title: "identity",
  category_id: "identity",
  is_muted: "identity",
  url: "source",
  feed_type: "source",
  fetch_interval_minutes: "source",
  retention_days: "source",
  is_active: "source",
  adapter: "source",
  intel_extraction_mode: "pipeline",
  ai_analysis_enabled: "pipeline",
  auto_extract_on_ingest: "pipeline",
  extract_detection_rules: "pipeline",
  extract_tools: "pipeline",
  reliability_rating: "assessment",
  timeliness_rating: "assessment",
  relevance_rating: "assessment",
  analyst_notes: "assessment",
};

/**
 * Curation is anyone's to change; everything else is shared plumbing the API
 * only accepts from an admin. A non-admin must not send the other keys at all
 * — the endpoint 403s on their mere presence, explicit nulls included.
 */
const CURATION_FIELDS = [
  "custom_title",
  "category_id",
  "is_muted",
  "reliability_rating",
  "timeliness_rating",
  "relevance_rating",
  "analyst_notes",
] as const satisfies readonly (keyof FeedFormValues)[];

const CURATION = new Set<string>(CURATION_FIELDS);

/** The response masks an existing Bluesky app password; never echo it back. */
const MASKED = /^•+$/;

function initialValues(feed: Feed): FeedFormValues {
  const adapter: Record<string, unknown> = { ...(feed.adapter_config || {}) };
  if (typeof adapter.app_password === "string" && MASKED.test(adapter.app_password)) {
    delete adapter.app_password;
  }
  return {
    custom_title: feed.custom_title || "",
    category_id: feed.category_id || "",
    is_muted: feed.is_muted,
    url: feed.url,
    feed_type: feed.feed_type,
    fetch_interval_minutes: feed.fetch_interval_minutes,
    retention_days: feed.retention_days != null ? String(feed.retention_days) : "",
    is_active: feed.is_active,
    intel_extraction_mode: (feed.intel_extraction_mode || "selective") as IntelMode,
    ai_analysis_enabled: feed.ai_analysis_enabled ?? true,
    auto_extract_on_ingest: feed.auto_extract_on_ingest ?? false,
    extract_detection_rules: feed.extract_detection_rules ?? false,
    extract_tools: feed.extract_tools ?? true,
    reliability_rating: feed.reliability_rating || "",
    timeliness_rating: feed.timeliness_rating || "",
    relevance_rating: feed.relevance_rating || "",
    analyst_notes: feed.analyst_notes || "",
    adapter,
  };
}

function same(a: unknown, b: unknown): boolean {
  if (typeof a === "object" && a !== null) return JSON.stringify(a) === JSON.stringify(b);
  return a === b;
}

export interface FeedForm {
  values: FeedFormValues;
  set: <K extends keyof FeedFormValues>(key: K, value: FeedFormValues[K]) => void;
  /** Several fields at once — a pipeline stage toggle implies more than one. */
  setMany: (patch: Partial<FeedFormValues>) => void;
  setAdapter: (key: string, value: unknown) => void;
  /** Non-empty = unsaved edits exist. */
  dirtyFields: (keyof FeedFormValues)[];
  dirtyPanes: Set<PaneId>;
  isDirty: boolean;
  /** New Bluesky app password, write-only — not part of dirty comparison. */
  newAppPassword: string;
  setNewAppPassword: (v: string) => void;
  /** Only the keys that actually changed, gated by role. */
  buildPayload: (isAdmin: boolean) => Record<string, unknown>;
  reset: () => void;
}

export function useFeedForm(feed: Feed): FeedForm {
  const initial = useMemo(() => initialValues(feed), [feed]);
  const [values, setValues] = useState<FeedFormValues>(initial);
  const [newAppPassword, setNewAppPassword] = useState("");

  const set = useCallback(
    <K extends keyof FeedFormValues>(key: K, value: FeedFormValues[K]) => {
      setValues((v) => ({ ...v, [key]: value }));
    },
    []
  );

  const setMany = useCallback((patch: Partial<FeedFormValues>) => {
    setValues((v) => ({ ...v, ...patch }));
  }, []);

  const setAdapter = useCallback((key: string, value: unknown) => {
    setValues((v) => ({ ...v, adapter: { ...v.adapter, [key]: value } }));
  }, []);

  const reset = useCallback(() => {
    setValues(initial);
    setNewAppPassword("");
  }, [initial]);

  const dirtyFields = useMemo(
    () =>
      (Object.keys(FIELD_PANE) as (keyof FeedFormValues)[]).filter(
        (k) => !same(values[k], initial[k])
      ),
    [values, initial]
  );

  const dirtyPanes = useMemo(() => {
    const panes = new Set<PaneId>();
    for (const f of dirtyFields) panes.add(FIELD_PANE[f]);
    return panes;
  }, [dirtyFields]);

  const isDirty = dirtyFields.length > 0 || newAppPassword !== "";

  const buildPayload = useCallback(
    (isAdmin: boolean) => {
      const payload: Record<string, unknown> = {};
      const fields = isAdmin ? dirtyFields : dirtyFields.filter((f) => CURATION.has(f));

      for (const field of fields) {
        switch (field) {
          case "category_id":
            payload.category_id = values.category_id || null;
            break;
          case "retention_days":
            payload.retention_days =
              values.retention_days === "" ? null : Number(values.retention_days);
            break;
          case "custom_title":
            payload.custom_title = values.custom_title.trim();
            break;
          case "analyst_notes":
            payload.analyst_notes = values.analyst_notes.trim();
            break;
          case "url":
            payload.url = values.url.trim();
            break;
          case "adapter":
            payload.adapter_config = buildAdapterConfig(values);
            break;
          default:
            payload[field] = values[field];
        }
      }

      // A new app password rides along in adapter_config even when nothing else
      // in it changed. Blank means "keep the stored one", which the API honours.
      if (isAdmin && newAppPassword !== "") {
        const config = (payload.adapter_config as Record<string, unknown>) ?? buildAdapterConfig(values);
        config.app_password = newAppPassword;
        payload.adapter_config = config;
      }

      return payload;
    },
    [dirtyFields, values, newAppPassword]
  );

  return {
    values,
    set,
    setMany,
    setAdapter,
    dirtyFields,
    dirtyPanes,
    isDirty,
    newAppPassword,
    setNewAppPassword,
    buildPayload,
    reset,
  };
}

/**
 * Bluesky is rebuilt rather than merged: its three modes use different keys
 * (handle / feed_uri / query), and merging would leave the previous mode's keys
 * behind for the adapter to trip over. Every other type merges, because its
 * config holds fetch state (watermarks, last_commit_sha) we must not drop.
 */
function buildAdapterConfig(values: FeedFormValues): Record<string, unknown> {
  const adapter = values.adapter;
  if (values.feed_type !== "bluesky") {
    const config = { ...adapter };
    delete config.app_password;
    return config;
  }

  const mode = (adapter.mode as string) || "author";
  const config: Record<string, unknown> = { mode };
  if (mode === "author") {
    config.handle = String(adapter.handle || "").trim().replace(/^@/, "");
    config.include_reposts = Boolean(adapter.include_reposts);
  } else if (mode === "feed") {
    config.feed_uri = String(adapter.feed_uri || "").trim();
  } else if (mode === "search") {
    config.query = String(adapter.query || "").trim();
    const lang = String(adapter.lang || "").trim();
    if (lang) config.lang = lang;
  }
  config.identifier = String(adapter.identifier || "").trim() || null;
  config.author_entity = adapter.author_entity ?? null;
  config.auto_translate = Boolean(adapter.auto_translate);
  return config;
}
