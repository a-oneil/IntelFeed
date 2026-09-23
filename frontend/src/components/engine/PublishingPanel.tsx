/**
 * PublishingPanel — Engine › Publishing: the outbound side of the observables
 * ledger. Shows each feed (TAXII collection, EDL blocklists, SIEM lookups)
 * with its eligible count and when a consumer last pulled it — a feed nobody
 * pulls is a signal to cut — plus the publish policy knobs from the settings
 * registry. Everything 404s until publishing is enabled and a token is set.
 */
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import api from "@/api/client";
import SystemSettings from "@/components/SystemSettings";
import { Chip } from "@/components/primitives";

import styles from "./PublishingPanel.module.css";

interface FeedRow {
  path: string;
  count: number;
  last_pulled_at?: string | null;
  last_consumer?: string | null;
}

interface PublishStatus {
  enabled: boolean;
  token_configured: boolean;
  policy: { min_confidence: number; max_age_days: number; states: string[] };
  never_publish_count: number;
  feeds: { edl: FeedRow[]; lookup: FeedRow[]; taxii: FeedRow };
}

function relTime(iso: string | null | undefined): string {
  if (!iso) return "never pulled";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 90) return "pulled just now";
  if (s < 3600) return `pulled ${Math.round(s / 60)}m ago`;
  if (s < 86_400) return `pulled ${Math.round(s / 3600)}h ago`;
  return `pulled ${Math.round(s / 86_400)}d ago`;
}

function FeedLine({ row }: { row: FeedRow }) {
  const [copied, setCopied] = useState(false);
  const url = `${window.location.origin}${row.path}`;
  return (
    <div className={styles.feedRow}>
      <span className={styles.feedPath}>{row.path}</span>
      <Chip>{row.count.toLocaleString()}</Chip>
      <span className={styles.feedMeta}>
        {relTime(row.last_pulled_at)}
        {row.last_pulled_at && row.last_consumer ? ` · ${row.last_consumer}` : ""}
      </span>
      <button
        type="button"
        className={styles.copyBtn}
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(url);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          } catch {
            /* insecure context — leave the button un-checked */
          }
        }}
      >
        {copied ? "✓" : "copy url"}
      </button>
    </div>
  );
}

export function PublishingPanel() {
  const { data: status, isError } = useQuery({
    queryKey: ["publish-status"],
    queryFn: async () => {
      const { data } = await api.get<PublishStatus>("/publish/status");
      return data;
    },
    refetchInterval: 60_000,
  });

  if (isError) return <div className={styles.loading}>Couldn't load publish status — is the API reachable?</div>;
  if (!status) return <div className={styles.loading}>Loading publish status…</div>;

  const live = status.enabled && status.token_configured;

  return (
    <div className={styles.wrap}>
      {!live && (
        <div className={styles.offNote}>
          Publishing is {status.enabled ? "enabled but has no token" : "off"} — every feed endpoint returns 404.
          Turn it on and set a token below; consumers then pull with{" "}
          <code>Authorization: Bearer &lt;token&gt;</code> (or <code>?token=</code> for appliances).
        </div>
      )}

      <div className={styles.card}>
        <div className={styles.cardHead}>
          <span className={styles.cardTitle}>TAXII 2.1 Collection</span>
          <Chip tone="toned" tint={live ? "var(--success)" : "var(--text-muted)"}>
            {live ? "live" : "off"}
          </Chip>
        </div>
        <div className={styles.cardBody}>
          <FeedLine row={status.feeds.taxii} />
          <div className={styles.cardNote}>
            STIX 2.1 indicators; <code>valid_until</code> tracks confidence decay so downstream tools age
            indicators the way the ledger does. Discovery at <code>/api/taxii2/</code>.
          </div>
        </div>
      </div>

      <div className={styles.card}>
        <div className={styles.cardHead}>
          <span className={styles.cardTitle}>Blocklists · EDL</span>
          <Chip tone="toned" tint={live ? "var(--success)" : "var(--text-muted)"}>
            {live ? "live" : "off"}
          </Chip>
        </div>
        <div className={styles.cardBody}>
          {status.feeds.edl.map((row) => (
            <FeedLine key={row.path} row={row} />
          ))}
          <div className={styles.cardNote}>Network atoms only — one value per line for Palo Alto EDL / pfBlockerNG.</div>
        </div>
      </div>

      <div className={styles.card}>
        <div className={styles.cardHead}>
          <span className={styles.cardTitle}>Lookup tables · CSV</span>
        </div>
        <div className={styles.cardBody}>
          {status.feeds.lookup.map((row) => (
            <FeedLine key={row.path} row={row} />
          ))}
          <div className={styles.cardNote}>
            Hashes and host artifacts (cmdlines, registry, paths) — SIEM lookups and hunting, never blocklists.
          </div>
        </div>
      </div>

      <div className={styles.card}>
        <div className={styles.cardHead}>
          <span className={styles.cardTitle}>Policy</span>
          <span className={styles.policySummary}>
            ≥ {Math.round(status.policy.min_confidence * 100)}% · ≤ {status.policy.max_age_days}d · active only ·{" "}
            {status.never_publish_count} never-publish
          </span>
        </div>
        <div className={styles.cardBody}>
          <SystemSettings
            filterKeys={[
              "observables_publish_enabled",
              "observables_publish_token",
              "observables_publish_min_confidence",
              "observables_publish_max_age_days",
              "observables_publish_never_suffixes",
            ]}
            flat
            hideGroupTitle
          />
        </div>
      </div>
    </div>
  );
}
