/**
 * EnrichmentGaps — the "fill in missing entity fields" surface, folded onto the
 * Enrich stage (per the relocation design). Reads the bucketed gap report
 * (entities of type X missing field Y) and lets an analyst dispatch AI
 * enrichment per bucket or across all supported buckets.
 */
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { useEnrichGap, useEnrichmentGaps } from "@/hooks/useHygiene";
import { getEntityCssVar, getEntityLabel } from "@/utils/entityTheme";

import styles from "./EnrichmentGaps.module.css";

// (entity_type:field) pairs Claude Code can research + fill today.
const SUPPORTED = new Set([
  "threat_actor:mitre_id",
  "threat_actor:country",
  "threat_actor:motivation",
  "threat_actor:description",
  "malware:malware_type",
  "malware:description",
  "product:vendor_id",
  "cve:cvss",
]);

const FIELD_LABEL: Record<string, string> = {
  mitre_id: "MITRE ID",
  malware_type: "malware type",
  vendor_id: "vendor",
  cvss: "CVSS score",
  description: "description",
  country: "country",
  motivation: "motivation",
  aliases: "aliases",
};

export function EnrichmentGaps() {
  const gaps = useEnrichmentGaps();
  const enrichGap = useEnrichGap();
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [bulkBusy, setBulkBusy] = useState(false);

  const buckets = useMemo(
    () => (gaps.data?.buckets ?? []).filter((b) => b.missing > 0).slice(0, 12),
    [gaps.data],
  );
  const supportedCount = buckets.filter((b) => SUPPORTED.has(`${b.entity_type}:${b.field}`)).length;

  const dispatch = async (entity_type: string, field: string) => {
    const key = `${entity_type}:${field}`;
    setBusyKey(key);
    try {
      const r = await enrichGap.mutateAsync({ entity_type, field, limit: 10 });
      if (!r.supported) toast.error(r.message ?? "AI enrichment not wired up for this field");
      else if (r.enqueued === 0) toast.message(r.message ?? "Nothing to enrich");
      else toast.success(`Enriching ${r.batch_size} of ${r.total_missing} — results fill in over ~1 min`);
    } catch (e) {
      toast.error(`Enrich failed: ${(e as Error).message}`);
    } finally {
      setBusyKey(null);
    }
  };

  const enrichAll = async () => {
    const targets = buckets.filter((b) => SUPPORTED.has(`${b.entity_type}:${b.field}`));
    if (!targets.length) return;
    if (!confirm(`Dispatch AI enrichment for ${targets.length} field groups (10 entities each)?`)) return;
    setBulkBusy(true);
    let n = 0;
    for (const b of targets) {
      try {
        await enrichGap.mutateAsync({ entity_type: b.entity_type, field: b.field, limit: 10 });
        n++;
      } catch {
        /* keep going */
      }
    }
    setBulkBusy(false);
    toast.success(`Dispatched ${n} enrichment batch${n === 1 ? "" : "es"}`);
  };

  return (
    <div className={styles.wrap}>
      <div className={styles.head}>
        <div>
          <h4 className={styles.title}>Enrichment gaps</h4>
          <p className={styles.hint}>Entities missing key fields — AI fills them from EPSS, KEV, MITRE, Malpedia, Wikipedia.</p>
        </div>
        <button className={styles.enrichAll} disabled={bulkBusy || supportedCount === 0} onClick={enrichAll}>
          {bulkBusy ? "Dispatching…" : `Enrich all (${supportedCount})`}
        </button>
      </div>

      <div className={styles.list}>
        {buckets.map((b) => {
          const key = `${b.entity_type}:${b.field}`;
          const slug = b.entity_type;
          const supported = SUPPORTED.has(key);
          const busy = busyKey === key;
          const samples = (b.sample ?? []).slice(0, 3).map((s) => s.name).filter(Boolean);
          return (
            <div key={key} className={styles.row}>
              <span className={styles.ent}>
                <span className={styles.dot} style={{ background: getEntityCssVar(slug) }} />
                {getEntityLabel(slug)}
              </span>
              <span className={styles.miss}>no {FIELD_LABEL[b.field] ?? b.field.replace(/_/g, " ")}</span>
              <span className={styles.samples}>
                {samples.length ? samples.join(", ") : ""}
                <span className={styles.count}>
                  {samples.length ? " · " : ""}
                  {b.missing.toLocaleString()} total
                </span>
              </span>
              {supported ? (
                <button className={styles.enrich} disabled={busy} onClick={() => dispatch(b.entity_type, b.field)}>
                  {busy ? "…" : "Enrich"}
                </button>
              ) : (
                <span className={styles.noAuto}>manual</span>
              )}
            </div>
          );
        })}
        {!gaps.isLoading && buckets.length === 0 && (
          <div className={styles.empty}>No enrichment gaps — every entity has its key fields.</div>
        )}
        {gaps.isLoading && <div className={styles.empty}>Loading gaps…</div>}
      </div>
    </div>
  );
}
