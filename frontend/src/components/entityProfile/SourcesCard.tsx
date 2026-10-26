/**
 * SourcesCard — the rail's single home for outbound links: the config's
 * external pivot links (moved out of the header meta row), per-type reference
 * links (Malpedia, GitHub, Wikipedia), and for CVEs the NVD reference set
 * grouped into Advisories / Patches / Analysis / Other, capped with an
 * "all N references" expansion. When no Wikipedia article is attached, the
 * find-article flow starts from here, and the enrichment controls close the
 * card out — machine-fetched sources belong with the ones an analyst clicks.
 *
 * Website is deliberately NOT a chip here — it stays an editable identity
 * field in the header (vendor/product), and two homes for one URL was the
 * duplicate the redesign set out to kill.
 */
import { useState } from "react";
import type { EntitySearchResult } from "@/api/types";
import type { EntityType } from "@/stores/intelStore";
import { EnrichmentSection, useEnrichmentSupported } from "./EnrichmentSection";
import type { EntityProfileConfig } from "./entityProfileConfig";
import { groupReferences, refDomain, type RefLink } from "./cveRefs";
import styles from "./entityProfile.module.css";
import { useIsVisitor } from "@/stores/authStore";

/** Per-group render cap when collapsed. */
const REFS_CAP = 12;

export function SourcesCard({
  entityType,
  entityId,
  entity,
  config,
  cveReferences,
  onFindWikipedia,
}: {
  entityType: EntityType;
  entityId: string;
  entity: EntitySearchResult;
  config: EntityProfileConfig;
  /** CVE only: raw reference links (structured references_ or the NVD blob). */
  cveReferences?: RefLink[];
  /** Opens the Wikipedia search flow; offered only when no article is attached. */
  onFindWikipedia?: () => void;
}) {
  const isVisitor = useIsVisitor();
  const [refsExpanded, setRefsExpanded] = useState(false);
  const enrichable = useEnrichmentSupported(entityType);
  const chips: Array<{ label: string; url: string }> = [];
  const seen = new Set<string>();
  const add = (label: string, url: string | null | undefined) => {
    if (!url || seen.has(url)) return;
    seen.add(url);
    chips.push({ label, url });
  };

  for (const link of config.externalLinks?.(entity) ?? []) add(link.platform, link.url);
  add("Malpedia", entity.malpedia_url);
  add("GitHub", (entity as { github_url?: string | null }).github_url);
  add("Wikipedia", entity.wikipedia_url);

  const refGroups = cveReferences ? groupReferences(cveReferences) : [];
  const refTotal = refGroups.reduce((n, g) => n + g.links.length, 0);
  const refShown = refGroups.reduce((n, g) => n + Math.min(g.links.length, REFS_CAP), 0);
  if (chips.length === 0 && refGroups.length === 0 && !onFindWikipedia && !enrichable) return null;

  return (
    <div className={styles.panel}>
      <div className={styles.panelTitle}>Sources &amp; References</div>
      {chips.length > 0 && (
        <div className={styles.extLinkRow}>
          {chips.map((c) => (
            <a key={c.url} className={styles.extLink} href={c.url} target="_blank" rel="noopener noreferrer" title={c.url}>
              {c.label} ↗
            </a>
          ))}
        </div>
      )}
      {refGroups.map(({ group, links }) => (
        <div key={group} className={styles.refGroup}>
          <span className={styles.metaLabel}>{group}</span>
          <div className={styles.extLinkRow}>
            {(refsExpanded ? links : links.slice(0, REFS_CAP)).map((r) => (
              <a key={r.url} className={styles.extLink} href={r.url} target="_blank" rel="noopener noreferrer" title={r.url}>
                {refDomain(r.url)} ↗
              </a>
            ))}
          </div>
        </div>
      ))}
      {refTotal > refShown && !refsExpanded && (
        <button className={styles.refsToggle} onClick={() => setRefsExpanded(true)}>
          all {refTotal} references →
        </button>
      )}
      {refsExpanded && refTotal > refShown && (
        <button className={styles.refsToggle} onClick={() => setRefsExpanded(false)}>
          show fewer <span className="caret-glyph">▴</span>
        </button>
      )}
      {!entity.wikipedia_content && onFindWikipedia && !isVisitor && (
        <button className={styles.sourcesFindWiki} onClick={onFindWikipedia}>
          Find Wikipedia article…
        </button>
      )}
      {/* Enrichment runs outside lookups; the Wikipedia search is one too. */}
      {!isVisitor && <EnrichmentSection entityType={entityType} entityId={entityId} />}
    </div>
  );
}
