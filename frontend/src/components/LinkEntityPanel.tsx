import { useState, useMemo, useEffect } from "react";
import {
  useThreatActors,
  useMalwareFamilies,
  useCountries,
  useTTPs,
  useCVEs,
  useMitigations,
  useOffensiveTools,
  useVendors,
  useProducts,
  useLinkEntity,
} from "@/hooks/useIntelligence";
import styles from "./AddAliasPanel.module.css";

type EntityTab = "threat_actor" | "malware" | "ttp" | "cve" | "country" | "mitigation" | "tool" | "vendor" | "product";

const TABS: { key: EntityTab; label: string }[] = [
  { key: "threat_actor", label: "Actors" },
  { key: "malware", label: "Malware" },
  { key: "ttp", label: "TTPs" },
  { key: "cve", label: "CVEs" },
  { key: "country", label: "Countries" },
  { key: "mitigation", label: "Mitigations" },
  { key: "tool", label: "Tools" },
  { key: "vendor", label: "Vendors" },
  { key: "product", label: "Products" },
];

interface LinkEntityPanelProps {
  entryId: string;
  initialSearch?: string;
  onClose: () => void;
}

function useDebounced(value: string, delay: number) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

export function LinkEntityPanel({ entryId, initialSearch, onClose }: LinkEntityPanelProps) {
  const [tab, setTab] = useState<EntityTab>("threat_actor");
  const [search, setSearch] = useState(initialSearch ?? "");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<{ name: string; type: string } | null>(null);

  const linkEntity = useLinkEntity();

  const debouncedSearch = useDebounced(search, 250);
  const searchParam = debouncedSearch.trim() || undefined;

  const { data: actorsData } = useThreatActors({ limit: 50, sort_by: "name", sort_order: "asc", search: searchParam });
  const { data: malwareData } = useMalwareFamilies({ limit: 50, sort_by: "name", sort_order: "asc", search: searchParam });
  const { data: countriesData } = useCountries({ limit: 50, sort_by: "name", sort_order: "asc", search: searchParam });
  const { data: ttpsData } = useTTPs({ limit: 50, sort_by: "technique_id", sort_order: "asc", search: searchParam });
  const { data: cvesData } = useCVEs({ limit: 50, sort_by: "cve_id", sort_order: "desc", search: searchParam });
  const { data: mitigationsData } = useMitigations({ limit: 50, search: searchParam });
  const { data: toolsData } = useOffensiveTools({ limit: 50, search: searchParam });
  const { data: vendorsData } = useVendors({ limit: 50, search: searchParam });
  const { data: productsData } = useProducts({ limit: 50, search: searchParam });

  const actors = useMemo(() => actorsData?.items ?? [], [actorsData]);
  const malwareItems = useMemo(() => malwareData?.items ?? [], [malwareData]);
  const countryItems = useMemo(() => countriesData?.items ?? [], [countriesData]);
  const ttpItems = useMemo(() => ttpsData?.items ?? [], [ttpsData]);
  const cveItems = useMemo(() => cvesData?.items ?? [], [cvesData]);
  const mitigationItems = useMemo(() => mitigationsData?.items ?? [], [mitigationsData]);
  const toolItems = useMemo(() => toolsData?.items ?? [], [toolsData]);
  const vendorItems = useMemo(() => vendorsData?.items ?? [], [vendorsData]);
  const productItems = useMemo(() => productsData?.items ?? [], [productsData]);

  const handleLink = async (entityId: string, entityType: EntityTab, displayName: string) => {
    setError(null);
    try {
      await linkEntity.mutateAsync({ entryId, entityId, entityType, selectedText: initialSearch });
      setSuccess({ name: displayName, type: entityType.replace("_", " ") });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to link entity";
      if (msg.includes("409") || msg.includes("already_linked")) {
        setError(`${displayName} is already linked to this entry`);
      } else {
        setError(msg);
      }
    }
  };

  if (success) {
    return (
      <div className={styles.panel}>
        <div className={styles.success}>
          <div className={styles.successMsg}>Entity linked</div>
          <div className={styles.successDetail}>
            <strong>{success.name}</strong> ({success.type}) is now linked to this entry
          </div>
          <button className={styles.doneBtn} onClick={onClose}>Done</button>
        </div>
      </div>
    );
  }

  const renderEntityList = () => {
    switch (tab) {
      case "threat_actor":
        return actors.length === 0 ? (
          <div className={styles.empty}>No threat actors found</div>
        ) : (
          actors.map((a) => (
            <button key={a.id} className={styles.entityItem} onClick={() => handleLink(a.id, "threat_actor", a.name)} disabled={linkEntity.isPending}>
              <div className={styles.entityInfo}>
                <div className={styles.entityName}>{a.name}</div>
                {a.aliases && a.aliases.length > 0 && <div className={styles.entityAliases}>aka: {a.aliases.join(", ")}</div>}
              </div>
              <span className={styles.entityMeta}>{a.article_count} articles</span>
            </button>
          ))
        );
      case "malware":
        return malwareItems.length === 0 ? (
          <div className={styles.empty}>No malware families found</div>
        ) : (
          malwareItems.map((m) => (
            <button key={m.id} className={styles.entityItem} onClick={() => handleLink(m.id, "malware", m.name)} disabled={linkEntity.isPending}>
              <div className={styles.entityInfo}>
                <div className={styles.entityName}>{m.name}</div>
                {m.aliases && m.aliases.length > 0 && <div className={styles.entityAliases}>aka: {m.aliases.join(", ")}</div>}
              </div>
              <span className={styles.entityMeta}>{m.article_count} articles</span>
            </button>
          ))
        );
      case "ttp":
        return ttpItems.length === 0 ? (
          <div className={styles.empty}>No TTPs found</div>
        ) : (
          ttpItems.map((t) => (
            <button key={t.id} className={styles.entityItem} onClick={() => handleLink(t.id, "ttp", `${t.technique_id} ${t.technique_name}`)} disabled={linkEntity.isPending}>
              <div className={styles.entityInfo}>
                <div className={styles.entityName}>{t.technique_id} — {t.technique_name}</div>
                {t.tactic && <div className={styles.entityAliases}>{t.tactic}</div>}
              </div>
              <span className={styles.entityMeta}>{t.article_count} articles</span>
            </button>
          ))
        );
      case "cve":
        return cveItems.length === 0 ? (
          <div className={styles.empty}>No CVEs found</div>
        ) : (
          cveItems.map((c) => (
            <button key={c.id} className={styles.entityItem} onClick={() => handleLink(c.id, "cve", c.cve_id)} disabled={linkEntity.isPending}>
              <div className={styles.entityInfo}>
                <div className={styles.entityName}>{c.cve_id}</div>
                {c.severity && <div className={styles.entityAliases}>{c.severity}{c.cvss_score != null ? ` (${c.cvss_score})` : ""}</div>}
              </div>
              <span className={styles.entityMeta}>{c.article_count} articles</span>
            </button>
          ))
        );
      case "country":
        return countryItems.length === 0 ? (
          <div className={styles.empty}>No countries found</div>
        ) : (
          countryItems.map((c) => (
            <button key={c.id} className={styles.entityItem} onClick={() => handleLink(c.id, "country", c.name)} disabled={linkEntity.isPending}>
              <div className={styles.entityInfo}>
                <div className={styles.entityName}>{c.name}</div>
                {c.aliases && c.aliases.length > 0 && <div className={styles.entityAliases}>aka: {c.aliases.join(", ")}</div>}
              </div>
              <span className={styles.entityMeta}>{c.article_count} articles</span>
            </button>
          ))
        );
      case "mitigation":
        return mitigationItems.length === 0 ? (
          <div className={styles.empty}>No mitigations found</div>
        ) : (
          mitigationItems.map((m) => (
            <button key={m.id} className={styles.entityItem} onClick={() => handleLink(m.id, "mitigation", m.name)} disabled={linkEntity.isPending}>
              <div className={styles.entityInfo}>
                <div className={styles.entityName}>{m.name}</div>
                {m.mitre_id && <div className={styles.entityAliases}>{m.mitre_id}</div>}
              </div>
              <span className={styles.entityMeta}>{m.article_count} articles</span>
            </button>
          ))
        );
      case "tool":
        return toolItems.length === 0 ? (
          <div className={styles.empty}>No tools found</div>
        ) : (
          toolItems.map((t) => (
            <button key={t.id} className={styles.entityItem} onClick={() => handleLink(t.id, "tool", t.name)} disabled={linkEntity.isPending}>
              <div className={styles.entityInfo}>
                <div className={styles.entityName}>{t.name}</div>
                {t.aliases && t.aliases.length > 0 && <div className={styles.entityAliases}>aka: {t.aliases.join(", ")}</div>}
              </div>
              <span className={styles.entityMeta}>{t.article_count} articles</span>
            </button>
          ))
        );
      case "vendor":
        return vendorItems.length === 0 ? (
          <div className={styles.empty}>No vendors found</div>
        ) : (
          vendorItems.map((v) => (
            <button key={v.id} className={styles.entityItem} onClick={() => handleLink(v.id, "vendor", v.name)} disabled={linkEntity.isPending}>
              <div className={styles.entityInfo}>
                <div className={styles.entityName}>{v.name}</div>
                {v.vendor_type && <div className={styles.entityAliases}>{v.vendor_type}</div>}
              </div>
              <span className={styles.entityMeta}>{v.article_count} articles</span>
            </button>
          ))
        );
      case "product":
        return productItems.length === 0 ? (
          <div className={styles.empty}>No products found</div>
        ) : (
          productItems.map((p) => (
            <button key={p.id} className={styles.entityItem} onClick={() => handleLink(p.id, "product", p.name)} disabled={linkEntity.isPending}>
              <div className={styles.entityInfo}>
                <div className={styles.entityName}>{p.name}</div>
                {p.vendor_name && <div className={styles.entityAliases}>{p.vendor_name}</div>}
              </div>
              <span className={styles.entityMeta}>{p.article_count} articles</span>
            </button>
          ))
        );
    }
  };

  return (
    <div className={styles.panel}>
      <div className={styles.aliasPreview}>
        <div className={styles.aliasLabel}>Link entity to entry</div>
        {initialSearch && <div className={styles.aliasValue}>&ldquo;{initialSearch}&rdquo;</div>}
      </div>

      <div className={styles.typeTabs}>
        {TABS.map((t) => (
          <button
            key={t.key}
            className={`${styles.typeTab} ${tab === t.key ? styles.typeTabActive : ""}`}
            onClick={() => { setTab(t.key); setError(null); }}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className={styles.searchWrap}>
        <input
          className={styles.searchInput}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search entities..."
          autoFocus
        />
      </div>

      {error && <div className={styles.error}>{error}</div>}

      <div className={styles.entityList}>
        {renderEntityList()}
      </div>
    </div>
  );
}
