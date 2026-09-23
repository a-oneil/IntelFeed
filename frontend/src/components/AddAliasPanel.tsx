import { useState, useMemo, useEffect } from "react";
import { useThreatActors, useMalwareFamilies, useCountries, useVendors, useProducts } from "@/hooks/useIntelligence";
import { useUpdateThreatActor, useUpdateMalwareFamily, useUpdateCountry, useUpdateVendor, useUpdateProduct } from "@/hooks/useEntityProfile";
import type { ThreatActor, MalwareFamily, Country, Vendor, Product } from "@/api/types";
import styles from "./AddAliasPanel.module.css";

type EntityTab = "threat_actor" | "malware" | "country" | "vendor" | "product";

interface AddAliasPanelProps {
  aliasText: string;
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

export function AddAliasPanel({ aliasText, onClose }: AddAliasPanelProps) {
  const [tab, setTab] = useState<EntityTab>("threat_actor");
  const [search, setSearch] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<{ name: string; type: string } | null>(null);

  const debouncedSearch = useDebounced(search, 250);
  const searchParam = debouncedSearch.trim() || undefined;

  const { data: actorsData } = useThreatActors({ limit: 50, sort_by: "name", sort_order: "asc", search: searchParam });
  const { data: malwareData } = useMalwareFamilies({ limit: 50, sort_by: "name", sort_order: "asc", search: searchParam });
  const { data: countriesData } = useCountries({ limit: 50, sort_by: "name", sort_order: "asc", search: searchParam });
  const { data: vendorsData } = useVendors({ limit: 50, search: searchParam });
  const { data: productsData } = useProducts({ limit: 50, search: searchParam });

  const updateActor = useUpdateThreatActor();
  const updateMalware = useUpdateMalwareFamily();
  const updateCountry = useUpdateCountry();
  const updateVendor = useUpdateVendor();
  const updateProduct = useUpdateProduct();

  const isPending = updateActor.isPending || updateMalware.isPending || updateCountry.isPending || updateVendor.isPending || updateProduct.isPending;

  const actors = useMemo(() => actorsData?.items ?? [], [actorsData]);
  const malware = useMemo(() => malwareData?.items ?? [], [malwareData]);
  const countries = useMemo(() => countriesData?.items ?? [], [countriesData]);
  const vendorItems = useMemo(() => vendorsData?.items ?? [], [vendorsData]);
  const productItems = useMemo(() => productsData?.items ?? [], [productsData]);

  const handleAddToActor = async (actor: ThreatActor) => {
    setError(null);
    const existing = actor.aliases ?? [];
    if (existing.some((a) => a.toLowerCase() === aliasText.toLowerCase())) {
      setError(`"${aliasText}" is already an alias of ${actor.name}`);
      return;
    }
    try {
      await updateActor.mutateAsync({ id: actor.id, aliases: [...existing, aliasText] });
      setSuccess({ name: actor.name, type: "threat actor" });
    } catch {
      setError("Failed to add alias");
    }
  };

  const handleAddToMalware = async (malware: MalwareFamily) => {
    setError(null);
    const existing = malware.aliases ?? [];
    if (existing.some((a) => a.toLowerCase() === aliasText.toLowerCase())) {
      setError(`"${aliasText}" is already an alias of ${malware.name}`);
      return;
    }
    try {
      await updateMalware.mutateAsync({ id: malware.id, aliases: [...existing, aliasText] });
      setSuccess({ name: malware.name, type: "malware" });
    } catch {
      setError("Failed to add alias");
    }
  };

  const handleAddToCountry = async (country: Country) => {
    setError(null);
    const existing = country.aliases ?? [];
    if (existing.some((a) => a.toLowerCase() === aliasText.toLowerCase())) {
      setError(`"${aliasText}" is already an alias of ${country.name}`);
      return;
    }
    try {
      await updateCountry.mutateAsync({ id: country.id, aliases: [...existing, aliasText] });
      setSuccess({ name: country.name, type: "country" });
    } catch {
      setError("Failed to add alias");
    }
  };

  const handleAddToVendor = async (vendor: Vendor) => {
    setError(null);
    const existing = vendor.aliases ?? [];
    if (existing.some((a) => a.toLowerCase() === aliasText.toLowerCase())) {
      setError(`"${aliasText}" is already an alias of ${vendor.name}`);
      return;
    }
    try {
      await updateVendor.mutateAsync({ id: vendor.id, aliases: [...existing, aliasText] });
      setSuccess({ name: vendor.name, type: "vendor" });
    } catch {
      setError("Failed to add alias");
    }
  };

  const handleAddToProduct = async (product: Product) => {
    setError(null);
    const existing = product.aliases ?? [];
    if (existing.some((a) => a.toLowerCase() === aliasText.toLowerCase())) {
      setError(`"${aliasText}" is already an alias of ${product.name}`);
      return;
    }
    try {
      await updateProduct.mutateAsync({ id: product.id, aliases: [...existing, aliasText] });
      setSuccess({ name: product.name, type: "product" });
    } catch {
      setError("Failed to add alias");
    }
  };

  if (success) {
    return (
      <div className={styles.panel}>
        <div className={styles.success}>
          <div className={styles.successMsg}>Alias added</div>
          <div className={styles.successDetail}>
            &ldquo;{aliasText}&rdquo; is now an alias of <strong>{success.name}</strong> ({success.type})
          </div>
          <button className={styles.doneBtn} onClick={onClose}>Done</button>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.panel}>
      <div className={styles.aliasPreview}>
        <div className={styles.aliasLabel}>Adding alias</div>
        <div className={styles.aliasValue}>&ldquo;{aliasText}&rdquo;</div>
      </div>

      <div className={styles.typeTabs}>
        {(["threat_actor", "malware", "country", "vendor", "product"] as EntityTab[]).map((t) => (
          <button
            key={t}
            className={`${styles.typeTab} ${tab === t ? styles.typeTabActive : ""}`}
            onClick={() => { setTab(t); setError(null); }}
          >
            {t === "threat_actor" ? "Actors" : t === "malware" ? "Malware" : t === "country" ? "Countries" : t === "vendor" ? "Vendors" : "Products"}
          </button>
        ))}
      </div>

      <div className={styles.searchWrap}>
        <input
          className={styles.searchInput}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter profiles..."
          autoFocus
        />
      </div>

      {error && <div className={styles.error}>{error}</div>}

      <div className={styles.entityList}>
        {tab === "threat_actor" && (
          actors.length === 0 ? (
            <div className={styles.empty}>No threat actors found</div>
          ) : (
            actors.map((actor) => (
              <button
                key={actor.id}
                className={styles.entityItem}
                onClick={() => handleAddToActor(actor)}
                disabled={isPending}
              >
                <div className={styles.entityInfo}>
                  <div className={styles.entityName}>{actor.name}</div>
                  {actor.aliases && actor.aliases.length > 0 && (
                    <div className={styles.entityAliases}>
                      aka: {actor.aliases.join(", ")}
                    </div>
                  )}
                </div>
                <span className={styles.entityMeta}>{actor.article_count} articles</span>
              </button>
            ))
          )
        )}

        {tab === "malware" && (
          malware.length === 0 ? (
            <div className={styles.empty}>No malware families found</div>
          ) : (
            malware.map((m) => (
              <button
                key={m.id}
                className={styles.entityItem}
                onClick={() => handleAddToMalware(m)}
                disabled={isPending}
              >
                <div className={styles.entityInfo}>
                  <div className={styles.entityName}>{m.name}</div>
                  {m.aliases && m.aliases.length > 0 && (
                    <div className={styles.entityAliases}>
                      aka: {m.aliases.join(", ")}
                    </div>
                  )}
                </div>
                <span className={styles.entityMeta}>{m.article_count} articles</span>
              </button>
            ))
          )
        )}

        {tab === "country" && (
          countries.length === 0 ? (
            <div className={styles.empty}>No countries found</div>
          ) : (
            countries.map((country) => (
              <button
                key={country.id}
                className={styles.entityItem}
                onClick={() => handleAddToCountry(country)}
                disabled={isPending}
              >
                <div className={styles.entityInfo}>
                  <div className={styles.entityName}>{country.name}</div>
                  {country.aliases && country.aliases.length > 0 && (
                    <div className={styles.entityAliases}>
                      aka: {country.aliases.join(", ")}
                    </div>
                  )}
                </div>
                <span className={styles.entityMeta}>{country.article_count} articles</span>
              </button>
            ))
          )
        )}

        {tab === "vendor" && (
          vendorItems.length === 0 ? (
            <div className={styles.empty}>No vendors found</div>
          ) : (
            vendorItems.map((v) => (
              <button key={v.id} className={styles.entityItem} onClick={() => handleAddToVendor(v)} disabled={isPending}>
                <div className={styles.entityInfo}>
                  <div className={styles.entityName}>{v.name}</div>
                  {v.aliases && v.aliases.length > 0 && <div className={styles.entityAliases}>aka: {v.aliases.join(", ")}</div>}
                </div>
                <span className={styles.entityMeta}>{v.article_count} articles</span>
              </button>
            ))
          )
        )}

        {tab === "product" && (
          productItems.length === 0 ? (
            <div className={styles.empty}>No products found</div>
          ) : (
            productItems.map((p) => (
              <button key={p.id} className={styles.entityItem} onClick={() => handleAddToProduct(p)} disabled={isPending}>
                <div className={styles.entityInfo}>
                  <div className={styles.entityName}>{p.name}</div>
                  {p.aliases && p.aliases.length > 0 && <div className={styles.entityAliases}>aka: {p.aliases.join(", ")}</div>}
                </div>
                <span className={styles.entityMeta}>{p.article_count} articles</span>
              </button>
            ))
          )
        )}
      </div>
    </div>
  );
}
