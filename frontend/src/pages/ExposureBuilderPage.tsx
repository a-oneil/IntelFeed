import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import api from "@/api/client";
import { PageHeader } from "@/components/primitives/PageHeader";
import { Chip } from "@/components/primitives";
import {
  useIntelProfiles,
  useCreateIntelProfile,
  useProfileThreatSurface,
  useSectorVocabulary,
} from "@/hooks/useIntelProfiles";
import { useGenerateExposureReport } from "@/hooks/useIntelReports";
import type { Country, PaginatedResponse, ThreatSurfaceItem } from "@/api/types";
import styles from "./ExposureBuilderPage.module.css";

/**
 * Threat Exposure Report builder: pick (or create) an intel profile — a named
 * regions × verticals scope — then curate the matched threat surface with
 * keep/drop before the report draft is generated. The platform is
 * enterprise-agnostic: profiles are plural (per customer, portfolio, or watch
 * area), never "the org".
 */
export function ExposureBuilderPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { data: profiles } = useIntelProfiles();
  const [profileId, setProfileId] = useState<string | null>(params.get("profile"));
  const [creating, setCreating] = useState(false);

  const selected = profiles?.find((p) => p.id === profileId) ?? null;

  return (
    <div className={styles.page}>
      <PageHeader
        title="Threat Exposure Report"
        subtitle="Pick a scope — regions × verticals — and curate who the corpus says is active against it."
      />
      <div className={styles.body}>
        <section className={styles.scopeRow}>
          <span className={styles.label}>Intel profile</span>
          <select
            className={styles.select}
            value={profileId ?? ""}
            onChange={(e) => {
              setCreating(false);
              setProfileId(e.target.value || null);
            }}
          >
            <option value="">Choose a profile…</option>
            {(profiles ?? []).map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
          <button className={styles.ghostBtn} onClick={() => { setProfileId(null); setCreating(true); }}>
            + New profile
          </button>
          {selected && (
            <span className={styles.scopeChips}>
              {selected.countries.map((c) => (
                <Chip key={c.id} tint="var(--entity-country)">{c.name}</Chip>
              ))}
              {selected.sector_labels.map((s) => (
                <Chip key={s} tint="var(--entity-sector)">{s}</Chip>
              ))}
              <Chip>last {selected.window_days}d</Chip>
            </span>
          )}
        </section>

        {creating && (
          <ProfileForm
            onCreated={(id) => {
              setCreating(false);
              setProfileId(id);
            }}
            onCancel={() => setCreating(false)}
          />
        )}

        {selected && <SurfaceStep profileId={selected.id} profileName={selected.name} onDone={(reportId) => navigate(`/workbench/report/${reportId}`)} />}

        {!selected && !creating && (
          <p className={styles.empty}>
            A profile is a saved scope you report against — one per customer, portfolio, or watch
            area. Choose one above or create your first.
          </p>
        )}
      </div>
    </div>
  );
}

function ProfileForm({ onCreated, onCancel }: { onCreated: (id: string) => void; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [windowDays, setWindowDays] = useState(90);
  const [countrySearch, setCountrySearch] = useState("");
  const [countries, setCountries] = useState<{ id: string; name: string }[]>([]);
  const [sectors, setSectors] = useState<string[]>([]);
  const { data: vocabulary } = useSectorVocabulary();
  const createProfile = useCreateIntelProfile();

  const { data: countryOptions } = useQuery({
    queryKey: ["country-picker", countrySearch],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<Country>>("/countries", {
        params: { search: countrySearch || undefined, limit: 8, sort_by: "article_count" },
      });
      return data.items;
    },
    enabled: countrySearch.length >= 2,
  });

  const submit = async () => {
    if (!name.trim()) {
      toast.error("Give the profile a name");
      return;
    }
    try {
      const profile = await createProfile.mutateAsync({
        name: name.trim(),
        country_ids: countries.map((c) => c.id),
        sectors,
        window_days: windowDays,
      });
      toast.success(`Profile "${profile.name}" saved`);
      onCreated(profile.id);
    } catch {
      /* interceptor toasts */
    }
  };

  return (
    <section className={styles.formCard}>
      <div className={styles.formRow}>
        <label className={styles.label} htmlFor="profile-name">Name</label>
        <input
          id="profile-name"
          className={styles.input}
          placeholder="e.g. FinServ & Healthcare portfolio"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <label className={styles.label} htmlFor="profile-window">Window</label>
        <select
          id="profile-window"
          className={styles.select}
          value={windowDays}
          onChange={(e) => setWindowDays(Number(e.target.value))}
        >
          <option value={30}>30 days</option>
          <option value={90}>90 days</option>
          <option value={180}>180 days</option>
          <option value={365}>1 year</option>
        </select>
      </div>

      <div className={styles.formRow}>
        <span className={styles.label}>Regions</span>
        <span className={styles.picked}>
          {countries.map((c) => (
            <button
              key={c.id}
              className={styles.pickedChip}
              title="Remove"
              onClick={() => setCountries((prev) => prev.filter((x) => x.id !== c.id))}
            >
              {c.name} ×
            </button>
          ))}
        </span>
        <span className={styles.pickerWrap}>
          <input
            className={styles.input}
            placeholder="Search countries…"
            value={countrySearch}
            onChange={(e) => setCountrySearch(e.target.value)}
          />
          {countrySearch.length >= 2 && (countryOptions?.length ?? 0) > 0 && (
            <span className={styles.pickerMenu}>
              {countryOptions!
                .filter((o) => !countries.some((c) => c.id === o.id))
                .map((o) => (
                  <button
                    key={o.id}
                    className={styles.pickerItem}
                    onClick={() => {
                      setCountries((prev) => [...prev, { id: o.id, name: o.name }]);
                      setCountrySearch("");
                    }}
                  >
                    {o.name}
                  </button>
                ))}
            </span>
          )}
        </span>
      </div>

      <div className={styles.formRow}>
        <span className={styles.label}>Verticals</span>
        <span className={styles.sectorGrid}>
          {(vocabulary ?? []).map((s) => {
            const on = sectors.includes(s.slug);
            return (
              <button
                key={s.slug}
                className={`${styles.sectorChip} ${on ? styles.sectorChipOn : ""}`}
                aria-pressed={on}
                onClick={() =>
                  setSectors((prev) => (on ? prev.filter((x) => x !== s.slug) : [...prev, s.slug]))
                }
              >
                {s.label}
              </button>
            );
          })}
        </span>
      </div>

      <div className={styles.formActions}>
        <button className={styles.ghostBtn} onClick={onCancel}>Cancel</button>
        <button className={styles.primaryBtn} onClick={submit} disabled={createProfile.isPending}>
          {createProfile.isPending ? "Saving…" : "Save profile"}
        </button>
      </div>
    </section>
  );
}

function SurfaceStep({
  profileId,
  profileName,
  onDone,
}: {
  profileId: string;
  profileName: string;
  onDone: (reportId: string) => void;
}) {
  const { data: surface, isLoading } = useProfileThreatSurface(profileId);
  const generate = useGenerateExposureReport();
  // id -> kept? Everything matched starts kept except what the profile's
  // remembered curation dropped last issue.
  const [dropped, setDropped] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!surface) return;
    const remembered = new Set([
      ...(surface.curation?.dropped?.actors ?? []),
      ...(surface.curation?.dropped?.malware ?? []),
    ]);
    setDropped(remembered);
  }, [surface]);

  const items = useMemo(
    () => [...(surface?.actors ?? []), ...(surface?.malware ?? [])].sort((a, b) => b.score - a.score),
    [surface]
  );

  const keptCount = items.filter((i) => !dropped.has(i.id)).length;

  const createReport = async () => {
    const kept = items.filter((i) => !dropped.has(i.id));
    const droppedItems = items.filter((i) => dropped.has(i.id));
    try {
      const report = await generate.mutateAsync({
        profile_id: profileId,
        actor_ids: kept.filter((i) => i.entity_type === "threat_actor").map((i) => i.id),
        malware_ids: kept.filter((i) => i.entity_type === "malware").map((i) => i.id),
        dropped_actor_ids: droppedItems.filter((i) => i.entity_type === "threat_actor").map((i) => i.id),
        dropped_malware_ids: droppedItems.filter((i) => i.entity_type === "malware").map((i) => i.id),
      });
      toast.success("Exposure report drafted");
      onDone(report.id);
    } catch {
      /* interceptor toasts */
    }
  };

  if (isLoading) return <p className={styles.empty}>Matching the threat surface…</p>;
  if (!items.length)
    return (
      <p className={styles.empty}>
        Nothing in the corpus matches this scope inside the window. Widen the window, add regions
        or verticals, or check that country/sector extraction has run.
      </p>
    );

  return (
    <section>
      <div className={styles.surfaceHead}>
        <h2 className={styles.surfaceTitle}>Matched threat surface</h2>
        <span className={styles.surfaceCount}>
          {surface!.actors.length} actors · {surface!.malware.length} malware · last{" "}
          {surface!.window_days} days
        </span>
        <button
          className={styles.primaryBtn}
          onClick={createReport}
          disabled={generate.isPending || keptCount === 0}
        >
          {generate.isPending ? "Building…" : `Create report (${keptCount} kept)`}
        </button>
      </div>
      <div className={styles.cards}>
        {items.map((item) => (
          <SurfaceCard
            key={item.id}
            item={item}
            isDropped={dropped.has(item.id)}
            onToggle={(drop) =>
              setDropped((prev) => {
                const next = new Set(prev);
                if (drop) next.add(item.id);
                else next.delete(item.id);
                return next;
              })
            }
          />
        ))}
      </div>
      <p className={styles.footnote}>
        Keep/drop is remembered on “{profileName}” for the next issue. Partial matches (one
        dimension only) rank lower with the gap stated — you decide, not the query.
      </p>
    </section>
  );
}

function SurfaceCard({
  item,
  isDropped,
  onToggle,
}: {
  item: ThreatSurfaceItem;
  isDropped: boolean;
  onToggle: (drop: boolean) => void;
}) {
  const tint = item.entity_type === "threat_actor" ? "var(--entity-actor)" : "var(--entity-malware)";
  return (
    <div className={`${styles.card} ${isDropped ? styles.cardDropped : ""}`}>
      <div className={styles.cardRow}>
        <div className={styles.cardIdent}>
          <span className={styles.cardName} style={{ color: tint }}>
            {item.name}
          </span>
          <span className={styles.cardAlias}>
            {[item.subtype, ...(item.aliases ?? [])].filter(Boolean).slice(0, 3).join(" · ")}
          </span>
        </div>
        <div className={styles.why}>
          {item.matched_regions.length > 0 && (
            <span className={styles.whyChip}>
              regions: <b className={styles.whyRegion}>{item.matched_regions.join(", ")}</b>
              {item.region_sources.includes("claim") ? " (claimed)" : ""}
            </span>
          )}
          {item.matched_sectors.length > 0 && (
            <span className={styles.whyChip}>
              verticals: <b className={styles.whySector}>{item.matched_sectors.join(", ")}</b>
            </span>
          )}
          {item.victim_count > 0 && (
            <span className={styles.whyChip}>
              <b className={styles.whyVictim}>{item.victim_count}</b> tracked victims
            </span>
          )}
          <span className={styles.whyChip}>
            <b>{item.entry_count}</b> entries
          </span>
          {item.partial && <span className={styles.partialFlag}>partial match</span>}
        </div>
        <div className={styles.keep}>
          <button
            className={`${styles.keepBtn} ${!isDropped ? styles.keepOn : ""}`}
            onClick={() => onToggle(false)}
          >
            Keep
          </button>
          <button
            className={`${styles.keepBtn} ${isDropped ? styles.dropOn : ""}`}
            onClick={() => onToggle(true)}
          >
            Drop
          </button>
        </div>
      </div>
      {item.latest_entry && (
        <div className={styles.evidence}>
          Latest: {item.latest_entry.title}
          {item.latest_entry.published_at &&
            ` · ${new Date(item.latest_entry.published_at).toLocaleDateString()}`}
        </div>
      )}
    </div>
  );
}
