import { useState } from "react";
import { useNavigate } from "react-router-dom";
import type { AxiosError } from "axios";
import {
  useCreateThreatActor,
  useCreateMalware,
  useCreateCVE,
  useCreateTTP,
  useCreateCountry,
  useCreateMitigation,
  useCreateOffensiveTool,
  useCreateVendor,
  useCreateProduct,
} from "@/hooks/useIntelligence";
import styles from "./CreateEntityPanel.module.css";

/** The types an analyst can create by hand.
 *
 * Deliberately narrower than the platform's EntityType: `cwe` is absent because
 * weaknesses come from the seeded MITRE catalog, so a hand-made one would be
 * either a duplicate or an id that does not exist. */
export type CreatableEntityType =
  | "threat_actor"
  | "malware"
  | "cve"
  | "ttp"
  | "country"
  | "mitigation"
  | "tool"
  | "vendor"
  | "product";

const CREATABLE_TYPES: readonly string[] = [
  "threat_actor",
  "malware",
  "cve",
  "ttp",
  "country",
  "mitigation",
  "tool",
  "vendor",
  "product",
];

export function isCreatableEntityType(value: string | null | undefined): value is CreatableEntityType {
  return !!value && CREATABLE_TYPES.includes(value);
}

type EntityType = CreatableEntityType;

const ENTITY_TABS: { key: EntityType; label: string }[] = [
  { key: "threat_actor", label: "Threat Actor" },
  { key: "malware", label: "Malware" },
  { key: "cve", label: "CVE" },
  { key: "ttp", label: "TTP" },
  { key: "country", label: "Country" },
  { key: "mitigation", label: "Mitigation" },
  { key: "tool", label: "Tool" },
  { key: "vendor", label: "Vendor" },
  { key: "product", label: "Product" },
];

// Mirrors the backend controlled vocabularies (models/malware_family.py MALWARE_TYPES,
// models/tool.py TOOL_TYPES) — free text is coerced server-side regardless.
const MALWARE_TYPES = ["ransomware", "stealer", "loader", "backdoor", "rat", "trojan", "banking_trojan", "botnet", "worm", "wiper", "spyware", "rootkit", "dropper", "downloader", "miner", "keylogger", "webshell", "exploit_kit", "phishing_kit", "implant", "adware", "other"];
const MOTIVATIONS = ["financial", "espionage", "hacktivism", "sabotage", "unknown"];
const CVE_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];
const EXPLOIT_AVAILABILITY = ["none", "poc", "weaponized", "active_exploitation"];
const TOOL_TYPES = ["c2_framework", "credential_access", "lateral_movement", "reconnaissance", "exploitation", "persistence", "defense_evasion", "lolbas", "framework", "phishing_kit", "tunneling", "remote_access", "ai_model", "defensive", "observability", "cloud", "identity", "dev_tool", "service", "software", "other"];
const VENDOR_TYPES = ["software", "hardware", "cloud", "security", "networking", "semiconductor", "telecommunications", "other"];
const PRODUCT_TYPES = ["os", "application", "security_tool", "network_device", "cloud_service", "database", "firmware", "library", "other"];
const TACTICS = [
  "reconnaissance", "resource-development", "initial-access", "execution",
  "persistence", "privilege-escalation", "defense-evasion", "credential-access",
  "discovery", "lateral-movement", "collection", "command-and-control",
  "exfiltration", "impact",
];

interface CreateEntityPanelProps {
  entryId?: string;
  initialText?: string;
  /** Preselects the type tab — the table header that opened this already knows it. */
  initialType?: EntityType;
  onClose: () => void;
  onCreated?: (entityType: EntityType, entityId: string) => void;
}

export function CreateEntityPanel({ entryId, initialText, initialType, onClose, onCreated }: CreateEntityPanelProps) {
  const navigate = useNavigate();
  const [entityType, setEntityType] = useState<EntityType>(initialType ?? "threat_actor");

  // Shared fields
  const [name, setName] = useState(initialText || "");
  const [description, setDescription] = useState("");
  const [aliases, setAliases] = useState("");
  const [error, setError] = useState<string | null>(null);
  // Entity-guardrails rejection (409 entity_creation_gated) — offers the
  // logged "create anyway" retry with force=true.
  const [gateWarning, setGateWarning] = useState<string | null>(null);

  // Threat actor fields
  const [country, setCountry] = useState("");
  const [motivation, setMotivation] = useState("unknown");

  // Malware fields
  const [malwareType, setMalwareType] = useState("other");

  // CVE fields
  const [cveId, setCveId] = useState("");
  const [severity, setSeverity] = useState("");
  const [cvssScore, setCvssScore] = useState("");
  const [exploitStatus, setExploitStatus] = useState("");
  const [exploitAvailability, setExploitAvailability] = useState("");

  // TTP fields
  const [techniqueId, setTechniqueId] = useState("");
  const [techniqueName, setTechniqueName] = useState("");
  const [tactic, setTactic] = useState("");

  // Country fields
  const [isoCode, setIsoCode] = useState("");
  const [region, setRegion] = useState("");

  // Mitigation fields
  const [mitreId, setMitreId] = useState("");

  // Tool fields
  const [toolType, setToolType] = useState("");
  const [githubUrl, setGithubUrl] = useState("");

  // Vendor fields
  const [vendorType, setVendorType] = useState("");
  const [website, setWebsite] = useState("");

  // Product fields
  const [productType, setProductType] = useState("");

  const createActor = useCreateThreatActor();
  const createMalware = useCreateMalware();
  const createCVE = useCreateCVE();
  const createTTP = useCreateTTP();
  const createCountry = useCreateCountry();
  const createMitigation = useCreateMitigation();
  const createTool = useCreateOffensiveTool();
  const createVendor = useCreateVendor();
  const createProduct = useCreateProduct();

  const isPending =
    createActor.isPending || createMalware.isPending ||
    createCVE.isPending || createTTP.isPending || createCountry.isPending ||
    createMitigation.isPending || createTool.isPending ||
    createVendor.isPending || createProduct.isPending;

  const handleEntityTypeChange = (t: EntityType) => {
    setEntityType(t);
    setError(null);
    setGateWarning(null);
  };

  const handleSubmit = async (force = false) => {
    setError(null);
    if (!force) setGateWarning(null);
    try {
      if (entityType === "threat_actor") {
        if (!name.trim()) { setError("Name is required"); return; }
        const result = await createActor.mutateAsync({
          name: name.trim(),
          description: description || undefined,
          aliases: aliases ? aliases.split(",").map((a) => a.trim()).filter(Boolean) : undefined,
          country: country || undefined,
          motivation: motivation || undefined,
          entry_id: entryId || undefined,
          force: force || undefined,
        });
        onCreated?.("threat_actor", result.id);
        navigate(`/workbench/threat_actor/${result.id}`);
      } else if (entityType === "malware") {
        if (!name.trim()) { setError("Name is required"); return; }
        const result = await createMalware.mutateAsync({
          name: name.trim(),
          description: description || undefined,
          aliases: aliases ? aliases.split(",").map((a) => a.trim()).filter(Boolean) : undefined,
          malware_type: malwareType || undefined,
          entry_id: entryId || undefined,
          force: force || undefined,
        });
        onCreated?.("malware", result.id);
        navigate(`/workbench/malware/${result.id}`);
      } else if (entityType === "cve") {
        if (!cveId.trim()) { setError("CVE ID is required"); return; }
        const result = await createCVE.mutateAsync({
          cve_id: cveId.trim(),
          description: description || undefined,
          severity: severity || undefined,
          cvss_score: cvssScore ? parseFloat(cvssScore) : undefined,
          exploit_status: exploitStatus || undefined,
          exploit_availability: exploitAvailability || undefined,
          entry_id: entryId || undefined,
        });
        onCreated?.("cve", result.id);
        navigate(`/workbench/cve/${result.id}`);
      } else if (entityType === "ttp") {
        if (!techniqueId.trim()) { setError("Technique ID is required"); return; }
        if (!techniqueName.trim()) { setError("Technique Name is required"); return; }
        const result = await createTTP.mutateAsync({
          technique_id: techniqueId.trim(),
          technique_name: techniqueName.trim(),
          tactic: tactic || undefined,
          description: description || undefined,
          entry_id: entryId || undefined,
        });
        onCreated?.("ttp", result.id);
        navigate(`/workbench/ttp/${result.id}`);
      } else if (entityType === "country") {
        if (!name.trim()) { setError("Name is required"); return; }
        const result = await createCountry.mutateAsync({
          name: name.trim(),
          iso_code: isoCode || undefined,
          aliases: aliases ? aliases.split(",").map((a) => a.trim()).filter(Boolean) : undefined,
          region: region || undefined,
          description: description || undefined,
          entry_id: entryId || undefined,
        });
        onCreated?.("country", result.id);
        navigate(`/workbench/country/${result.id}`);
      } else if (entityType === "mitigation") {
        if (!name.trim()) { setError("Name is required"); return; }
        const result = await createMitigation.mutateAsync({
          name: name.trim(),
          mitre_id: mitreId || undefined,
          description: description || undefined,
          entry_id: entryId || undefined,
        });
        onCreated?.("mitigation", result.id);
        navigate(`/workbench/mitigation/${result.id}`);
      } else if (entityType === "tool") {
        if (!name.trim()) { setError("Name is required"); return; }
        const result = await createTool.mutateAsync({
          name: name.trim(),
          aliases: aliases ? aliases.split(",").map((a) => a.trim()).filter(Boolean) : undefined,
          description: description || undefined,
          tool_type: toolType || undefined,
          github_url: githubUrl || undefined,
          entry_id: entryId || undefined,
          force: force || undefined,
        });
        onCreated?.("tool", result.id);
        navigate(`/workbench/tool/${result.id}`);
      } else if (entityType === "vendor") {
        if (!name.trim()) { setError("Name is required"); return; }
        const result = await createVendor.mutateAsync({
          name: name.trim(),
          aliases: aliases ? aliases.split(",").map((a) => a.trim()).filter(Boolean) : undefined,
          description: description || undefined,
          vendor_type: vendorType || undefined,
          website: website || undefined,
          entry_id: entryId || undefined,
          force: force || undefined,
        });
        onCreated?.("vendor", result.id);
        navigate(`/workbench/vendor/${result.id}`);
      } else if (entityType === "product") {
        if (!name.trim()) { setError("Name is required"); return; }
        const result = await createProduct.mutateAsync({
          name: name.trim(),
          aliases: aliases ? aliases.split(",").map((a) => a.trim()).filter(Boolean) : undefined,
          description: description || undefined,
          product_type: productType || undefined,
          website: website || undefined,
          entry_id: entryId || undefined,
          force: force || undefined,
        });
        onCreated?.("product", result.id);
        navigate(`/workbench/product/${result.id}`);
      }
      onClose();
    } catch (e: unknown) {
      const apiError = (e as AxiosError<{ error?: { code?: string; message?: string } }>).response?.data?.error;
      if (apiError?.code === "entity_creation_gated") {
        setGateWarning(apiError.message || "Creation was rejected by the entity guardrails.");
        return;
      }
      const msg = apiError?.message || (e instanceof Error ? e.message : "Failed to create entity");
      setError(msg);
    }
  };

  return (
    <div className={styles.panel}>
      <div className={styles.typeTabs}>
        {ENTITY_TABS.map((t) => (
          <button
            key={t.key}
            className={`${styles.typeTab} ${entityType === t.key ? styles.typeTabActive : ""}`}
            onClick={() => handleEntityTypeChange(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className={styles.form}>
        {entityType === "cve" && (
          <>
            <label className={styles.label}>
              CVE ID
              <input className={styles.input} value={cveId} onChange={(e) => setCveId(e.target.value)} placeholder="e.g. CVE-2024-1234" autoFocus />
            </label>
            <label className={styles.label}>
              Severity <span className={styles.optional}>(optional)</span>
              <select className={styles.select} value={severity} onChange={(e) => setSeverity(e.target.value)}>
                <option value="">--</option>
                {CVE_SEVERITIES.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </label>
            <label className={styles.label}>
              CVSS Score <span className={styles.optional}>(optional)</span>
              <input className={styles.input} type="number" min="0" max="10" step="0.1" value={cvssScore} onChange={(e) => setCvssScore(e.target.value)} placeholder="0.0 - 10.0" />
            </label>
            <label className={styles.label}>
              Exploit Availability <span className={styles.optional}>(optional)</span>
              <select className={styles.select} value={exploitAvailability} onChange={(e) => setExploitAvailability(e.target.value)}>
                <option value="">--</option>
                {EXPLOIT_AVAILABILITY.map((ea) => (
                  <option key={ea} value={ea}>{ea.replace(/_/g, " ")}</option>
                ))}
              </select>
            </label>
            <label className={styles.label}>
              Exploit Status <span className={styles.optional}>(optional)</span>
              <input className={styles.input} value={exploitStatus} onChange={(e) => setExploitStatus(e.target.value)} placeholder="e.g. actively exploited" />
            </label>
            <label className={styles.label}>
              Description <span className={styles.optional}>(optional)</span>
              <textarea className={styles.textarea} value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />
            </label>
          </>
        )}

        {entityType === "ttp" && (
          <>
            <label className={styles.label}>
              Technique ID
              <input className={styles.input} value={techniqueId} onChange={(e) => setTechniqueId(e.target.value)} placeholder="e.g. T1059.001" autoFocus />
            </label>
            <label className={styles.label}>
              Technique Name
              <input className={styles.input} value={techniqueName} onChange={(e) => setTechniqueName(e.target.value)} placeholder="e.g. PowerShell" />
            </label>
            <label className={styles.label}>
              Tactic <span className={styles.optional}>(optional)</span>
              <select className={styles.select} value={tactic} onChange={(e) => setTactic(e.target.value)}>
                <option value="">--</option>
                {TACTICS.map((t) => (
                  <option key={t} value={t}>{t.replace(/-/g, " ")}</option>
                ))}
              </select>
            </label>
            <label className={styles.label}>
              Description <span className={styles.optional}>(optional)</span>
              <textarea className={styles.textarea} value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />
            </label>
          </>
        )}

        {entityType === "threat_actor" && (
          <>
            <label className={styles.label}>
              Name
              <input className={styles.input} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. APT29" autoFocus />
            </label>
            <label className={styles.label}>
              Aliases <span className={styles.optional}>(comma-separated)</span>
              <input className={styles.input} value={aliases} onChange={(e) => setAliases(e.target.value)} placeholder="Cozy Bear, The Dukes" />
            </label>
            <label className={styles.label}>
              Country <span className={styles.optional}>(optional)</span>
              <input className={styles.input} value={country} onChange={(e) => setCountry(e.target.value)} placeholder="e.g. Russia" />
            </label>
            <label className={styles.label}>
              Motivation
              <select className={styles.select} value={motivation} onChange={(e) => setMotivation(e.target.value)}>
                {MOTIVATIONS.map((m) => (
                  <option key={m} value={m}>{m.charAt(0).toUpperCase() + m.slice(1)}</option>
                ))}
              </select>
            </label>
            <label className={styles.label}>
              Description <span className={styles.optional}>(optional)</span>
              <textarea className={styles.textarea} value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />
            </label>
          </>
        )}

        {entityType === "malware" && (
          <>
            <label className={styles.label}>
              Name
              <input className={styles.input} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Cobalt Strike" autoFocus />
            </label>
            <label className={styles.label}>
              Aliases <span className={styles.optional}>(comma-separated)</span>
              <input className={styles.input} value={aliases} onChange={(e) => setAliases(e.target.value)} placeholder="Alias1, Alias2" />
            </label>
            <label className={styles.label}>
              Type
              <select className={styles.select} value={malwareType} onChange={(e) => setMalwareType(e.target.value)}>
                {MALWARE_TYPES.map((t) => (
                  <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>
                ))}
              </select>
            </label>
            <label className={styles.label}>
              Description <span className={styles.optional}>(optional)</span>
              <textarea className={styles.textarea} value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />
            </label>
          </>
        )}

        {entityType === "country" && (
          <>
            <label className={styles.label}>
              Name
              <input className={styles.input} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. China" autoFocus />
            </label>
            <label className={styles.label}>
              ISO Code <span className={styles.optional}>(optional)</span>
              <input className={styles.input} value={isoCode} onChange={(e) => setIsoCode(e.target.value)} placeholder="e.g. CHN" />
            </label>
            <label className={styles.label}>
              Aliases <span className={styles.optional}>(comma-separated)</span>
              <input className={styles.input} value={aliases} onChange={(e) => setAliases(e.target.value)} placeholder="PRC, People's Republic of China" />
            </label>
            <label className={styles.label}>
              Region <span className={styles.optional}>(optional)</span>
              <input className={styles.input} value={region} onChange={(e) => setRegion(e.target.value)} placeholder="e.g. East Asia" />
            </label>
            <label className={styles.label}>
              Description <span className={styles.optional}>(optional)</span>
              <textarea className={styles.textarea} value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />
            </label>
          </>
        )}

        {entityType === "mitigation" && (
          <>
            <label className={styles.label}>
              Name
              <input className={styles.input} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Network Segmentation" autoFocus />
            </label>
            <label className={styles.label}>
              MITRE ID <span className={styles.optional}>(optional)</span>
              <input className={styles.input} value={mitreId} onChange={(e) => setMitreId(e.target.value)} placeholder="e.g. M1030" />
            </label>
            <label className={styles.label}>
              Description <span className={styles.optional}>(optional)</span>
              <textarea className={styles.textarea} value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />
            </label>
          </>
        )}

        {entityType === "tool" && (
          <>
            <label className={styles.label}>
              Name
              <input className={styles.input} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Mimikatz" autoFocus />
            </label>
            <label className={styles.label}>
              Aliases <span className={styles.optional}>(comma-separated)</span>
              <input className={styles.input} value={aliases} onChange={(e) => setAliases(e.target.value)} placeholder="Alias1, Alias2" />
            </label>
            <label className={styles.label}>
              Tool Type <span className={styles.optional}>(optional)</span>
              <select className={styles.select} value={toolType} onChange={(e) => setToolType(e.target.value)}>
                <option value="">--</option>
                {TOOL_TYPES.map((t) => (
                  <option key={t} value={t}>{t.replace(/_/g, " ")}</option>
                ))}
              </select>
            </label>
            <label className={styles.label}>
              GitHub URL <span className={styles.optional}>(optional)</span>
              <input className={styles.input} value={githubUrl} onChange={(e) => setGithubUrl(e.target.value)} placeholder="https://github.com/..." />
            </label>
            <label className={styles.label}>
              Description <span className={styles.optional}>(optional)</span>
              <textarea className={styles.textarea} value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />
            </label>
          </>
        )}

        {entityType === "vendor" && (
          <>
            <label className={styles.label}>
              Name
              <input className={styles.input} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Microsoft" autoFocus />
            </label>
            <label className={styles.label}>
              Aliases <span className={styles.optional}>(comma-separated)</span>
              <input className={styles.input} value={aliases} onChange={(e) => setAliases(e.target.value)} placeholder="Alias1, Alias2" />
            </label>
            <label className={styles.label}>
              Vendor Type <span className={styles.optional}>(optional)</span>
              <select className={styles.select} value={vendorType} onChange={(e) => setVendorType(e.target.value)}>
                <option value="">--</option>
                {VENDOR_TYPES.map((t) => (
                  <option key={t} value={t}>{t.replace(/_/g, " ")}</option>
                ))}
              </select>
            </label>
            <label className={styles.label}>
              Website <span className={styles.optional}>(optional)</span>
              <input className={styles.input} value={website} onChange={(e) => setWebsite(e.target.value)} placeholder="https://..." />
            </label>
            <label className={styles.label}>
              Description <span className={styles.optional}>(optional)</span>
              <textarea className={styles.textarea} value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />
            </label>
          </>
        )}

        {entityType === "product" && (
          <>
            <label className={styles.label}>
              Name
              <input className={styles.input} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Microsoft 365" autoFocus />
            </label>
            <label className={styles.label}>
              Aliases <span className={styles.optional}>(comma-separated)</span>
              <input className={styles.input} value={aliases} onChange={(e) => setAliases(e.target.value)} placeholder="Alias1, Alias2" />
            </label>
            <label className={styles.label}>
              Product Type <span className={styles.optional}>(optional)</span>
              <select className={styles.select} value={productType} onChange={(e) => setProductType(e.target.value)}>
                <option value="">--</option>
                {PRODUCT_TYPES.map((t) => (
                  <option key={t} value={t}>{t.replace(/_/g, " ")}</option>
                ))}
              </select>
            </label>
            <label className={styles.label}>
              Website <span className={styles.optional}>(optional)</span>
              <input className={styles.input} value={website} onChange={(e) => setWebsite(e.target.value)} placeholder="https://..." />
            </label>
            <label className={styles.label}>
              Description <span className={styles.optional}>(optional)</span>
              <textarea className={styles.textarea} value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />
            </label>
          </>
        )}

        {gateWarning && (
          <div className={styles.gateWarning}>
            <span>{gateWarning}</span>
            <button className={styles.forceBtn} onClick={() => handleSubmit(true)} disabled={isPending}>
              Create anyway
            </button>
          </div>
        )}
        {error && <div className={styles.error}>{error}</div>}

        <div className={styles.actions}>
          <button className={styles.cancelBtn} onClick={onClose} disabled={isPending}>
            Cancel
          </button>
          <button className={styles.submitBtn} onClick={() => handleSubmit()} disabled={isPending}>
            {isPending ? "Creating..." : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}
