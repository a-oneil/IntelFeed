import { useNavigate } from "react-router-dom";
import api from "@/api/client";
import { useIntelStore } from "@/stores/intelStore";
import { Chip } from "@/components/primitives";
import styles from "./RuleEntryCard.module.css";

interface RuleMetadata {
  content_type?: string;
  owner?: string;
  repo?: string;
  file_path?: string;
  commit_sha?: string;
  change_type?: string;
  extracted?: {
    rule_title?: string;
    rule_name?: string;
    template_name?: string;
    rule_level?: string;
    rule_severity?: string;
    template_severity?: string;
    rule_description?: string;
    template_description?: string;
    mitre_attack_ids?: string[];
    mitre_tactics?: string[];
    cve_ids?: string[];
    rule_status?: string;
    rule_author?: string;
    template_author?: string;
    technique_id?: string;
    supported_platforms?: string[];
    binary_name?: string;
    atomic_tests?: { name: string; executor_type: string }[];
    rule_references?: string[];
    logsource_category?: string;
    logsource_product?: string;
    logsource_service?: string;
  };
}

const CONTENT_TYPE_LABELS: Record<string, string> = {
  sigma_rule: "SIGMA",
  elastic_rule: "ELASTIC",
  splunk_detection: "SPLUNK",
  sentinel_rule: "SENTINEL",
  yara_rule: "YARA",
  lolbas_entry: "LOLBAS",
  loobin_entry: "LOOBin",
  loldriver_entry: "LOLDriver",
  atomic_test: "ATOMIC",
  nuclei_template: "NUCLEI",
  kql_query: "KQL",
  anvilogic_rule: "ANVILOGIC",
};

/* Raw hexes with no design token behind them — a rule's own severity scale,
   not an entity colour, so they stay literal and ride in as the Chip tint. */
const SEVERITY_TINTS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#2563eb",
  informational: "#6b7280",
  info: "#6b7280",
};

const CHANGE_TYPE_LABELS: Record<string, string> = {
  added: "New",
  modified: "Modified",
  removed: "Removed",
};

interface Props {
  metadata: Record<string, unknown>;
}

export function RuleEntryCard({ metadata }: Props) {
  const navigate = useNavigate();
  const selectEntity = useIntelStore((s) => s.selectEntity);
  const meta = metadata as unknown as RuleMetadata;

  if (!meta?.content_type || !CONTENT_TYPE_LABELS[meta.content_type]) {
    return null;
  }

  const extracted = meta.extracted || {};
  const contentType = meta.content_type;
  const label = CONTENT_TYPE_LABELS[contentType];
  const severity = extracted.rule_level || extracted.rule_severity || extracted.template_severity;
  const severityTint = severity ? SEVERITY_TINTS[severity.toLowerCase()] : undefined;
  const techniques = extracted.mitre_attack_ids || [];
  const tactics = extracted.mitre_tactics || [];
  const cves = extracted.cve_ids || [];
  const changeType = meta.change_type;
  const author = extracted.rule_author || extracted.template_author;
  const status = extracted.rule_status;
  const platforms = extracted.supported_platforms || [];
  const description = extracted.rule_description || extracted.template_description;
  const binaryName = extracted.binary_name;
  const logsource = [
    extracted.logsource_product,
    extracted.logsource_category,
    extracted.logsource_service,
  ].filter(Boolean).join(" / ");
  const owner = meta.owner;
  const repo = meta.repo;
  const filePath = meta.file_path;
  const commitSha = meta.commit_sha;

  const githubUrl = owner && repo && filePath && commitSha
    ? `https://github.com/${owner}/${repo}/blob/${commitSha}/${filePath}`
    : null;

  const handleTechniqueClick = async (tid: string) => {
    try {
      const { data } = await api.get(`/ttps/by-technique/${encodeURIComponent(tid)}`);
      if (data?.id) {
        selectEntity("ttp", data.id, tid);
        navigate("/workbench/explore");
        return;
      }
    } catch {
      // TTP not in DB yet — fall back to search
    }
    navigate(`/workbench?search=${encodeURIComponent(tid)}&type=ttp`);
  };

  const handleCveClick = async (cveId: string) => {
    try {
      const { data } = await api.get(`/cves/${encodeURIComponent(cveId)}`);
      if (data?.id) {
        selectEntity("cve", data.id, cveId);
        navigate("/workbench/explore");
        return;
      }
    } catch {
      // CVE not in DB yet — fall back to search
    }
    navigate(`/workbench?search=${encodeURIComponent(cveId)}&type=cve`);
  };

  return (
    <div className={styles.ruleCard}>
      <div className={styles.ruleHeader}>
        <Chip tone="solid" tint="var(--accent)" className={styles.ruleType}>
          {label}
        </Chip>
        {severity && (
          <Chip
            tone={severityTint ? "solid" : "default"}
            tint={severityTint}
            className={styles.severity}
          >
            {severity}
          </Chip>
        )}
        {status && status !== "test" && (
          <Chip className={styles.statusBadge}>{status}</Chip>
        )}
        {changeType && CHANGE_TYPE_LABELS[changeType] && (
          <span className={`${styles.changeType} ${styles[`change_${changeType}`] || ""}`}>
            {CHANGE_TYPE_LABELS[changeType]}
          </span>
        )}
        {author && <span className={styles.author}>{author}</span>}
        <div className={styles.spacer} />
        {githubUrl && (
          <a
            href={githubUrl}
            target="_blank"
            rel="noopener noreferrer"
            className={styles.githubLink}
          >
            View on GitHub
          </a>
        )}
      </div>

      {description && (
        <div className={styles.description}>{description}</div>
      )}

      {(logsource || binaryName || platforms.length > 0) && (
        <div className={styles.detailRow}>
          {logsource && <span className={styles.detailItem}>Log: {logsource}</span>}
          {binaryName && <span className={styles.detailItem}>Binary: {binaryName}</span>}
          {platforms.length > 0 && (
            <span className={styles.detailItem}>Platforms: {platforms.join(", ")}</span>
          )}
        </div>
      )}

      {(techniques.length > 0 || tactics.length > 0 || cves.length > 0) && (
        <div className={styles.badges}>
          {techniques.map((tid) => (
            <Chip
              key={tid}
              tone="solid"
              tint="var(--entity-ttp)"
              className={styles.techniqueBadge}
              onClick={() => handleTechniqueClick(tid)}
              title={`View profile for ${tid}`}
            >
              {tid}
            </Chip>
          ))}
          {tactics.map((tactic) => (
            <Chip key={tactic} className={styles.tacticBadge}>
              {tactic}
            </Chip>
          ))}
          {cves.map((cve) => (
            <Chip
              key={cve}
              tone="solid"
              tint="var(--entity-cve)"
              className={styles.cveBadge}
              onClick={() => handleCveClick(cve)}
              title={`View profile for ${cve}`}
            >
              {cve}
            </Chip>
          ))}
        </div>
      )}
    </div>
  );
}
