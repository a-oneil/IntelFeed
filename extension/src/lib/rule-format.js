// Guessing which rule language a block of text is written in, so the "save as
// detection rule" window can preselect it. The user can always change it, and
// the server's validator has the last word.

// The formats IntelFeed stores (RULE_TYPE_PATTERN in backend/app/schemas/intelligence.py).
export const RULE_TYPES = [
  ["sigma", "Sigma"],
  ["splunk_spl", "Splunk SPL"],
  ["kql", "KQL (Microsoft Sentinel / Defender)"],
  ["elastic_ql", "Elastic (EQL or ES|QL)"],
  ["crowdstrike_ql", "CrowdStrike query"],
  ["yara", "YARA"],
  ["snort_suricata", "Snort / Suricata"],
  ["nuclei", "Nuclei template"],
  ["yaral", "YARA-L (Google SecOps)"],
  ["aql", "AQL (QRadar)"],
  ["sumo", "Sumo Logic"],
  ["panther", "Panther"],
  ["sql", "SQL"],
];

// Short names, for rule titles.
export const SHORT_NAMES = {
  sigma: "Sigma",
  splunk_spl: "SPL",
  kql: "KQL",
  elastic_ql: "Elastic",
  crowdstrike_ql: "CrowdStrike",
  yara: "YARA",
  snort_suricata: "Snort",
  nuclei: "Nuclei",
  yaral: "YARA-L",
  aql: "AQL",
  sumo: "Sumo Logic",
  panther: "Panther",
  sql: "SQL",
};

const KQL_TABLES =
  /^\s*(DeviceProcessEvents|DeviceNetworkEvents|DeviceFileEvents|DeviceRegistryEvents|DeviceEvents|DeviceLogonEvents|DeviceImageLoadEvents|SecurityEvent|SigninLogs|AuditLogs|OfficeActivity|CommonSecurityLog|Syslog|AzureActivity|EmailEvents|IdentityLogonEvents|CloudAppEvents|AADSignInEventsBeta|Event|W3CIISLog)\b/m;

/** The likely rule type of `text`, or null when nothing fits well enough to guess. */
export function detectRuleType(text) {
  const t = String(text || "");
  if (/^\s*rule\s+\w+[\s\S]*\{[\s\S]*\bcondition\s*:/m.test(t)) return "yara";
  if (/^\s*(alert|drop|reject|pass)\s+(tcp|udp|icmp|ip|http|dns|tls|smb|ftp)\s+\S+\s+\S+\s+(->|<>)\s+/m.test(t)) {
    return "snort_suricata";
  }
  if (/^\s*rule\s+\w+\s*\{[\s\S]*\bevents\s*:/m.test(t)) return "yaral";
  if (/^\s*id\s*:/m.test(t) && /^\s*info\s*:/m.test(t) && /^\s*(http|requests|dns|network|tcp|file|code)\s*:/m.test(t)) {
    return "nuclei";
  }
  if (/^\s*logsource\s*:/m.test(t) && /^\s*detection\s*:/m.test(t)) return "sigma";
  if (KQL_TABLES.test(t) || (/^\s*[A-Z]\w+\s*$/m.test(t.split("\n")[0]) && /^\s*\|\s*(where|project|summarize|extend)\b/m.test(t))) {
    return "kql";
  }
  if (/\b(process|network|file|registry|any|sequence)\s+where\b/i.test(t) || /^\s*FROM\s+[\w.*-]+\s*(\||$)/m.test(t)) {
    return "elastic_ql";
  }
  if (/#event_simpleName|\bevent_simpleName\s*=/.test(t)) return "crowdstrike_ql";
  if (/\b(index|sourcetype|source)\s*=/.test(t) || /^\s*\|\s*(tstats|stats|table|eval|search|rex)\b/m.test(t)) {
    return "splunk_spl";
  }
  if (/\bLOGSOURCENAME\s*\(|\bFROM\s+events\b/i.test(t)) return "aql";
  if (/^\s*_sourceCategory\s*=/m.test(t)) return "sumo";
  if (/^\s*def\s+rule\s*\(\s*event\s*\)/m.test(t)) return "panther";
  if (/^\s*SELECT\b[\s\S]+\bFROM\b/im.test(t)) return "sql";
  return null;
}
