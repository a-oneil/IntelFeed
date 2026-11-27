/** The analyst's preferred query language, the one setting every place that writes a query or detection logic for them reads. Mirrors backend/app/ai/query_language.py: ids, names and the library rule format a language maps onto, when one exists. */
export type QueryLanguage =
  | "kql"
  | "spl"
  | "esql"
  | "eql"
  | "cql"
  | "yaral"
  | "aql"
  | "sumo"
  | "sql"
  | "panther"
  | "sigma";

export interface QueryLanguageOption {
  value: QueryLanguage;
  label: string;
  short: string;
  /** The detection-rule format this language is stored as. ES|QL and EQL share `elastic_ql`; the rest map one to one. */
  ruleType: string | null;
}

export const QUERY_LANGUAGES: QueryLanguageOption[] = [
  { value: "kql", label: "KQL (Microsoft Sentinel / Defender XDR)", short: "KQL", ruleType: "kql" },
  { value: "spl", label: "SPL (Splunk)", short: "SPL", ruleType: "splunk_spl" },
  { value: "esql", label: "ES|QL (Elastic)", short: "ES|QL", ruleType: "elastic_ql" },
  { value: "eql", label: "EQL (Elastic)", short: "EQL", ruleType: "elastic_ql" },
  { value: "cql", label: "CQL (CrowdStrike Falcon / LogScale)", short: "CQL", ruleType: "crowdstrike_ql" },
  { value: "yaral", label: "YARA-L (Google SecOps, Chronicle)", short: "YARA-L", ruleType: "yaral" },
  { value: "aql", label: "AQL (IBM QRadar)", short: "AQL", ruleType: "aql" },
  { value: "sumo", label: "Sumo Logic search", short: "Sumo", ruleType: "sumo" },
  { value: "sql", label: "SQL (data lake: Athena, Snowflake, BigQuery)", short: "SQL", ruleType: "sql" },
  { value: "panther", label: "Panther (Python detections)", short: "Panther", ruleType: "panther" },
  { value: "sigma", label: "Sigma (vendor-neutral)", short: "Sigma", ruleType: "sigma" },
];

export const DEFAULT_QUERY_LANGUAGE: QueryLanguage = "kql";

const BY_ID = new Map(QUERY_LANGUAGES.map((q) => [q.value, q]));

export function isQueryLanguage(v: unknown): v is QueryLanguage {
  return typeof v === "string" && BY_ID.has(v as QueryLanguage);
}

export function queryLanguageShort(id: string | null | undefined): string {
  return (id && BY_ID.get(id as QueryLanguage)?.short) || "query";
}

/** Rule formats to generate when nothing was chosen: Sigma, which converts everywhere, plus the preferred language's own format when the library has one. Same rule as the backend (`default_rule_types`). */
export function defaultRuleTypes(lang: QueryLanguage): string[] {
  const own = BY_ID.get(lang)?.ruleType ?? null;
  return own && own !== "sigma" ? ["sigma", own] : ["sigma"];
}
