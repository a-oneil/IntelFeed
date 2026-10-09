import { useState, useCallback, useMemo } from "react";
import styles from "./QueryBuilder.module.css";

// ── Field definitions ────────────────────────────────────

interface FieldDef {
  key: string;
  label: string;
  category: "entry" | "entity" | "meta";
  operators: OperatorDef[];
  values?: string[]; // static enum values
  placeholder?: string;
  freeText?: boolean; // allow arbitrary text input even if values exist
}

interface OperatorDef {
  key: string;
  label: string;
  /** How to format: "field:value", "field:>value", "field:value1..value2" */
  format: (field: string, value: string, value2?: string) => string;
  needsValue?: boolean; // false for operators like "any" — default true
  needsSecondValue?: boolean; // for range operator
}

const OP_EQUALS: OperatorDef = {
  key: "eq",
  label: "is",
  format: (f, v) => (v.includes(" ") ? `${f}:"${v}"` : `${f}:${v}`),
};
const OP_CONTAINS: OperatorDef = {
  key: "contains",
  label: "contains",
  format: (f, v) => (v.includes(" ") ? `${f}:"${v}"` : `${f}:*${v}*`),
};
const OP_GT: OperatorDef = {
  key: "gt",
  label: ">",
  format: (f, v) => `${f}:>${v}`,
};
const OP_GTE: OperatorDef = {
  key: "gte",
  label: ">=",
  format: (f, v) => `${f}:>=${v}`,
};
const OP_LT: OperatorDef = {
  key: "lt",
  label: "<",
  format: (f, v) => `${f}:<${v}`,
};
const OP_LTE: OperatorDef = {
  key: "lte",
  label: "<=",
  format: (f, v) => `${f}:<=${v}`,
};
const OP_RANGE: OperatorDef = {
  key: "range",
  label: "between",
  format: (f, v, v2) => `${f}:${v}..${v2 || v}`,
  needsSecondValue: true,
};

const ENUM_OPS = [OP_EQUALS];
const TEXT_OPS = [OP_EQUALS, OP_CONTAINS];
const NUMERIC_OPS = [OP_EQUALS, OP_GT, OP_GTE, OP_LT, OP_LTE, OP_RANGE];
const DATE_OPS = [OP_GT, OP_GTE, OP_LT, OP_LTE, OP_RANGE];

const FIELDS: FieldDef[] = [
  // Entry fields
  { key: "title", label: "Title", category: "entry", operators: TEXT_OPS, placeholder: "search title..." },
  { key: "content", label: "Content", category: "entry", operators: TEXT_OPS, placeholder: "search content..." },
  { key: "author", label: "Author", category: "entry", operators: TEXT_OPS, placeholder: "author name..." },
  { key: "feed", label: "Feed", category: "entry", operators: TEXT_OPS, placeholder: "feed name...", freeText: true },
  { key: "tag", label: "Tag", category: "entry", operators: ENUM_OPS, placeholder: "tag name...", freeText: true },
  { key: "type", label: "Feed Type", category: "entry", operators: ENUM_OPS, values: ["rss", "youtube", "podcast"] },
  { key: "media", label: "Media", category: "entry", operators: ENUM_OPS, values: ["audio", "video"] },
  { key: "lang", label: "Language", category: "entry", operators: ENUM_OPS, placeholder: "en, es, fr...", freeText: true },
  { key: "date", label: "Date", category: "entry", operators: DATE_OPS, placeholder: "YYYY-MM-DD" },
  { key: "is", label: "State", category: "entry", operators: ENUM_OPS, values: ["starred", "unread", "read", "bookmarked", "noted"] },

  // Intelligence entity fields
  { key: "cve", label: "CVE", category: "entity", operators: TEXT_OPS, placeholder: "CVE-2025-..." },
  { key: "cve.severity", label: "CVE Severity", category: "entity", operators: ENUM_OPS, values: ["critical", "high", "medium", "low"] },
  { key: "cve.cvss", label: "CVSS Score", category: "entity", operators: NUMERIC_OPS, placeholder: "0.0 - 10.0" },
  { key: "ttp", label: "TTP", category: "entity", operators: TEXT_OPS, placeholder: "T1234 or technique name..." },
  { key: "ttp.tactic", label: "TTP Tactic", category: "entity", operators: ENUM_OPS, placeholder: "e.g. initial-access", freeText: true },
  { key: "threat_actor", label: "Threat Actor", category: "entity", operators: TEXT_OPS, placeholder: "APT29, Lazarus..." },
  { key: "threat_actor.country", label: "Actor Country", category: "entity", operators: ENUM_OPS, placeholder: "Russia, China...", freeText: true },
  { key: "threat_actor.sector", label: "Actor Targets Sector", category: "entity", operators: ENUM_OPS, placeholder: "healthcare, government...", freeText: true },
  { key: "malware", label: "Malware", category: "entity", operators: TEXT_OPS, placeholder: "Emotet, Cobalt Strike..." },
  { key: "malware.type", label: "Malware Type", category: "entity", operators: ENUM_OPS, placeholder: "ransomware, rat...", freeText: true },
  { key: "malware.sector", label: "Malware Targets Sector", category: "entity", operators: ENUM_OPS, placeholder: "healthcare, retail...", freeText: true },
  { key: "country", label: "Country", category: "entity", operators: TEXT_OPS, placeholder: "country name..." },
  { key: "country.region", label: "Region", category: "entity", operators: ENUM_OPS, placeholder: "Europe, Asia...", freeText: true },
  { key: "sector", label: "Targeted Sector", category: "entity", operators: TEXT_OPS, placeholder: "healthcare, banks, energy..." },
  { key: "tool", label: "Tool", category: "entity", operators: TEXT_OPS, placeholder: "Mimikatz, PsExec..." },
  { key: "tool.type", label: "Tool Type", category: "entity", operators: ENUM_OPS, placeholder: "framework, scanner...", freeText: true },
  { key: "vendor", label: "Vendor", category: "entity", operators: TEXT_OPS, placeholder: "Microsoft, Cisco..." },
  { key: "vendor.type", label: "Vendor Type", category: "entity", operators: ENUM_OPS, placeholder: "software, hardware...", freeText: true },
  { key: "product", label: "Product", category: "entity", operators: TEXT_OPS, placeholder: "Exchange, Fortigate..." },
  { key: "product.type", label: "Product Type", category: "entity", operators: ENUM_OPS, placeholder: "firewall, vpn...", freeText: true },
  { key: "mitigation", label: "Mitigation", category: "entity", operators: TEXT_OPS, placeholder: "M1234 or name..." },
  { key: "campaign", label: "Campaign", category: "entity", operators: TEXT_OPS, placeholder: "campaign name..." },
  { key: "campaign.status", label: "Campaign Status", category: "entity", operators: ENUM_OPS, values: ["active", "monitoring", "closed", "historical"] },
  { key: "ransomware_victim", label: "Ransomware Victim", category: "entity", operators: TEXT_OPS, placeholder: "organization name..." },
  { key: "ransomware_victim.sector", label: "Victim Sector", category: "entity", operators: ENUM_OPS, placeholder: "healthcare, technology...", freeText: true },
  { key: "ransomware_victim.domain", label: "Victim Domain", category: "entity", operators: TEXT_OPS, placeholder: "example.com" },
  { key: "rule", label: "Detection Rule", category: "entity", operators: TEXT_OPS, placeholder: "rule title..." },
  { key: "rule.type", label: "Rule Format", category: "entity", operators: ENUM_OPS, values: ["sigma", "splunk_spl", "crowdstrike_ql", "elastic_ql", "kql"] },
  { key: "rule.severity", label: "Rule Severity", category: "entity", operators: ENUM_OPS, values: ["critical", "high", "medium", "low"] },
  { key: "pir", label: "Intel Requirement", category: "entity", operators: TEXT_OPS, placeholder: "requirement title..." },
  { key: "pir.priority", label: "PIR Priority", category: "entity", operators: ENUM_OPS, values: ["critical", "high", "medium", "low"] },
  { key: "pir.category", label: "PIR Category", category: "entity", operators: ENUM_OPS, values: ["strategic", "operational", "tactical"] },

  // Meta
  { key: "sort", label: "Sort By", category: "meta", operators: ENUM_OPS, values: ["newest", "oldest", "shortest", "longest", "relevance", "title_asc", "title_desc"] },
];

const FIELD_MAP = new Map(FIELDS.map((f) => [f.key, f]));

// ── Filter row state ─────────────────────────────────────

interface FilterRow {
  id: number;
  field: string;
  operator: string;
  value: string;
  value2: string; // for range operators
  negated: boolean;
}

let rowIdCounter = 0;
function newRow(): FilterRow {
  return { id: ++rowIdCounter, field: "", operator: "", value: "", value2: "", negated: false };
}

// ── Component ────────────────────────────────────────────

interface QueryBuilderProps {
  onApply: (query: string) => void;
  /** Current query string — used to seed text field */
  currentQuery?: string;
}

export function QueryBuilder({ onApply, currentQuery }: QueryBuilderProps) {
  const [rows, setRows] = useState<FilterRow[]>([newRow()]);
  const [joinMode, setJoinMode] = useState<"AND" | "OR">("AND");
  const [freeText, setFreeText] = useState("");

  // Group fields by category for the dropdown
  const groupedFields = useMemo(() => {
    const groups: { label: string; category: string; fields: FieldDef[] }[] = [
      { label: "Entry Filters", category: "entry", fields: [] },
      { label: "Intelligence", category: "entity", fields: [] },
      { label: "Meta", category: "meta", fields: [] },
    ];
    for (const f of FIELDS) {
      const g = groups.find((g) => g.category === f.category);
      g?.fields.push(f);
    }
    return groups.filter((g) => g.fields.length > 0);
  }, []);

  const updateRow = useCallback((id: number, patch: Partial<FilterRow>) => {
    setRows((prev) =>
      prev.map((r) => {
        if (r.id !== id) return r;
        const updated = { ...r, ...patch };
        // Reset operator/value when field changes
        if (patch.field !== undefined && patch.field !== r.field) {
          updated.operator = "";
          updated.value = "";
          updated.value2 = "";
        }
        return updated;
      }),
    );
  }, []);

  const addRow = useCallback(() => {
    setRows((prev) => [...prev, newRow()]);
  }, []);

  const removeRow = useCallback((id: number) => {
    setRows((prev) => {
      const next = prev.filter((r) => r.id !== id);
      return next.length === 0 ? [newRow()] : next;
    });
  }, []);

  const buildQuery = useCallback(() => {
    const parts: string[] = [];

    // Free text
    if (freeText.trim()) {
      parts.push(freeText.trim());
    }

    // Filter rows
    const filterParts: string[] = [];
    for (const row of rows) {
      if (!row.field || !row.value) continue;
      const fieldDef = FIELD_MAP.get(row.field);
      if (!fieldDef) continue;
      const opDef = fieldDef.operators.find((o) => o.key === row.operator) || fieldDef.operators[0];
      if (!opDef) continue;

      let fragment = opDef.format(row.field, row.value, row.value2);
      if (row.negated) fragment = `NOT ${fragment}`;
      filterParts.push(fragment);
    }

    if (filterParts.length > 0) {
      if (joinMode === "OR" && filterParts.length > 1) {
        parts.push(`(${filterParts.join(" OR ")})`);
      } else {
        parts.push(filterParts.join(" "));
      }
    }

    return parts.join(" ").trim();
  }, [rows, joinMode, freeText]);

  const handleApply = useCallback(() => {
    const q = buildQuery();
    if (q) onApply(q);
  }, [buildQuery, onApply]);

  const handleAppend = useCallback(() => {
    const q = buildQuery();
    if (q) {
      const combined = currentQuery ? `${currentQuery} ${q}` : q;
      onApply(combined.trim());
    }
  }, [buildQuery, onApply, currentQuery]);

  const preview = buildQuery();

  return (
    <div className={styles.builder}>
      <div className={styles.builderHeader}>
        <span className={styles.builderTitle}>Query Builder</span>
        <div className={styles.joinToggle}>
          <button
            className={`${styles.joinBtn} ${joinMode === "AND" ? styles.joinBtnActive : ""}`}
            onClick={() => setJoinMode("AND")}
          >
            AND
          </button>
          <button
            className={`${styles.joinBtn} ${joinMode === "OR" ? styles.joinBtnActive : ""}`}
            onClick={() => setJoinMode("OR")}
          >
            OR
          </button>
        </div>
      </div>

      {/* Free text input */}
      <div className={styles.freeTextRow}>
        <label className={styles.freeTextLabel}>Keywords</label>
        <input
          className={styles.freeTextInput}
          type="text"
          value={freeText}
          onChange={(e) => setFreeText(e.target.value)}
          placeholder="free text search terms..."
        />
      </div>

      {/* Filter rows */}
      <div className={styles.rows}>
        {rows.map((row, idx) => {
          const fieldDef = FIELD_MAP.get(row.field);
          const operators = fieldDef?.operators ?? [];
          const opDef = operators.find((o) => o.key === row.operator);
          const hasEnum = fieldDef?.values && fieldDef.values.length > 0;

          return (
            <div key={row.id} className={styles.row}>
              {idx > 0 && (
                <span className={styles.joinLabel}>{joinMode}</span>
              )}

              {/* Negate toggle */}
              <button
                className={`${styles.negateBtn} ${row.negated ? styles.negateBtnActive : ""}`}
                onClick={() => updateRow(row.id, { negated: !row.negated })}
                title="Negate (NOT)"
              >
                NOT
              </button>

              {/* Field selector */}
              <select
                className={styles.fieldSelect}
                value={row.field}
                onChange={(e) => updateRow(row.id, { field: e.target.value })}
              >
                <option value="">Field...</option>
                {groupedFields.map((group) => (
                  <optgroup key={group.category} label={group.label}>
                    {group.fields.map((f) => (
                      <option key={f.key} value={f.key}>
                        {f.label}
                      </option>
                    ))}
                  </optgroup>
                ))}
              </select>

              {/* Operator selector */}
              {row.field && operators.length > 1 && (
                <select
                  className={styles.opSelect}
                  value={row.operator || operators[0]?.key}
                  onChange={(e) => updateRow(row.id, { operator: e.target.value })}
                >
                  {operators.map((op) => (
                    <option key={op.key} value={op.key}>
                      {op.label}
                    </option>
                  ))}
                </select>
              )}

              {/* Value input */}
              {row.field && (
                <>
                  {hasEnum && !fieldDef?.freeText ? (
                    <select
                      className={styles.valueSelect}
                      value={row.value}
                      onChange={(e) => updateRow(row.id, { value: e.target.value })}
                    >
                      <option value="">Value...</option>
                      {fieldDef!.values!.map((v) => (
                        <option key={v} value={v}>
                          {v}
                        </option>
                      ))}
                    </select>
                  ) : hasEnum && fieldDef?.freeText ? (
                    <>
                      <select
                        className={styles.valueSelect}
                        value={fieldDef!.values!.includes(row.value) ? row.value : ""}
                        onChange={(e) => updateRow(row.id, { value: e.target.value })}
                      >
                        <option value="">Select or type...</option>
                        {fieldDef!.values!.map((v) => (
                          <option key={v} value={v}>
                            {v}
                          </option>
                        ))}
                      </select>
                      <input
                        className={styles.valueInput}
                        type="text"
                        value={fieldDef!.values!.includes(row.value) ? "" : row.value}
                        onChange={(e) => updateRow(row.id, { value: e.target.value })}
                        placeholder={fieldDef?.placeholder || "or type value..."}
                      />
                    </>
                  ) : (
                    <input
                      className={styles.valueInput}
                      type={row.field === "date" ? "date" : "text"}
                      value={row.value}
                      onChange={(e) => updateRow(row.id, { value: e.target.value })}
                      placeholder={fieldDef?.placeholder || "value..."}
                    />
                  )}

                  {/* Second value for range */}
                  {opDef?.needsSecondValue && (
                    <>
                      <span className={styles.rangeSep}>to</span>
                      <input
                        className={styles.valueInput}
                        type={row.field === "date" ? "date" : "text"}
                        value={row.value2}
                        onChange={(e) => updateRow(row.id, { value2: e.target.value })}
                        placeholder={fieldDef?.placeholder || "value..."}
                      />
                    </>
                  )}
                </>
              )}

              {/* Remove row */}
              <button
                className={styles.removeBtn}
                onClick={() => removeRow(row.id)}
                title="Remove filter"
              >
                &times;
              </button>
            </div>
          );
        })}
      </div>

      {/* Add row + actions */}
      <div className={styles.builderFooter}>
        <button className={styles.addRowBtn} onClick={addRow}>
          + Add Filter
        </button>

        <div className={styles.builderActions}>
          {preview && (
            <code className={styles.preview}>{preview}</code>
          )}
          {currentQuery && (
            <button className={styles.appendBtn} onClick={handleAppend} disabled={!preview}>
              Append
            </button>
          )}
          <button className={styles.applyBtn} onClick={handleApply} disabled={!preview}>
            Search
          </button>
        </div>
      </div>
    </div>
  );
}
