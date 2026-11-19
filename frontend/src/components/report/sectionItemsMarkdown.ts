/**
 * A data section's rows as Markdown — the same shapes the backend exporter
 * writes (`render_markdown` in app/intelligence/reporting.py), so what the
 * analyst sees in the editor is what the export would have said. Editing it
 * turns the rows into hand-written text: the saved body replaces the rows.
 */

const cell = (v: unknown): string => (Array.isArray(v) ? v.join(", ") : v == null ? "" : String(v));

function table(header: string[], rows: string[][]): string {
  const line = (cells: string[]) => `| ${cells.map((c) => c.replace(/\|/g, "\\|")).join(" | ")} |`;
  return [line(header), `|${header.map(() => "---").join("|")}|`, ...rows.map(line)].join("\n");
}

export function itemsToMarkdown(items: Record<string, unknown>[]): string {
  if (items.length === 0) return "";
  const first = items[0] || {};

  if ("kind" in first && "value" in first) {
    return table(
      ["Kind", "Value", "Confidence", "Attribution", "Last seen"],
      items.map((it) => [
        cell(it.kind),
        cell(it.value),
        typeof it.confidence === "number" ? `${Math.round(it.confidence * 100)}%` : "",
        cell(it.claimed_by),
        cell(it.last_seen),
      ]),
    );
  }
  if ("matched_regions" in first) {
    return table(
      ["Entity", "Type", "Regions", "Verticals", "Entries", "Victims"],
      items.map((it) => [
        `**${cell(it.name)}**`,
        cell(it.subtype || (it.entity_type === "threat_actor" ? "actor" : it.entity_type)),
        cell(it.matched_regions) || "—",
        cell(it.matched_sectors) || "—",
        cell(it.entry_count),
        cell(it.victim_count) || "—",
      ]),
    );
  }
  if ("rule_title" in first) {
    return table(
      ["Rule", "Format", "Source", "Licence", "ATT&CK"],
      items.map((it) => [
        `${cell(it.rule_title)}${it.is_draft ? " *(draft)*" : ""}`,
        cell(it.rule_type),
        cell(it.repo || "local"),
        cell(it.license || "unstated"),
        cell(it.techniques) || "—",
      ]),
    );
  }
  return items
    .map((it) => {
      if ("technique_id" in it) return `- **${cell(it.technique_id)}** ${cell(it.name)} (${cell(it.tactic) || "N/A"})`;
      if ("url" in it && "title" in it) return `- [${cell(it.title) || cell(it.url)}](${cell(it.url)})`;
      if ("date" in it && "title" in it) return `- **${cell(it.date).slice(0, 10) || "Unknown"}**: ${cell(it.title)}`;
      if ("cve_id" in it) {
        return `- **${cell(it.cve_id)}** (Severity: ${cell(it.severity) || "N/A"}, CVSS: ${cell(it.cvss_score) || "N/A"})`;
      }
      if ("name" in it && "aliases" in it) {
        const aliases = cell(it.aliases);
        return `- **${cell(it.name)}**${aliases ? ` (aliases: ${aliases})` : ""}`;
      }
      if ("name" in it && "malware_type" in it) return `- **${cell(it.name)}** (${cell(it.malware_type) || "Unknown"})`;
      return `- ${cell(it.name) || JSON.stringify(it)}`;
    })
    .join("\n");
}

/** What a data section's editor opens with: its written body, then its rows. */
export function dataSectionText(body: string, items: Record<string, unknown>[]): string {
  const rows = itemsToMarkdown(items);
  return [body.trim(), rows].filter(Boolean).join("\n\n");
}
