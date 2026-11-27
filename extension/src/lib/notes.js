// Saving a page as a note: on a telemetry source, on an entity, or as a note of its own. No browser APIs.

const NOTE_KINDS = ["telemetry", "entity", "note"];

// The entity types an entity note can be on (EntityNoteCreate's pattern), in the order the search lists them.
export const NOTE_ENTITY_TYPES = [
  "threat_actor",
  "malware",
  "tool",
  "cve",
  "ttp",
  "campaign",
  "vendor",
  "product",
  "sector",
  "country",
  "mitigation",
];

// The names the extension shows for entity types. src/content/page.js keeps a copy.
export const TYPE_LABELS = {
  threat_actor: "Threat actor",
  malware: "Malware",
  cve: "CVE",
  cwe: "CWE",
  ttp: "ATT&CK technique",
  country: "Country",
  tool: "Tool",
  vendor: "Vendor",
  product: "Product",
  mitigation: "Mitigation",
  sector: "Sector",
  observable: "Indicator",
  campaign: "Campaign",
};

/** A /api/intelligence/search result as {type, id, name}, or null for a type that can't take a note. */
export function entityOption(result) {
  if (!result || !NOTE_ENTITY_TYPES.includes(result.type)) return null;
  const name =
    result.type === "ttp"
      ? [result.technique_id, result.technique_name].filter(Boolean).join(" ")
      : result.name || result.cve_id || result.title || result.value;
  return name ? { type: result.type, id: result.id, name } : null;
}

/** The note's text: a link to the page, the selected text as a quote, then what the user wrote. */
export function linkNoteMarkdown({ url, pageTitle, quote, content }) {
  const title = String(pageTitle || url).replace(/[[\]]/g, "");
  const parts = [`[${title}](${url})`];
  const q = String(quote || "").trim();
  if (q) parts.push(q.split("\n").map((line) => `> ${line}`.trimEnd()).join("\n"));
  const c = String(content || "").trim();
  if (c) parts.push(c);
  return parts.join("\n\n");
}

/** Which kind the Note tab opens on: a source the page is about, else the last kind used. */
export function initialKind({ preferredSource, lastKind }) {
  if (preferredSource) return "telemetry";
  return NOTE_KINDS.includes(lastKind) ? lastKind : "note";
}
