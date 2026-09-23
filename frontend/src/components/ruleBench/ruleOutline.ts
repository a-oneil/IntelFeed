/**
 * Parse a rule body into a shallow outline the left rail can jump from.
 *
 * Deliberately regex-level, not a real parser: the outline only has to be good
 * enough to click, and a rule that fails to parse must still render its editor.
 * Anything unrecognised yields an empty outline rather than a wrong one.
 */

export interface OutlineNode {
  id: string;
  label: string;
  /** 1-indexed line in the rule body — what the editor scrolls to. */
  line: number;
  depth: 0 | 1;
  /** Field/condition count for the segment, when it is cheap to count. */
  count?: number;
}

const YAML_LIKE = new Set(["sigma", "nuclei"]);
const PIPE_LIKE = new Set(["kql", "splunk_spl", "elastic_ql", "crowdstrike_ql"]);

/** Trailing `:` and quotes carry no information in a nav label. */
function clean(label: string): string {
  return label.replace(/[:{,]+\s*$/, "").replace(/^["']|["']$/g, "").trim();
}

function countFields(segment: string): number | undefined {
  const body = segment.replace(/^\|\s*/, "");
  const verb = body.split(/\s+/)[0]?.toLowerCase();
  if (["project", "table", "fields", "project-away", "project-rename"].includes(verb)) {
    const args = body.slice(verb.length).trim();
    return args ? args.split(",").filter((s) => s.trim()).length : undefined;
  }
  if (verb === "where" || verb === "search") {
    const comparisons = body.match(/(==|=~|!=|!~|>=|<=|\bin\b|\bhas\b|\bcontains\b|\bstartswith\b|\bendswith\b)/gi);
    return comparisons?.length;
  }
  if (verb === "summarize" || verb === "stats") {
    const by = body.split(/\bby\b/i)[1];
    return by ? by.split(",").filter((s) => s.trim()).length : undefined;
  }
  return undefined;
}

function parseYamlLike(lines: string[]): OutlineNode[] {
  const nodes: OutlineNode[] = [];
  let detectionIndent: number | null = null;
  let childIndent: number | null = null;
  let current: OutlineNode | null = null;

  lines.forEach((raw, i) => {
    if (!raw.trim() || raw.trimStart().startsWith("#")) return;
    const indent = raw.length - raw.trimStart().length;
    const key = raw.trim().match(/^([\w$@.-]+):/);

    if (indent === 0) {
      detectionIndent = null;
      childIndent = null;
      current = null;
      if (!key) return;
      nodes.push({ id: `l${i}`, label: clean(key[1]), line: i + 1, depth: 0 });
      // Only `detection` earns children — logsource keys are noise in a rail.
      if (key[1] === "detection") detectionIndent = 0;
      return;
    }

    if (detectionIndent === null) return;
    if (childIndent === null) childIndent = indent;

    if (indent === childIndent && key) {
      current = { id: `l${i}`, label: clean(key[1]), line: i + 1, depth: 1, count: 0 };
      nodes.push(current);
    } else if (current && indent > childIndent) {
      current.count = (current.count ?? 0) + 1;
    }
  });

  // A selection block with no counted children reads better with no badge.
  return nodes.map((n) => (n.count === 0 ? { ...n, count: undefined } : n));
}

function parsePipeLike(lines: string[]): OutlineNode[] {
  const nodes: OutlineNode[] = [];
  lines.forEach((raw, i) => {
    const text = raw.trim();
    if (!text || text.startsWith("//") || text.startsWith("#")) return;
    const isPipe = text.startsWith("|");
    // The first bare line is the data source (a table, an index, a macro).
    if (!isPipe && nodes.length > 0) return;
    const body = text.replace(/^\|\s*/, "");
    const words = body.split(/\s+/).filter(Boolean).slice(0, 2).join(" ");
    nodes.push({
      id: `l${i}`,
      label: clean(words).slice(0, 40),
      line: i + 1,
      depth: isPipe ? 1 : 0,
      count: countFields(text),
    });
  });
  return nodes;
}

function parseYara(lines: string[]): OutlineNode[] {
  const nodes: OutlineNode[] = [];
  let section: OutlineNode | null = null;
  lines.forEach((raw, i) => {
    const text = raw.trim();
    const rule = text.match(/^(?:private\s+|global\s+)*rule\s+([\w.]+)/);
    if (rule) {
      section = null;
      nodes.push({ id: `l${i}`, label: rule[1], line: i + 1, depth: 0 });
      return;
    }
    const sec = text.match(/^(meta|strings|condition)\s*:/);
    if (sec) {
      section = { id: `l${i}`, label: sec[1], line: i + 1, depth: 1, count: 0 };
      nodes.push(section);
      return;
    }
    if (section && text && text !== "}") section.count = (section.count ?? 0) + 1;
  });
  return nodes.map((n) => (n.count === 0 ? { ...n, count: undefined } : n));
}

function parseSnort(lines: string[]): OutlineNode[] {
  const nodes: OutlineNode[] = [];
  lines.forEach((raw, i) => {
    const text = raw.trim();
    if (!text || text.startsWith("#")) return;
    if (!/^(alert|log|pass|drop|reject|sdrop)\b/.test(text)) return;
    const msg = text.match(/msg\s*:\s*"([^"]*)"/);
    nodes.push({
      id: `l${i}`,
      label: (msg?.[1] || text.split(/\s+/).slice(0, 3).join(" ")).slice(0, 40),
      line: i + 1,
      depth: 0,
      count: text.match(/content\s*:/g)?.length,
    });
  });
  return nodes;
}

function parsePython(lines: string[]): OutlineNode[] {
  const nodes: OutlineNode[] = [];
  lines.forEach((raw, i) => {
    const fn = raw.match(/^(?:\s*)def\s+(\w+)\s*\(/);
    if (fn) nodes.push({ id: `l${i}`, label: fn[1], line: i + 1, depth: raw.startsWith(" ") ? 1 : 0 });
  });
  return nodes;
}

export function parseRuleOutline(content: string, ruleType: string): OutlineNode[] {
  if (!content?.trim()) return [];
  const lines = content.split("\n");
  if (YAML_LIKE.has(ruleType)) return parseYamlLike(lines);
  if (PIPE_LIKE.has(ruleType)) return parsePipeLike(lines);
  if (ruleType === "yara") return parseYara(lines);
  if (ruleType === "snort_suricata") return parseSnort(lines);
  if (ruleType === "panther") return parsePython(lines);
  // Unknown format: a pipe query is the commonest shape, but only claim an
  // outline when the body actually looks like one.
  const piped = parsePipeLike(lines);
  return piped.length > 1 ? piped : [];
}
