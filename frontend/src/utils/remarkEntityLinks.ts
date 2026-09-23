import type { Root, RootContent, Text, Link, Parent } from "mdast";

export interface RemarkEntityLink {
  type: string;
  value: string;
  href: string;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Remark plugin: substitute literal entity surface forms in text nodes
 * with link nodes pointing at the entity profile.
 *
 * Hand-rolled recursive walker (no unist-util-visit). Each `walk(parent)`
 * call reads `parent.children` into a fresh array and reassigns once at
 * the end of that call, so no third-party traversal state can desync.
 *
 * Skipped:
 *  - text inside an existing `link` ancestor (preserves the model's
 *    `[Article Title](URL)` references — and would produce invalid nested
 *    anchors otherwise)
 *  - text inside `code` / `inlineCode` (CVE-2024-1234 inside a fenced
 *    block shouldn't be re-styled)
 */
export function remarkEntityLinks(entities: RemarkEntityLink[]) {
  return (tree: Root) => {
    const valid = entities.filter(
      (e) => e && typeof e.value === "string" && e.value.length > 0,
    );
    if (valid.length === 0) return;

    const sorted = [...valid].sort((a, b) => b.value.length - a.value.length);
    const entityMap = new Map<string, RemarkEntityLink>();
    for (const e of sorted) entityMap.set(e.value.toLowerCase(), e);

    const pattern = sorted
      .map((e) => `(?<!\\w)${escapeRegExp(e.value)}(?!\\w)`)
      .join("|");
    if (!pattern) return;

    const wrapText = (text: string): RootContent[] | null => {
      const regex = new RegExp(pattern, "gi");
      const out: RootContent[] = [];
      let lastIndex = 0;
      let m: RegExpExecArray | null;
      let any = false;

      while ((m = regex.exec(text)) !== null) {
        any = true;
        if (m.index > lastIndex) {
          out.push({ type: "text", value: text.slice(lastIndex, m.index) } as Text);
        }
        const ent = entityMap.get(m[0].toLowerCase());
        if (ent) {
          const link: Link = {
            type: "link",
            url: ent.href,
            children: [{ type: "text", value: m[0] } as Text],
          };
          out.push(link);
        } else {
          out.push({ type: "text", value: m[0] } as Text);
        }
        lastIndex = regex.lastIndex;
      }

      if (!any) return null;
      if (lastIndex < text.length) {
        out.push({ type: "text", value: text.slice(lastIndex) } as Text);
      }
      return out;
    };

    const walk = (parent: Parent): void => {
      if (!parent || !Array.isArray(parent.children)) return;
      const next: RootContent[] = [];
      for (const child of parent.children) {
        if (!child || typeof child !== "object") {
          next.push(child);
          continue;
        }
        if (child.type === "text") {
          const replacements = wrapText((child as Text).value || "");
          if (replacements) {
            next.push(...replacements);
          } else {
            next.push(child);
          }
          continue;
        }
        if (
          child.type === "link" ||
          child.type === "linkReference" ||
          child.type === "code" ||
          child.type === "inlineCode"
        ) {
          next.push(child);
          continue;
        }
        if ("children" in child && Array.isArray((child as Parent).children)) {
          walk(child as Parent);
        }
        next.push(child);
      }
      parent.children = next as Parent["children"];
    };

    try {
      walk(tree);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn("[entity-links] walker threw:", err);
    }
  };
}
