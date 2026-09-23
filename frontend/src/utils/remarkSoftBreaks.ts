import type { Root, Text, Parent, RootContent } from "mdast";

/**
 * Remark plugin: render single newlines as hard line breaks, the way GitHub
 * comments do (equivalent to the `remark-breaks` package, inlined to avoid a
 * dependency).
 *
 * Markdown normally collapses a soft break (a lone `\n`) into a space, so a
 * pasted plaintext note — or a markdown note that relies on line breaks rather
 * than blank-line paragraphs — renders as one run-on blob. Splitting `text`
 * nodes on `\n` into `break` nodes keeps those line breaks while still letting
 * real markdown syntax (headings, lists, emphasis, links) render.
 *
 * Only `text` nodes are touched, so newlines inside fenced `code` / `inlineCode`
 * (distinct node types) are left untouched.
 */
export function remarkSoftBreaks() {
  return (tree: Root) => {
    const walk = (parent: Parent): void => {
      if (!parent || !Array.isArray(parent.children)) return;
      const next: RootContent[] = [];
      for (const child of parent.children) {
        if (
          child &&
          child.type === "text" &&
          typeof (child as Text).value === "string" &&
          (child as Text).value.includes("\n")
        ) {
          const parts = (child as Text).value.split("\n");
          parts.forEach((part, i) => {
            if (i > 0) next.push({ type: "break" } as RootContent);
            if (part) next.push({ type: "text", value: part } as Text);
          });
          continue;
        }
        if (child && typeof child === "object" && "children" in child && Array.isArray((child as Parent).children)) {
          walk(child as Parent);
        }
        next.push(child);
      }
      parent.children = next as Parent["children"];
    };
    walk(tree);
  };
}
