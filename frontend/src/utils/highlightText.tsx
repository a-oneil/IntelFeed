function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export interface GlossaryTermHighlight {
  id: string;
  name: string;
  category: string;
  search_terms?: string[];
}

/**
 * Annotate glossary terms in sanitized HTML by wrapping them in
 * <span class="glossary-term" data-glossary-id="..." data-glossary-category="...">
 * elements. Must be called on already-sanitized HTML (post-DOMPurify).
 */
export function annotateGlossaryHTML(html: string, terms: GlossaryTermHighlight[]): string {
  if (terms.length === 0 || !html) return html;

  // Sort by name length descending so longer terms match first
  const sorted = [...terms].sort((a, b) => b.name.length - a.name.length);

  // Build all matchable names: term.name + search_terms (aliases)
  const allNames: string[] = [];
  const termMap = new Map<string, GlossaryTermHighlight>();
  for (const t of sorted) {
    const names = [t.name, ...(t.search_terms || [])];
    for (const n of names) {
      const trimmed = (n || "").trim();
      if (!trimmed) continue;
      allNames.push(trimmed);
      termMap.set(trimmed.toLowerCase(), t);
    }
  }
  if (allNames.length === 0) return html;

  // Sort by length descending so longer names match first
  allNames.sort((a, b) => b.length - a.length);

  const pattern = allNames.map((n) => `\\b${escapeRegExp(n)}\\b`).join("|");
  const regex = new RegExp(`(${pattern})`, "gi");

  const doc = new DOMParser().parseFromString(html, "text/html");
  const walker = doc.createTreeWalker(doc.body, NodeFilter.SHOW_TEXT);

  const textNodes: Text[] = [];
  let node: Text | null;
  while ((node = walker.nextNode() as Text | null)) {
    textNodes.push(node);
  }

  for (const textNode of textNodes) {
    // Skip text inside unsafe/non-prose elements or existing links/glossary spans
    if (textNode.parentElement?.closest("textarea,option,script,style,title,noscript,code,pre,a,.glossary-term")) {
      continue;
    }

    const text = textNode.textContent || "";
    if (!regex.test(text)) continue;
    regex.lastIndex = 0;

    const fragment = doc.createDocumentFragment();
    let lastIndex = 0;
    let match: RegExpExecArray | null;
    let matched = false;

    while ((match = regex.exec(text)) !== null) {
      if (!match[0]) {
        regex.lastIndex++;
        continue;
      }
      matched = true;
      if (match.index > lastIndex) {
        fragment.appendChild(doc.createTextNode(text.slice(lastIndex, match.index)));
      }

      const term = termMap.get(match[0].toLowerCase());
      const span = doc.createElement("span");
      span.className = "glossary-term";
      span.dataset.glossaryId = term?.id || "";
      span.dataset.glossaryCategory = term?.category || "";
      span.textContent = match[0];
      fragment.appendChild(span);

      lastIndex = regex.lastIndex;
    }

    if (matched) {
      if (lastIndex < text.length) {
        fragment.appendChild(doc.createTextNode(text.slice(lastIndex)));
      }
      textNode.parentNode?.replaceChild(fragment, textNode);
    }
  }

  return doc.body.innerHTML;
}
