/**
 * Scroll the CodeMirror instance inside `root` to a 1-indexed line.
 *
 * Goes through the DOM rather than an EditorView handle because the outline is
 * the only caller and CodeMirrorEditor exposes no imperative API. Rule bodies
 * are tens of lines, so CM6 has them all rendered; the proportional fallback
 * covers the pathological long rule where it does not.
 */
export function scrollEditorToLine(root: HTMLElement | null, line: number, flashClass?: string) {
  if (!root || line < 1) return;
  const scroller = root.querySelector<HTMLElement>(".cm-scroller");
  const content = root.querySelector<HTMLElement>(".cm-content");
  if (!scroller || !content) return;

  const rendered = content.children;
  const target = rendered[line - 1] as HTMLElement | undefined;
  if (target) {
    scroller.scrollTo({ top: Math.max(0, target.offsetTop - 24), behavior: "smooth" });
    if (flashClass) {
      target.classList.add(flashClass);
      window.setTimeout(() => target.classList.remove(flashClass), 1200);
    }
    return;
  }
  const ratio = rendered.length > 0 ? (line - 1) / rendered.length : 0;
  scroller.scrollTo({ top: scroller.scrollHeight * ratio, behavior: "smooth" });
}
