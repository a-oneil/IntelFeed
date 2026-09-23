/**
 * NoteBody — renders a note's saved content as formatted text.
 *
 * Note content is inconsistent across how notes were authored:
 *  - pure markdown source (entity notes, CLI notes)
 *  - real rendered HTML (`content_html`, legacy WYSIWYG notes)
 *  - markdown blocks each wrapped in <p>…</p> (AI copilot output) — the markdown
 *    syntax (#, **, |, ---) is intact but buried inside HTML block tags, which
 *    neither a markdown parser nor an HTML renderer will format on its own.
 *
 * So we look for *rich* HTML tags (headings, strong, tables, lists, links…):
 *  - present  → it's genuinely rendered HTML → sanitize + show via SafeHTML.
 *  - absent   → treat as markdown; first unwrap any <p>/<br> block wrappers back
 *               into plain markdown, then render via EntityLinkedMarkdown, which
 *               formats it *and* auto-links known intelligence entities.
 * Shared by the read view and the editor's live preview.
 */
import { useMemo } from "react";
import { SafeHTML } from "./SafeHTML";
import { EntityLinkedMarkdown } from "./EntityLinkedMarkdown";
import { isRichHtml, toMarkdownSource } from "@/utils/noteContent";
import styles from "./NoteBody.module.css";

interface NoteBodyProps {
  content: string;
  /** Force a renderer; defaults to auto-detecting HTML vs markdown. */
  format?: "auto" | "html" | "markdown";
  /** Entity whose profile is shown — never links a note to its own entity. */
  excludeEntityId?: string;
  /** Scan + link entities in markdown (off for the editor preview). */
  scanEntities?: boolean;
  className?: string;
}

export function NoteBody({
  content,
  format = "auto",
  excludeEntityId,
  scanEntities = true,
  className,
}: NoteBodyProps) {
  const cls = className ? `${styles.body} ${className}` : styles.body;

  const asHtml = format === "html" || (format === "auto" && isRichHtml(content));

  const markdown = useMemo(
    () => (asHtml ? "" : toMarkdownSource(content)),
    [asHtml, content],
  );

  if (asHtml) {
    return <SafeHTML html={content} className={cls} />;
  }

  return (
    <div className={cls}>
      <EntityLinkedMarkdown text={markdown} excludeEntityId={excludeEntityId} enabled={scanEntities} />
    </div>
  );
}
