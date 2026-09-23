import api from "@/api/client";

export async function exportEntry(entryId: string): Promise<void> {
  const res = await api.get(`/export/entries/${entryId}`, {
    responseType: "blob",
  });
  const blob = new Blob([res.data], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const disposition = res.headers["content-disposition"] || "";
  const match = disposition.match(/filename="(.+?)"/);
  const filename = match ? match[1] : "export.md";
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export async function exportNote(noteId: string): Promise<void> {
  const res = await api.get(`/export/notes/${noteId}`, {
    responseType: "blob",
  });
  const blob = new Blob([res.data], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const disposition = res.headers["content-disposition"] || "";
  const match = disposition.match(/filename="(.+?)"/);
  const filename = match ? match[1] : "export.md";
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Export any note as a downloaded markdown file, client-side. Works for every
 * note type (entry, sidebar, entity) since it only needs the title + markdown
 * the card already holds — no per-model backend endpoint required.
 */
export function exportMarkdownNote(title: string, markdown: string): void {
  const heading = (title || "Note").trim();
  const md = `# ${heading}\n\n${markdown.trim()}\n`;
  const safe = heading.slice(0, 50).replace(/[/\\]/g, "-") || "note";
  triggerDownload(md, "text/markdown", `${safe}.md`);
}

function triggerDownload(data: BlobPart, type: string, filename: string): void {
  const blob = new Blob([data], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function filenameFromHeaders(headers: Record<string, unknown>, fallback: string): string {
  const disposition = (headers["content-disposition"] as string) || "";
  const match = disposition.match(/filename="(.+?)"/);
  return match ? match[1] : fallback;
}

/** Export a single entity profile as a downloaded markdown file. */
export async function exportEntityProfile(entityType: string, entityId: string): Promise<void> {
  const res = await api.get(`/export/entities/${entityType}/${entityId}`, {
    responseType: "blob",
  });
  triggerDownload(res.data, "text/markdown", filenameFromHeaders(res.headers, "profile.md"));
}

/**
 * Export many entity profiles of one type as a downloaded ZIP. Pass explicit
 * `entityIds`, or `all: true` to export every entity of the type.
 */
export async function bulkExportEntityProfiles(params: {
  entityType: string;
  entityIds?: string[];
  all?: boolean;
}): Promise<void> {
  const res = await api.post(
    "/export/entities/bulk",
    { entity_type: params.entityType, entity_ids: params.entityIds ?? [], all: params.all ?? false },
    { responseType: "blob" }
  );
  triggerDownload(
    res.data,
    "application/zip",
    filenameFromHeaders(res.headers, `intelfeed-${params.entityType}-profiles.zip`)
  );
}

export async function bulkExport(entryIds: string[], noteIds: string[]): Promise<void> {
  const res = await api.post(
    "/export/bulk",
    { entry_ids: entryIds, note_ids: noteIds },
    { responseType: "blob" }
  );
  const blob = new Blob([res.data], { type: "application/zip" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "intelfeed-export.zip";
  a.click();
  URL.revokeObjectURL(url);
}
