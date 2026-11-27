// Is the tab showing a PDF? The browsers' PDF viewers don't let extensions read the page, so a PDF is sent as the file itself. No browser APIs here.

/** The address ends in .pdf (ignoring a query or #page=2). */
export function isPdfUrl(url) {
  try {
    return /\.pdf$/i.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

export const isPdfType = (contentType) => /^application\/(x-)?pdf\b/i.test(String(contentType || "").trim());

/** A file name for the upload: the last path segment, else the title. */
export function pdfFileName(url, title) {
  try {
    const last = decodeURIComponent(new URL(url).pathname.split("/").pop() || "");
    if (/\.pdf$/i.test(last)) return last;
  } catch {
    // fall through
  }
  const base =
    String(title || "document")
      .replace(/[\\/:*?"<>|]+/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 100) || "document";
  return `${base}.pdf`;
}
