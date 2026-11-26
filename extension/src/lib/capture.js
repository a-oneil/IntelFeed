// Runs inside the page (chrome.scripting.executeScript({func: capturePage})),
// so it must be self-contained: no imports, no closures over this module.
// It only reads the document; page-meta.js turns the result into a request.

export function capturePage(includeHtml) {
  const metas = [];
  for (const el of document.querySelectorAll("meta[content]")) {
    const key = el.getAttribute("property") || el.getAttribute("name") || el.getAttribute("itemprop");
    if (key) metas.push([key.toLowerCase(), el.getAttribute("content")]);
  }
  const ldjson = [];
  for (const el of document.querySelectorAll('script[type="application/ld+json"]')) {
    if (el.textContent && el.textContent.length < 200000) ldjson.push(el.textContent);
  }
  const feeds = [];
  for (const el of document.querySelectorAll('link[rel~="alternate"][href]')) {
    feeds.push({ href: el.href, type: (el.type || "").toLowerCase(), title: el.title || "" });
  }
  const timeEl = document.querySelector("article time[datetime], time[pubdate][datetime]");
  // On a GitHub repo page the default branch is in the page's embedded app data.
  let githubDefaultBranch = null;
  if (location.hostname === "github.com") {
    for (const el of document.querySelectorAll('script[type="application/json"]')) {
      const m = /"defaultBranch":"([^"]+)"/.exec(el.textContent || "");
      if (m) {
        githubDefaultBranch = m[1];
        break;
      }
    }
  }
  // The server accepts up to 2,000,000 characters of HTML (PageIngestRequest.html).
  // A larger page is sent without it, and the server fetches the URL instead.
  const html = includeHtml ? document.documentElement.outerHTML : null;
  return {
    url: location.href,
    title: document.title,
    selection: String(window.getSelection() || "").trim(),
    metas,
    ldjson,
    feeds,
    time: timeEl ? timeEl.getAttribute("datetime") : null,
    githubDefaultBranch,
    html: html && html.length <= 2000000 ? html : null,
  };
}
