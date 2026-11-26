// Turning what the server reports about a page into words. No browser APIs.

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** "2 actors, 3 CVEs, 5 techniques, 1 rule", or "" when nothing was found. */
export function summarize(results) {
  if (!results) return "";
  const parts = [];
  const actors = results.actors?.length || 0;
  const malware = results.malware?.length || 0;
  const tools = results.tools?.length || 0;
  const cves = results.cves?.length || 0;
  const ttps = results.ttps?.length || 0;
  if (actors) parts.push(plural(actors, "actor"));
  if (malware) parts.push(plural(malware, "malware family", "malware families"));
  if (tools) parts.push(plural(tools, "tool"));
  if (cves) parts.push(plural(cves, "CVE"));
  if (ttps) parts.push(plural(ttps, "technique"));
  if (results.rule_count) parts.push(plural(results.rule_count, "detection rule"));
  if (results.observable_count) parts.push(plural(results.observable_count, "indicator"));
  return parts.join(", ");
}

/** The notification once the pipeline is done with a page that was sent. */
export function notificationText(results) {
  const found = summarize(results);
  if (results.state === "errored") {
    return found ? `Processing hit an error. Found so far: ${found}.` : "Processing hit an error before anything was found.";
  }
  return found ? `Found ${found}.` : "Nothing was found in it.";
}

/** "7 articles from 4 sites": the size of a story thread. */
export function threadSize(thread) {
  if (!thread) return "";
  return `${plural(thread.entry_count, "article")} from ${plural(thread.source_count, "site")}`;
}
