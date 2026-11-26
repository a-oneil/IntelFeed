// The update check: is a newer extension release on GitHub than this one?

export const RELEASES_API = "https://api.github.com/repos/a-oneil/IntelFeed/releases?per_page=50";
export const RELEASES_PAGE = "https://github.com/a-oneil/IntelFeed/releases";
const TAG = /^extension-v(\d+\.\d+\.\d+)$/;

/** -1, 0 or 1, comparing dotted versions numerically ("1.0.10" > "1.0.9"). */
export function compareVersions(a, b) {
  const pa = String(a).split(".").map(Number);
  const pb = String(b).split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d > 0 ? 1 : -1;
  }
  return 0;
}

/** The newest published extension release in a GitHub releases list: {version, url}, or null. */
export function latestRelease(releases) {
  let best = null;
  for (const r of releases || []) {
    const m = TAG.exec(r.tag_name || "");
    if (!m || r.draft || r.prerelease) continue;
    if (!best || compareVersions(m[1], best.version) > 0) best = { version: m[1], url: r.html_url };
  }
  return best;
}
