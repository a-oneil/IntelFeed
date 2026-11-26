// Finding entity names in page text. Loaded into the page before page.js as a
// plain script (content scripts can't be modules), and by the tests under node.

(function (root) {
  function escape(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  /**
   * One regex for every surface form, longest first so "APT29 Cozy Bear" wins
   * over "APT29", matching whole words only. Case-sensitive: the forms are the
   * spellings the server's autolinker accepted in this very text.
   */
  function buildPattern(forms) {
    const unique = [...new Set(forms.filter((f) => f && f.length >= 2))].sort((a, b) => b.length - a.length);
    if (!unique.length) return null;
    return new RegExp(`(?<![\\p{L}\\p{N}_])(?:${unique.map(escape).join("|")})(?![\\p{L}\\p{N}_])`, "gu");
  }

  /** [{start, end, form}] for every non-overlapping match in text. */
  function findMatches(text, pattern) {
    const out = [];
    if (!pattern) return out;
    pattern.lastIndex = 0;
    let m;
    while ((m = pattern.exec(text))) {
      out.push({ start: m.index, end: m.index + m[0].length, form: m[0] });
    }
    return out;
  }

  /**
   * What a page is about, judged from its address alone: one CVE (an NVD,
   * cve.org or vendor advisory page names it in the URL) or one ATT&CK
   * technique (attack.mitre.org). Null for anything else, including a URL that
   * names more than one CVE.
   */
  function contextFromUrl(url) {
    let u;
    try {
      u = new URL(url);
    } catch (e) {
      return null;
    }
    if (u.hostname === "attack.mitre.org") {
      const m = /^\/techniques\/(T\d{4})(?:\/(\d{3}))?\/?$/.exec(u.pathname);
      return m ? { kind: "ttp", id: m[2] ? `${m[1]}.${m[2]}` : m[1] } : null;
    }
    const cves = new Set((decodeURIComponent(u.pathname + u.search).match(/CVE-\d{4}-\d{4,7}/gi) || []).map((c) => c.toUpperCase()));
    return cves.size === 1 ? { kind: "cve", id: [...cves][0] } : null;
  }

  root.IntelFeedMatcher = { buildPattern, findMatches, contextFromUrl };
})(globalThis);
