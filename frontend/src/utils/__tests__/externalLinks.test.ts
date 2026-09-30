import { afterEach, describe, expect, it } from "vitest";
import {
  BUILT_IN_TRUSTED_DOMAINS,
  UNTRUSTED_CONTENT_ATTR,
  evaluateLinkClick,
  findTextMismatch,
  hostMatchesDomain,
  hostsFromUrls,
  isAlarming,
  isExternalWebUrl,
  isTrustedHost,
  parseMode,
  parseTrustedHosts,
  type InterceptContext,
} from "../externalLinks";

const ORIGIN = "https://intelfeed.example";

function ctx(overrides: Partial<InterceptContext> = {}): InterceptContext {
  return {
    origin: ORIGIN,
    baseUri: `${ORIGIN}/`,
    mode: "all",
    trustedHosts: [],
    feedHosts: [],
    ...overrides,
  };
}

function anchor(html: string, untrusted = false): HTMLAnchorElement {
  document.body.innerHTML = untrusted
    ? `<div ${UNTRUSTED_CONTENT_ATTR}>${html}</div>`
    : `<div>${html}</div>`;
  return document.querySelector("a") as HTMLAnchorElement;
}

const click = () => new MouseEvent("click", { button: 0 });

afterEach(() => {
  document.body.innerHTML = "";
});

describe("hostMatchesDomain", () => {
  it("matches the domain and its subdomains", () => {
    expect(hostMatchesDomain("nist.gov", "nist.gov")).toBe(true);
    expect(hostMatchesDomain("nvd.nist.gov", "nist.gov")).toBe(true);
  });

  it("respects label boundaries", () => {
    expect(hostMatchesDomain("evilnist.gov", "nist.gov")).toBe(false);
    expect(hostMatchesDomain("nist.gov.evil.com", "nist.gov")).toBe(false);
  });
});

describe("isTrustedHost", () => {
  it("trusts the built-in registries and their subdomains", () => {
    expect(BUILT_IN_TRUSTED_DOMAINS.length).toBeGreaterThan(0);
    expect(isTrustedHost("attack.mitre.org", [], [])).toBe(true);
    expect(isTrustedHost("nvd.nist.gov", [], [])).toBe(true);
    expect(isTrustedHost("www.cisa.gov", [], [])).toBe(true);
    expect(isTrustedHost("cve.org", [], [])).toBe(true);
  });

  it("does not trust lookalikes of the built-ins", () => {
    expect(isTrustedHost("mitre.org.evil.com", [], [])).toBe(false);
    expect(isTrustedHost("notmitre.org", [], [])).toBe(false);
  });

  it("matches user and feed hosts exactly, ignoring www", () => {
    expect(isTrustedHost("example.com", ["example.com"], [])).toBe(true);
    expect(isTrustedHost("www.example.com", ["example.com"], [])).toBe(true);
    expect(isTrustedHost("example.com", [], ["www.example.com"])).toBe(true);
    // Trusting a host must not widen to its subdomains.
    expect(isTrustedHost("blog.example.com", ["example.com"], [])).toBe(false);
    expect(isTrustedHost("attacker.github.io", ["github.io"], [])).toBe(false);
  });
});

describe("parseTrustedHosts / parseMode / hostsFromUrls", () => {
  it("cleans a persisted list", () => {
    expect(parseTrustedHosts([" Example.COM ", "example.com", 5, null, "", "www.foo.org"])).toEqual([
      "example.com",
      "foo.org",
    ]);
    expect(parseTrustedHosts("nope")).toEqual([]);
    expect(parseTrustedHosts(undefined)).toEqual([]);
  });

  it("caps the list length", () => {
    const many = Array.from({ length: 500 }, (_, i) => `h${i}.example.com`);
    expect(parseTrustedHosts(many)).toHaveLength(200);
  });

  it("falls back to article mode for unknown values", () => {
    expect(parseMode("off")).toBe("off");
    expect(parseMode("all")).toBe("all");
    expect(parseMode("article")).toBe("article");
    expect(parseMode("everything")).toBe("article");
    expect(parseMode(undefined)).toBe("article");
  });

  it("extracts hosts and skips junk", () => {
    expect(hostsFromUrls(["https://Blog.Example.com/feed.xml", null, "not a url", undefined])).toEqual([
      "blog.example.com",
    ]);
  });
});

describe("findTextMismatch", () => {
  it("flags URL text that points elsewhere", () => {
    expect(findTextMismatch("https://microsoft.com/security/report", "evil.example")).toEqual({
      claimedHost: "microsoft.com",
      actualHost: "evil.example",
      related: false,
    });
    expect(findTextMismatch("microsoft.com", "evil.example")).not.toBeNull();
  });

  it("flags a scheme-qualified URL buried in prose", () => {
    expect(findTextMismatch("Read https://microsoft.com/report now", "evil.example")).not.toBeNull();
  });

  it("ignores text that names no host", () => {
    expect(findTextMismatch("click here to see the report", "evil.example")).toBeNull();
    expect(findTextMismatch("", "evil.example")).toBeNull();
  });

  it("does not flag a bare host mentioned inside a sentence", () => {
    expect(findTextMismatch("see example.com for details", "other.example")).toBeNull();
  });

  it("accepts the same host with or without www but flags different subdomains", () => {
    expect(findTextMismatch("microsoft.com", "www.microsoft.com")).toBeNull();
    expect(findTextMismatch("learn.microsoft.com/docs", "microsoft.com")).not.toBeNull();
    expect(findTextMismatch("github.io", "attacker.github.io")).not.toBeNull();
  });

  it("catches a Cyrillic lookalike in the text", () => {
    expect(findTextMismatch("аpple.com", "apple.com")).not.toBeNull();
  });

  it("does not mistake file-like names for hosts", () => {
    expect(findTextMismatch("Node.js", "nodejs.org")).toBeNull();
    expect(findTextMismatch("setup.py", "github.com")).toBeNull();
  });

  // Regression: every one of these fired the red banner on real feed content
  // (Krebs, The DFIR Report) — file names in prose and indicator domains linked to
  // a lookup page.
  it("does not mistake common file names for hosts", () => {
    for (const name of ["ads.txt", "app-ads.txt", "msimg32.dll", "setup.exe", "report.pdf", "notes.docx"]) {
      expect(findTextMismatch(name, "example.com"), name).toBeNull();
    }
  });

  it("still catches abusable real TLDs used as file-looking text", () => {
    expect(findTextMismatch("invoice.zip", "evil.example")).not.toBeNull();
  });

  it("marks a domain linked to a lookup page about it as related, not alarming", () => {
    const m = findTextMismatch("armytimes.com", "decryptads.com", "/publisher/armytimes.com");
    expect(m).toEqual({ claimedHost: "armytimes.com", actualHost: "decryptads.com", related: true });
    expect(isAlarming(m)).toBe(false);

    const vt = findTextMismatch("evil.example", "www.virustotal.com", "/gui/domain/evil.example/detection");
    expect(vt?.related).toBe(true);

    const encoded = findTextMismatch("evil.example", "urlscan.io", "/search/", );
    expect(encoded?.related).toBe(false);
    expect(findTextMismatch("evil.example", "x.example", "/q%3Fd%3Devil.example")?.related).toBe(true);
  });

  it("treats a claimed host missing from the URL as alarming", () => {
    const m = findTextMismatch("https://microsoft.com/security", "evil.example", "/login");
    expect(isAlarming(m)).toBe(true);
  });

  it("tolerates trailing punctuation around the URL", () => {
    expect(findTextMismatch("(https://microsoft.com/report).", "evil.example")).not.toBeNull();
    expect(findTextMismatch("(https://microsoft.com/report).", "microsoft.com")).toBeNull();
  });
});

describe("evaluateLinkClick", () => {
  it("does nothing when switched off", () => {
    const a = anchor('<a href="https://evil.example/x">x</a>', true);
    expect(evaluateLinkClick(a, click(), ctx({ mode: "off" }))).toBeNull();
  });

  it("in article mode only intercepts links inside untrusted content", () => {
    const outside = anchor('<a href="https://evil.example/x">x</a>');
    expect(evaluateLinkClick(outside, click(), ctx({ mode: "article" }))).toBeNull();
    const inside = anchor('<a href="https://evil.example/x">x</a>', true);
    expect(evaluateLinkClick(inside, click(), ctx({ mode: "article" }))).not.toBeNull();
  });

  it("in all mode intercepts links anywhere", () => {
    const outside = anchor('<a href="https://evil.example/x">x</a>');
    expect(evaluateLinkClick(outside, click(), ctx({ mode: "all" }))).not.toBeNull();
  });

  it("skips same-origin, relative, hash and non-web links", () => {
    for (const href of [
      `${ORIGIN}/settings`,
      "/settings",
      "#section",
      "mailto:a@b.example",
      "tel:+15555550100",
      "blob:https://intelfeed.example/1234",
      "cid:image001",
    ]) {
      const a = anchor(`<a href="${href}">x</a>`, true);
      expect(evaluateLinkClick(a, click(), ctx()), href).toBeNull();
    }
  });

  it("skips anchors with no href", () => {
    document.body.innerHTML = "<a>nothing</a>";
    const a = document.querySelector("a") as HTMLAnchorElement;
    expect(evaluateLinkClick(a, click(), ctx())).toBeNull();
  });

  it("reports the host, full URL and visible text", () => {
    const a = anchor('<a href="https://Evil.Example/path?q=1#frag">  the   report </a>', true);
    const info = evaluateLinkClick(a, click(), ctx())!;
    expect(info.host).toBe("evil.example");
    expect(info.url).toBe("https://evil.example/path?q=1#frag");
    expect(info.text).toBe("the report");
    expect(info.mismatch).toBeNull();
  });

  it("lets built-in, user and feed hosts through", () => {
    const nvd = anchor('<a href="https://nvd.nist.gov/vuln/detail/CVE-2024-1">cve</a>', true);
    expect(evaluateLinkClick(nvd, click(), ctx())).toBeNull();

    const mine = anchor('<a href="https://blog.example.com/p">post</a>', true);
    expect(evaluateLinkClick(mine, click(), ctx({ trustedHosts: ["blog.example.com"] }))).toBeNull();
    expect(evaluateLinkClick(mine, click(), ctx({ feedHosts: ["blog.example.com"] }))).toBeNull();
    expect(evaluateLinkClick(mine, click(), ctx())).not.toBeNull();
  });

  it("still stops a trusted host when the text claims another one", () => {
    const a = anchor('<a href="https://attack.mitre.org/x">https://paypal.com/login</a>', true);
    const info = evaluateLinkClick(a, click(), ctx())!;
    expect(info).not.toBeNull();
    expect(info.mismatch).toEqual({
      claimedHost: "paypal.com",
      actualHost: "attack.mitre.org",
      related: false,
    });
  });

  it("holds a trusted lookup-style link even when the claimed host appears in its path", () => {
    const lookup = anchor('<a href="https://decryptads.com/publisher/armytimes.com">armytimes.com</a>', true);
    const info = evaluateLinkClick(lookup, click(), ctx({ trustedHosts: ["decryptads.com"] }))!;
    expect(info.mismatch?.related).toBe(true);
  });

  it("holds an HTTPS claim that actually points to HTTP on a trusted host", () => {
    const a = anchor('<a href="http://blog.example.com/report">https://blog.example.com/report</a>', true);
    const info = evaluateLinkClick(a, click(), ctx({ trustedHosts: ["blog.example.com"] }))!;
    expect(info.notes.map((n) => n.id)).toContain("downgrade");
  });

  it("notes the common redirect hosts as shorteners", () => {
    for (const host of ["hubs.li", "feedproxy.google.com", "safelinks.protection.outlook.com"]) {
      const a = anchor(`<a href="https://${host}/abc">x</a>`, true);
      expect(evaluateLinkClick(a, click(), ctx())!.notes.map((n) => n.id), host).toEqual(["shortener"]);
    }
  });

  it("still stops a trusted host when the URL carries user-info", () => {
    const a = anchor('<a href="https://user:pw@nvd.nist.gov/x">nvd</a>', true);
    const info = evaluateLinkClick(a, click(), ctx({ trustedHosts: ["nvd.nist.gov"] }))!;
    expect(info.notes.map((n) => n.id)).toContain("userinfo");
  });

  it("treats mitre.org@evil as going to evil", () => {
    const a = anchor('<a href="https://mitre.org@evil.example/x">mitre</a>', true);
    const info = evaluateLinkClick(a, click(), ctx())!;
    expect(info.host).toBe("evil.example");
    expect(info.notes.map((n) => n.id)).toContain("userinfo");
  });

  it("notes shorteners, raw IPs and punycode hosts", () => {
    const short = evaluateLinkClick(anchor('<a href="https://bit.ly/abc">x</a>', true), click(), ctx())!;
    expect(short.notes.map((n) => n.id)).toEqual(["shortener"]);

    const ip = evaluateLinkClick(anchor('<a href="http://203.0.113.9/x">x</a>', true), click(), ctx())!;
    expect(ip.notes.map((n) => n.id)).toEqual(["ip"]);

    const idn = evaluateLinkClick(anchor('<a href="https://аpple.com/">x</a>', true), click(), ctx())!;
    expect(idn.host).toMatch(/^xn--/);
    expect(idn.notes.map((n) => n.id)).toEqual(["idn"]);
  });

  it("a user-trusted shortener no longer prompts", () => {
    const a = anchor('<a href="https://bit.ly/abc">x</a>', true);
    expect(evaluateLinkClick(a, click(), ctx({ trustedHosts: ["bit.ly"] }))).toBeNull();
  });

  it("records whether the original click would have opened a new tab", () => {
    const same = anchor('<a href="https://evil.example/">x</a>', true);
    expect(evaluateLinkClick(same, click(), ctx())!.newTab).toBe(false);

    const blank = anchor('<a href="https://evil.example/" target="_blank">x</a>', true);
    expect(evaluateLinkClick(blank, click(), ctx())!.newTab).toBe(true);

    expect(
      evaluateLinkClick(same, new MouseEvent("click", { button: 0, metaKey: true }), ctx())!.newTab,
    ).toBe(true);
    expect(
      evaluateLinkClick(same, new MouseEvent("click", { button: 0, ctrlKey: true }), ctx())!.newTab,
    ).toBe(true);
    expect(evaluateLinkClick(same, new MouseEvent("auxclick", { button: 1 }), ctx())!.newTab).toBe(true);
  });
});

describe("isExternalWebUrl", () => {
  const o = "https://intelfeed.example";
  const base = "https://intelfeed.example/";
  it("is true only for web URLs that leave the site", () => {
    expect(isExternalWebUrl("https://evil.example/x", o, base)).toBe(true);
    expect(isExternalWebUrl("http://intelfeed.example/x", o, base)).toBe(true); // different origin (scheme)
    expect(isExternalWebUrl("//evil.example/x", o, base)).toBe(true);
    expect(isExternalWebUrl("ftp://files.example/x", o, base)).toBe(true);
  });
  it("is false for everything within the site or not a web link", () => {
    for (const u of ["/settings", "settings", "#top", "?q=1", "https://intelfeed.example/entries/1", "mailto:a@b.example", "tel:+1555", "blob:https://intelfeed.example/1", "javascript:void(0)", "", "http://"]) {
      expect(isExternalWebUrl(u, o, base), JSON.stringify(u)).toBe(false);
    }
  });
});
