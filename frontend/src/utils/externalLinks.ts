/**
 * Pure logic for the external-link interstitial: which clicks get intercepted,
 * which hosts are trusted, and what looks wrong about a link. No DOM listeners
 * or React in here so it can be unit tested exhaustively; the listener lives in
 * `components/ExternalLinkGuard.tsx`.
 */

export type ExternalLinkMode = "off" | "article" | "all";

export const DEFAULT_EXTERNAL_LINK_MODE: ExternalLinkMode = "article";

/** Keys inside `user.settings` (server-side, so they follow the account). */
export const EXTERNAL_LINK_MODE_KEY = "external_link_mode";
export const EXTERNAL_LINK_TRUSTED_KEY = "external_link_trusted_hosts";

/**
 * sessionStorage key prefix for hosts trusted "for this tab" (one key per
 * account, plus one for public pages). Lives here, not in the store, so the
 * logout cleanup can clear them without importing the store (which imports
 * authStore, which imports the cleanup).
 */
export const EXTERNAL_LINK_SESSION_TRUST_PREFIX = "intelfeed:external-link-trust:";

/** Cap on the saved list so the settings blob can't grow without bound. */
export const MAX_TRUSTED_HOSTS = 200;

/**
 * Marks a subtree whose links come from feed content and are therefore
 * attacker-influenceable. In "article" mode only links inside such a subtree
 * are intercepted.
 */
export const UNTRUSTED_CONTENT_ATTR = "data-untrusted-content";

/**
 * Domains that ship trusted, matched as the domain or any subdomain of it.
 * Keep this to registries that only the named organisation controls — never a
 * shared-hosting suffix (github.io, blogspot.com), where a subdomain is
 * anyone's.
 */
export const BUILT_IN_TRUSTED_DOMAINS = ["mitre.org", "nist.gov", "cve.org", "cisa.gov"];

/** Hosts whose whole purpose is hiding the real destination. */
const URL_SHORTENERS = new Set([
  "bit.ly",
  "t.co",
  "tinyurl.com",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "rebrand.ly",
  "cutt.ly",
  "shorturl.at",
  "t.ly",
  "lnkd.in",
  "tiny.cc",
  "rb.gy",
  "hubs.li",
  "feedproxy.google.com",
  "l.facebook.com",
  "safelinks.protection.outlook.com",
]);

/**
 * Trailing "extensions" that read like a host but are file names in prose
 * (`ads.txt`, `msimg32.dll`) — common in incident write-ups. Real TLDs that
 * double as extensions and get abused in phishing (.zip, .mov) are left out on
 * purpose, as is anything else that could be a genuine host.
 */
const NOT_A_TLD = new Set([
  "js", "ts", "jsx", "tsx", "py", "rb", "md", "sh", "go", "cs", "ps1", "json",
  "txt", "dll", "exe", "sys", "bat", "vbs", "jar", "doc", "docx", "xls", "xlsx", "ppt",
  "pptx", "pdf", "csv", "log", "ini", "cfg", "conf", "yml", "yaml", "xml", "html", "htm",
  "php", "asp", "aspx", "jsp", "so", "lnk", "msi", "iso", "tmp", "bin", "dat", "sql",
]);

const WEB_PROTOCOLS = new Set(["http:", "https:", "ftp:", "ftps:"]);

export type LinkNoteId = "userinfo" | "idn" | "ip" | "shortener" | "downgrade";

export interface LinkNote {
  id: LinkNoteId;
  message: string;
}

export interface LinkMismatch {
  /** Host the visible link text claims. */
  claimedHost: string;
  /** Host the link actually goes to. */
  actualHost: string;
  /**
   * The claimed host also appears in the link's own path/query — the shape of a
   * lookup page *about* that host (`evil.com` linking to
   * `virustotal.com/gui/domain/evil.com`), which is how analysts routinely link
   * indicators. Still shown, but as a note rather than an alarm: an attacker can
   * copy the host into a path too, so it must not silence the warning entirely.
   */
  related: boolean;
}

export interface ExternalLinkInfo {
  url: string;
  host: string;
  /** Visible link text, whitespace-collapsed and length-capped. */
  text: string;
  /** Whether the original click would have opened a new tab. */
  newTab: boolean;
  mismatch: LinkMismatch | null;
  notes: LinkNote[];
}

export interface InterceptContext {
  /** `window.location.origin` — same-origin links are never intercepted. */
  origin: string;
  mode: ExternalLinkMode;
  /** User-trusted hosts, matched exactly (ignoring a leading "www."). */
  trustedHosts: readonly string[];
  /** Hosts of subscribed feed URLs, matched exactly like `trustedHosts`. */
  feedHosts: readonly string[];
  /** Base for resolving relative hrefs. Defaults to the document's base URI. */
  baseUri?: string;
}

export function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
}

/** True when `host` is `domain` or a subdomain of it — on a label boundary. */
export function hostMatchesDomain(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`);
}

export function isTrustedHost(
  host: string,
  trustedHosts: readonly string[],
  feedHosts: readonly string[],
): boolean {
  const h = normalizeHost(host);
  if (BUILT_IN_TRUSTED_DOMAINS.some((d) => hostMatchesDomain(h, d))) return true;
  // User and feed entries are exact on purpose: "trust example.com" must not
  // silently trust every subdomain, and without a public-suffix list there is
  // no safe way to widen it.
  return (
    trustedHosts.some((t) => normalizeHost(t) === h) ||
    feedHosts.some((f) => normalizeHost(f) === h)
  );
}

/** Clean a persisted value into a bounded, deduped, lowercase host list. */
export function parseTrustedHosts(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (typeof item !== "string") continue;
    const host = normalizeHost(item);
    if (host && host.length <= 253) seen.add(host);
    if (seen.size >= MAX_TRUSTED_HOSTS) break;
  }
  return [...seen];
}

export function parseMode(raw: unknown): ExternalLinkMode {
  return raw === "off" || raw === "article" || raw === "all" ? raw : DEFAULT_EXTERNAL_LINK_MODE;
}

/** Host list of a feed's own URLs — the sites the user chose to follow. */
export function hostsFromUrls(urls: readonly (string | null | undefined)[]): string[] {
  const hosts = new Set<string>();
  for (const u of urls) {
    if (!u) continue;
    try {
      hosts.add(new URL(u).hostname.toLowerCase());
    } catch {
      // not a URL — skip
    }
  }
  return [...hosts];
}

const HOST_TOKEN =
  /^(?:(?:https?|ftp):\/\/)?((?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]*[a-z0-9¡-￿])?\.)+[a-z¡-￿]{2,})(?::\d+)?(?:[/?#]\S*)?$/i;

function stripPunctuation(token: string): string {
  return token.replace(/^[([<"'“‘]+/, "").replace(/[)\]>"'”’.,;:!?…]+$/, "");
}

/**
 * The classic phishing tell: link text that *is* a URL, pointing somewhere
 * else. Only text that names a host can disagree with an href, so "click here"
 * is never flagged. A scheme-qualified URL anywhere in the text counts; a bare
 * host only counts when it is the whole text, to keep prose like "see
 * example.com for details" from tripping it.
 */
export function findTextMismatch(
  text: string,
  actualHost: string,
  hrefTail = "",
): LinkMismatch | null {
  const tokens = text.split(/\s+/).map(stripPunctuation).filter(Boolean);
  for (const token of tokens) {
    const match = HOST_TOKEN.exec(token);
    if (!match) continue;
    const hasScheme = /^[a-z]+:\/\//i.test(token);
    if (!hasScheme && tokens.length > 1) continue;
    const tld = match[1].split(".").pop()!.toLowerCase();
    if (!hasScheme && NOT_A_TLD.has(tld)) continue;

    let claimed: string;
    try {
      // Round-trips through the URL parser so a Cyrillic lookalike in the text
      // compares as its punycode form, exactly like the href does.
      claimed = new URL(`http://${match[1]}`).hostname;
    } catch {
      continue;
    }
    const a = normalizeHost(claimed);
    const b = normalizeHost(actualHost);
    // Parent and child hosts are not interchangeable on shared hosting
    // services (for example github.io and attacker.github.io).
    if (a === b) return null;
    let tail = hrefTail;
    try {
      tail = decodeURIComponent(hrefTail);
    } catch {
      // malformed escapes: match against the raw text
    }
    return { claimedHost: claimed, actualHost, related: tail.toLowerCase().includes(a) };
  }
  return null;
}

/** A mismatch worth stopping a trusted host for: text names a host the URL never mentions. */
export function isAlarming(mismatch: LinkMismatch | null): boolean {
  return mismatch !== null && !mismatch.related;
}

export function collectNotes(url: URL, text = ""): LinkNote[] {
  const notes: LinkNote[] = [];
  const host = url.hostname.toLowerCase();
  if (url.username || url.password) {
    notes.push({
      id: "userinfo",
      message:
        "This URL has a username/password section before the host — a common way to make a link look like it goes somewhere else.",
    });
  }
  if (url.protocol === "http:" && text.split(/\s+/).some((token) => {
    const candidate = stripPunctuation(token);
    if (!candidate.toLowerCase().startsWith("https://")) return false;
    try {
      return normalizeHost(new URL(candidate).hostname) === normalizeHost(host);
    } catch {
      return false;
    }
  })) {
    notes.push({
      id: "downgrade",
      message: "The link text promises HTTPS, but the destination uses unencrypted HTTP.",
    });
  }
  if (host.split(".").some((label) => label.startsWith("xn--"))) {
    notes.push({
      id: "idn",
      message:
        "Internationalised domain name (shown as punycode). Check for lookalike characters standing in for Latin letters.",
    });
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) {
    notes.push({ id: "ip", message: "The destination is a raw IP address, not a domain name." });
  }
  const bare = normalizeHost(host);
  if (URL_SHORTENERS.has(bare)) {
    notes.push({
      id: "shortener",
      message: "URL shortener — the final destination is hidden until the redirect is followed.",
    });
  }
  return notes;
}

function collapseText(anchor: HTMLAnchorElement): string {
  return (anchor.textContent ?? "").replace(/\s+/g, " ").trim().slice(0, 300);
}

function opensNewTab(anchor: HTMLAnchorElement, event: MouseEvent): boolean {
  if (event.type === "auxclick" || event.metaKey || event.ctrlKey || event.shiftKey) return true;
  const target = anchor.target.toLowerCase();
  return target !== "" && target !== "_self" && target !== "_parent" && target !== "_top";
}

/**
 * The shared decision, given a URL rather than a DOM node. `untrusted` says the
 * URL came from feed content: "article" scope only covers those.
 */
function evaluateUrl(
  rawUrl: string,
  ctx: InterceptContext,
  opts: { text: string; newTab: boolean; untrusted: boolean },
): ExternalLinkInfo | null {
  if (ctx.mode === "off") return null;

  let url: URL;
  try {
    url = new URL(rawUrl, ctx.baseUri ?? document.baseURI);
  } catch {
    return null;
  }
  // mailto:, tel:, blob:, cid: and friends never leave the app in a way this
  // dialog can describe; javascript: is already stripped by the sanitiser.
  if (!WEB_PROTOCOLS.has(url.protocol)) return null;
  if (url.origin === ctx.origin) return null;

  if (ctx.mode === "article" && !opts.untrusted) return null;

  const host = url.hostname.toLowerCase();
  const mismatch = findTextMismatch(opts.text, host, url.pathname + url.search + url.hash);
  const notes = collectNotes(url, opts.text);

  // A trusted host skips the prompt only when the link text agrees with it.
  // Notes about IPs, shorteners and IDNs describe the host itself; user-info
  // and HTTPS downgrades describe this particular link and still force a prompt.
  const disguised = mismatch !== null || notes.some((n) => n.id === "userinfo" || n.id === "downgrade");
  if (!disguised && isTrustedHost(host, ctx.trustedHosts, ctx.feedHosts)) return null;

  return { url: url.href, host, text: opts.text, newTab: opts.newTab, mismatch, notes };
}

/**
 * Decide whether a click on `anchor` should be held for confirmation. Returns
 * null to let the browser proceed untouched.
 */
export function evaluateLinkClick(
  anchor: HTMLAnchorElement,
  event: MouseEvent,
  ctx: InterceptContext,
): ExternalLinkInfo | null {
  const href = anchor.getAttribute("href");
  if (!href) return null;
  return evaluateUrl(href, ctx, {
    text: collapseText(anchor),
    newTab: opensNewTab(anchor, event),
    untrusted: anchor.closest(`[${UNTRUSTED_CONTENT_ATTR}]`) !== null,
  });
}

/**
 * Same decision for a URL the app is about to open from code (the `o` shortcut,
 * a widget row) rather than from a link click. These URLs come from feeds, so
 * they count as untrusted in every scope except "off". For an entry that sits
 * on its own feed's site the feed-host allowlist means this never prompts.
 */
export function evaluateProgrammaticOpen(
  rawUrl: string,
  ctx: InterceptContext,
  text = "",
): ExternalLinkInfo | null {
  return evaluateUrl(rawUrl, ctx, { text, newTab: true, untrusted: true });
}
