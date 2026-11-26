// The background worker: the only part of the extension that talks to the
// server (see lib/api.js), plus the right-click menus, the toolbar dot and
// badge, the page script's registration, the user's theme, and the alarm that
// keeps the session fresh.

import { ApiError, NotSignedIn, originPattern, refreshSession, request, signIn, signOut, unlessSignedOut } from "./lib/api.js";
import { capturePage } from "./lib/capture.js";
import { notificationText } from "./lib/findings.js";
import { lookupUrl } from "./lib/lookup.js";
import { addFailed, enqueue, isRetryable } from "./lib/outbox.js";
import { githubRepo, ingestBody, redditFeedBody, repoFeedBody, siteFeeds } from "./lib/page-meta.js";
import { isPdfType, isPdfUrl, pdfFileName } from "./lib/pdf.js";
import * as store from "./lib/store.js";
import { cardView } from "./lib/card-view.js";
import { entityOption, linkNoteMarkdown, NOTE_ENTITY_TYPES } from "./lib/notes.js";
import { preferredSource, rememberPick } from "./lib/telemetry.js";
import { mergeTheme } from "./lib/theme.js";
import { setToolbarIcon } from "./lib/toolbar-icon.js";
import { compareVersions, latestRelease, RELEASES_API, RELEASES_PAGE } from "./lib/version.js";
import { WATCHABLE, watchState } from "./lib/watchlist.js";

const CLIENT = `intelfeed-extension/${chrome.runtime.getManifest().version}`;
const REFRESH_ALARM = "refresh-session";
const UPDATE_ALARM = "check-for-update";
const RESULTS_ALARM = "watch-results";
const OUTBOX_ALARM = "flush-outbox";
// The toolbar dot and highlighting need to see every page: an optional
// permission the user grants on the settings page.
const ALL_SITES = { origins: ["http://*/*", "https://*/*"] };
const PAGE_SCRIPT = "page";

// ── session upkeep ────────────────────────────────────────────────────
//
// A refresh token is good for 7 days and each refresh issues a new one, so
// refreshing twice a day (and when the browser starts) keeps the extension
// signed in for as long as the browser gets used at least once a week.

async function keepFresh() {
  const { refresh } = await store.load();
  if (!refresh) return;
  try {
    await refreshSession();
    await loadTheme();
  } catch {
    // NotSignedIn clears the session itself; a network error waits for the next alarm
    return;
  }
  // The server answered: anything that couldn't be sent earlier can go now.
  flushOutbox().catch(() => {});
}

async function setUp() {
  chrome.alarms.create(REFRESH_ALARM, { periodInMinutes: 12 * 60 });
  chrome.alarms.create(UPDATE_ALARM, { periodInMinutes: 24 * 60 });
  checkForUpdate().catch(() => {});
  await buildMenus();
  await syncPageScript();
  await showSessionState();
  const { outbox, watching, theme } = await store.load();
  await setToolbarIcon(theme?.vars?.accent).catch(() => {});
  if (outbox.length) chrome.alarms.create(OUTBOX_ALARM, { periodInMinutes: 5 });
  if (watching.length) chrome.alarms.create(RESULTS_ALARM, { periodInMinutes: 1 });
}

chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  await setUp();
  const { server } = await store.load();
  if (reason === "install" && !server) chrome.runtime.openOptionsPage();
});

chrome.runtime.onStartup.addListener(async () => {
  await setUp();
  await keepFresh();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === REFRESH_ALARM) keepFresh();
  if (alarm.name === UPDATE_ALARM) checkForUpdate().catch(() => {});
  if (alarm.name === RESULTS_ALARM) pollResults().catch(() => {});
  if (alarm.name === OUTBOX_ALARM) flushOutbox().catch(() => {});
});

// ── update check ──────────────────────────────────────────────────────
//
// Once a day: the newest extension-v* release on GitHub. The extension never
// updates itself; the popup and settings page say when a newer one exists.

async function checkForUpdate() {
  const resp = await fetch(RELEASES_API, { headers: { Accept: "application/vnd.github+json" } });
  if (!resp.ok) return;
  const latest = latestRelease(await resp.json());
  await store.save({ update: { latest, checkedAt: Date.now() } });
}

async function updateStatus() {
  const { update } = await store.load();
  const current = chrome.runtime.getManifest().version;
  const latest = update?.latest || null;
  return {
    current,
    latest: latest?.version || null,
    url: latest?.url || RELEASES_PAGE,
    newer: Boolean(latest && compareVersions(latest.version, current) > 0),
    checkedAt: update?.checkedAt || null,
  };
}

// ── address bar: "if <words>" searches IntelFeed ─────────────────────

chrome.omnibox.setDefaultSuggestion({ description: "Search IntelFeed for: %s" });

chrome.omnibox.onInputEntered.addListener(async (text, disposition) => {
  const { server } = await store.load();
  if (!server) return chrome.runtime.openOptionsPage();
  const url = lookupUrl(server, text);
  if (!url) return;
  if (disposition === "currentTab") chrome.tabs.update({ url });
  else chrome.tabs.create({ url, active: disposition !== "newBackgroundTab" });
});

// Signed out (a refused refresh, or Sign out): say so on the toolbar button
// for every tab, instead of the page features quietly stopping.
async function showSessionState() {
  const { access, server, outbox } = await store.load();
  const signedOut = Boolean(server) && !access;
  const waiting = outbox.length;
  await chrome.action.setBadgeBackgroundColor({ color: signedOut ? "#c62828" : "#546e7a" });
  await chrome.action.setBadgeText({ text: signedOut ? "!" : waiting ? String(waiting) : "" });
  await chrome.action.setTitle({
    title: signedOut
      ? "IntelFeed: you are signed out. Open the extension settings to sign in again."
      : waiting
        ? `IntelFeed: ${waiting} ${waiting === 1 ? "page is" : "pages are"} waiting to send`
        : "Send to IntelFeed",
  });
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.access || changes.outbox) showSessionState();
  if (changes.features) buildMenus();
  if (changes.theme) setToolbarIcon(changes.theme.newValue?.vars?.accent).catch(() => {});
  if (changes.features || changes.server || changes.access) syncPageScript().catch(() => {});
  if (changes.outbox || changes.features || changes.access) redrawDots();
});

chrome.permissions.onAdded.addListener(() => syncPageScript().catch(() => {}));
chrome.permissions.onRemoved.addListener(() => syncPageScript().catch(() => {}));

// ── theme ─────────────────────────────────────────────────────────────

const THEME_MAX_AGE = 10 * 60 * 1000;

/** Fetch the user's IntelFeed theme (their pick, else the instance default) and store it. */
async function loadTheme({ force = false } = {}) {
  const { theme: current, access } = await store.load();
  if (!access) return current;
  if (!force && current?.fetchedAt && Date.now() - current.fetchedAt < THEME_MAX_AGE) return current;
  const [me, schema] = await Promise.all([request("/api/auth/me"), request("/api/themes/schema")]);
  let picked = null;
  if (me.theme_id) {
    try {
      picked = await request(`/api/themes/${me.theme_id}`);
    } catch {
      picked = null; // a deleted custom theme: fall back to the default
    }
  }
  picked ??= await request("/api/themes/default");
  const theme = { ...mergeTheme(schema, picked), fetchedAt: Date.now() };
  await store.save({ theme });
  return theme;
}

// ── right-click menus ─────────────────────────────────────────────────

async function buildMenus() {
  const { features } = await store.load();
  await chrome.contextMenus.removeAll();
  chrome.contextMenus.create({ id: "send-page", title: "Send page to IntelFeed", contexts: ["page"] });
  chrome.contextMenus.create({ id: "send-link", title: "Send link to IntelFeed", contexts: ["link"] });
  if (features.lookupMenu) {
    chrome.contextMenus.create({ id: "lookup", title: "Look up “%s” in IntelFeed", contexts: ["selection"] });
  }
  chrome.contextMenus.create({ id: "save-rule", title: "Save selection as a detection rule", contexts: ["selection"] });
}

/** The selected text exactly as written — contextMenus' selectionText folds line breaks, which breaks rules. */
async function selectedText(tabId, fallback) {
  try {
    const [r] = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => String(window.getSelection() || ""),
    });
    return r?.result || fallback || "";
  } catch {
    return fallback || "";
  }
}

async function openRuleWindow(tab, info) {
  const text = await selectedText(tab.id, info.selectionText);
  const key = crypto.randomUUID();
  await chrome.storage.session.set({ [`rule:${key}`]: { text, url: tab.url, title: tab.title } });
  await chrome.windows.create({
    url: chrome.runtime.getURL(`src/rule/rule.html?key=${key}`),
    type: "popup",
    width: 620,
    height: 760,
  });
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  try {
    if (info.menuItemId === "lookup") {
      const { server } = await store.load();
      if (!server) return chrome.runtime.openOptionsPage();
      const url = lookupUrl(server, info.selectionText);
      if (url) await chrome.tabs.create({ url, index: tab ? tab.index + 1 : undefined });
    } else if (info.menuItemId === "save-rule" && tab?.id != null) {
      await openRuleWindow(tab, info);
    } else if (info.menuItemId === "send-page" && tab?.id != null) {
      await sendTab(tab.id, {});
    } else if (info.menuItemId === "send-link" && info.linkUrl) {
      const result = await sendLink(info.linkUrl, info.linkText);
      flash(tab?.id, result.queued ? "queued" : result.created ? "ok" : "seen");
    }
  } catch (err) {
    flash(tab?.id, "error");
    if (err instanceof NotSignedIn) return chrome.runtime.openOptionsPage();
    const what = { "send-page": "the page", "send-link": "the link", "save-rule": "the selection" }[info.menuItemId];
    if (what) {
      chrome.notifications.create({
        type: "basic",
        iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
        title: `IntelFeed couldn’t take ${what}`,
        message: err?.message || String(err),
      });
    }
  }
});

// ── what the server knows about a page (cached briefly) ──────────────

const LOOKUP_MAX_AGE = 5 * 60 * 1000;
const FEEDS_MAX_AGE = 30 * 60 * 1000;
const lookups = new Map(); // url → {entry | null, at}
let followed = null; // {urls: Set, at}

const stripHash = (url) => String(url).split("#", 1)[0];

async function lookupEntry(url) {
  const key = stripHash(url);
  const hit = lookups.get(key);
  if (hit && Date.now() - hit.at < LOOKUP_MAX_AGE) return hit.entry;
  const res = await request("/api/entries/ingest/lookup", { query: { url: key }, raw: true });
  const entry = res.status === 200 ? res.body : null;
  if (lookups.size > 500) lookups.clear();
  lookups.set(key, { entry, at: Date.now() });
  return entry;
}

/** The URLs of every feed the user can see, so the popup and dot can say "already followed". */
async function followedFeeds() {
  if (followed && Date.now() - followed.at < FEEDS_MAX_AGE) return followed.urls;
  const page = await request("/api/feeds", { query: { limit: 1000 } });
  // Lower-cased too: reddit.com/r/Malware and /r/malware are one subreddit.
  followed = { urls: new Set((page.items || []).flatMap((f) => [f.url, f.url.toLowerCase()])), at: Date.now() };
  return followed.urls;
}

const isFollowed = (follows, url) => follows.has(url) || follows.has(url.toLowerCase());

const repoUrl = (repo) => `https://github.com/${repo.owner}/${repo.repo}`;

// ── the toolbar dot and badge ─────────────────────────────────────────
//
// Per tab: a green dot when the page is already in IntelFeed, an
// accent-colored one when the site offers a feed (or is a GitHub repo) the
// user doesn't follow yet. A send flashes ✓ or ! for a few seconds, then the
// dot comes back.

// Per tab: {url, collected, followable}, kept in storage.session under
// `tab:<id>` so it survives the worker being stopped between events.
const tabKey = (tabId) => `tab:${tabId}`;
const getTab = async (tabId) => (await chrome.storage.session.get(tabKey(tabId)))[tabKey(tabId)];
const setTab = (tabId, state) => chrome.storage.session.set({ [tabKey(tabId)]: state });
const dropTab = (tabId) => chrome.storage.session.remove(tabKey(tabId));
const flashing = new Set();

const BADGES = {
  ok: { text: "✓", color: "#2e7d32" },
  seen: { text: "✓", color: "#546e7a" },
  error: { text: "!", color: "#c62828" },
  queued: { text: "…", color: "#546e7a" },
};

async function setDot(tabId) {
  if (tabId == null || flashing.has(tabId)) return;
  const { features, access, server, outbox, theme } = await store.load();
  const state = await getTab(tabId);
  let text = "";
  let color = "#2e7d32";
  if (features.pageDot && access && state) {
    if (state.collected) {
      text = "●";
      color = theme?.vars?.success || "#2e7d32";
    } else if (state.followable) {
      text = "●";
      color = theme?.vars?.accent || "#2563eb";
    }
  }
  try {
    // No dot: the same badge showSessionState sets for every tab, since a
    // tab's own badge hides it. Signed out shows !, else the number of sends
    // waiting for the server, if any.
    if (!text && server && !access) {
      text = "!";
      color = "#c62828";
    } else if (!text && outbox.length) {
      text = String(outbox.length);
      color = "#546e7a";
    }
    await chrome.action.setBadgeBackgroundColor({ tabId, color });
    await chrome.action.setBadgeText({ tabId, text });
  } catch {
    // the tab closed
  }
}

function flash(tabId, kind) {
  if (tabId == null) return;
  const badge = BADGES[kind];
  flashing.add(tabId);
  chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
  chrome.action.setBadgeText({ tabId, text: badge.text });
  setTimeout(() => {
    flashing.delete(tabId);
    setDot(tabId);
  }, 4000);
}

/** Redraw the badge on every open tab, after a change that affects all of them. */
async function redrawDots() {
  for (const t of await chrome.tabs.query({})) setDot(t.id);
}

chrome.tabs.onRemoved.addListener((tabId) => dropTab(tabId));

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (!changeInfo.url) return;
  const state = await getTab(tabId);
  if (state && stripHash(state.url) === stripHash(changeInfo.url)) return;
  await dropTab(tabId);
  setDot(tabId);
  // A page that changes its URL without loading (a single-page app) keeps the
  // same page script: ask it to look again once the new view has rendered.
  setTimeout(() => chrome.tabs.sendMessage(tabId, { type: "rescan" }).catch(() => {}), 1500);
});

// ── the page script ───────────────────────────────────────────────────

let pageScriptQueue = Promise.resolve();

/**
 * Register the page script when the user has allowed it and wants the dot or
 * highlighting; else remove it. Several events can ask at once (a settings
 * save and its storage change), so the calls run one after another: two
 * overlapping unregister/register runs fail with a duplicate script id.
 */
function syncPageScript() {
  const run = pageScriptQueue.then(registerPageScript);
  pageScriptQueue = run.catch(() => {});
  return run;
}

async function registerPageScript() {
  const { server, access, features } = await store.load();
  const granted = await chrome.permissions.contains(ALL_SITES);
  const want = Boolean(granted && server && access && (features.pageDot || features.highlight || features.contextPanel));
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [PAGE_SCRIPT] });
  if (existing.length) await chrome.scripting.unregisterContentScripts({ ids: [PAGE_SCRIPT] });
  if (!want) return;
  await chrome.scripting.registerContentScripts([
    {
      id: PAGE_SCRIPT,
      matches: ALL_SITES.origins,
      // IntelFeed itself already links its entities.
      excludeMatches: [originPattern(server)],
      js: ["src/content/matcher.js", "src/content/page.js"],
      runAt: "document_idle",
    },
  ]);
}

const siteOf = (url) => {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
};

async function highlightAllowed(url) {
  const { features, disabledSites } = await store.load();
  return features.highlight && !disabledSites.includes(siteOf(url));
}

async function pageSeen(tabId, { url, feeds }) {
  const { access, features } = await store.load();
  if (!access) return { highlight: false };
  const page = { url, feeds: Array.isArray(feeds) ? feeds.slice(0, 50) : [] };
  const state = { url, collected: false, followable: false };
  await setTab(tabId, state);
  if (features.pageDot) {
    try {
      const [entry, follows] = await Promise.all([lookupEntry(url), followedFeeds()]);
      state.collected = Boolean(entry);
      const repo = githubRepo(page);
      state.followable =
        siteFeeds(page).some((f) => !isFollowed(follows, f.url)) || Boolean(repo && !follows.has(repoUrl(repo)));
      await setTab(tabId, state);
    } catch {
      // offline or signed out: no dot
    }
    await setDot(tabId);
  }
  const highlight = await highlightAllowed(url);
  const wantTheme = highlight || features.contextPanel;
  return {
    highlight,
    contextPanel: features.contextPanel,
    theme: wantTheme ? await loadTheme().catch(() => null) : null,
  };
}

const SCAN_MAX_AGE = 10 * 60 * 1000;
const scans = new Map(); // url → {matches, at}

async function scan({ url, text }) {
  if (!(await highlightAllowed(url))) return { matches: [] };
  const key = stripHash(url);
  const hit = scans.get(key);
  if (hit && Date.now() - hit.at < SCAN_MAX_AGE) return { matches: hit.matches };
  const [{ server }, theme, found] = await Promise.all([
    store.load(),
    loadTheme().catch(() => null),
    request("/api/autolink/scan", { method: "POST", body: { text: String(text).slice(0, 120000) } }),
  ]);
  const colors = theme?.entityColors || {};
  const modes = await watchModes().catch(() => new Map());
  const matches = (found.matches || []).map((m) => {
    const e = m.entity || {};
    // Facts, badges, aliases and links as the app's popover shows them
    const view = cardView(m.entity_type, e, m.canonical_name);
    if (view.image && !/^https:\/\//i.test(view.image)) view.image = null;
    return {
      type: m.entity_type,
      id: m.entity_id,
      name: m.canonical_name,
      forms: m.surface_forms || [],
      description: String(view.description).slice(0, 5000),
      view,
      articleCount: typeof e.article_count === "number" ? e.article_count : null,
      color: colors[m.entity_type] || null,
      href: `${server}/workbench/${m.entity_type}/${encodeURIComponent(m.entity_id)}`,
      searchHref: lookupUrl(server, m.canonical_name),
      ...watchState(m.entity_type, modes.get(`${m.entity_type}:${m.entity_id}`)),
    };
  });
  if (scans.size > 200) scans.clear();
  scans.set(key, { matches, at: Date.now() });
  return { matches };
}

// ── hover card actions ────────────────────────────────────────────────

let watches = null; // {modes: Map("type:id" → watch | mute | stack), at}

async function watchModes({ fresh = false } = {}) {
  if (!fresh && watches && Date.now() - watches.at < LOOKUP_MAX_AGE) return watches.modes;
  const rows = await request("/api/intelligence/watchlist");
  watches = { modes: new Map(rows.map((w) => [`${w.entity_type}:${w.entity_id}`, w.mode])), at: Date.now() };
  return watches.modes;
}

async function setWatch({ entityType: type, id, on }) {
  const key = `${type}:${id}`;
  // The watchlist keeps one mode per entity, so watching a muted entity or one
  // in My Stack would replace that mode. The card offers no button for them;
  // this refuses a stale card's click.
  if (!WATCHABLE.has(type)) throw new Error("This type of entity can't be added to the watchlist.");
  const modes = await watchModes({ fresh: true });
  if (!watchState(type, modes.get(key)).watchable) {
    throw new Error("This entity is muted or in My Stack. Change it in IntelFeed.");
  }
  if (on) {
    await request("/api/intelligence/watchlist", { method: "PUT", body: { entity_type: type, entity_id: id, mode: "watch" } });
    modes.set(key, "watch");
  } else {
    await request(`/api/intelligence/watchlist/${type}/${id}`, { method: "DELETE" });
    modes.delete(key);
  }
  return { watched: on };
}

// The latest articles about a highlighted entity, for its hover card.
const RECENT_DAYS = 90;
const RECENT_MAX_AGE = 5 * 60 * 1000;
const recentArticles = new Map(); // "type:id" → {items, at}

async function entityArticles({ entityType, id }) {
  const key = `${entityType}:${id}`;
  const hit = recentArticles.get(key);
  if (hit && Date.now() - hit.at < RECENT_MAX_AGE) return hit.items;
  const { server } = await store.load();
  const end = new Date(Date.now() + 60 * 1000);
  const start = new Date(end.getTime() - RECENT_DAYS * 24 * 3600 * 1000);
  const found = await request(`/api/entities/${entityType}/${encodeURIComponent(id)}/entries-window`, {
    query: { start: start.toISOString(), end: end.toISOString(), limit: 3 },
  });
  const items = (found.items || []).map((e) => ({
    title: e.title,
    feed: e.feed_title,
    published: e.published_at,
    href: `${server}/?entry=${encodeURIComponent(e.entry_id)}`,
  }));
  if (recentArticles.size > 300) recentArticles.clear();
  recentArticles.set(key, { items, at: Date.now() });
  return items;
}

async function intelProfiles() {
  const page = await request("/api/intel-profiles", { query: { limit: 100 } });
  return (page.items || []).map((p) => ({ id: p.id, name: p.name, countryIds: p.country_ids || [] }));
}

/** Add a country to an intel profile's regions. Intel profiles are scoped by countries and sectors only. */
async function addCountryToProfile({ profileId, countryId }) {
  const profile = await request(`/api/intel-profiles/${profileId}`);
  const ids = new Set(profile.country_ids || []);
  if (ids.has(countryId)) return { added: false, name: profile.name };
  ids.add(countryId);
  await request(`/api/intel-profiles/${profileId}`, { method: "PUT", body: { country_ids: [...ids] } });
  return { added: true, name: profile.name };
}

// ── the CVE / ATT&CK panel ────────────────────────────────────────────

let exposure = null; // {items, at}

async function stackExposure() {
  if (exposure && Date.now() - exposure.at < SCAN_MAX_AGE) return exposure.items;
  const data = await request("/api/intelligence/exposure");
  exposure = { items: data.items || [], at: Date.now() };
  return exposure.items;
}

async function pageContext({ kind, id }) {
  const { server, features } = await store.load();
  if (!features.contextPanel) return null;
  if (kind === "cve") {
    const res = await request(`/api/cves/${encodeURIComponent(id)}`, { raw: true });
    if (res.status === 404) return { kind, id, found: false, server };
    const cve = res.body;
    const [stack, rules] = await Promise.all([
      stackExposure().catch(() => []),
      request("/api/detection-rules", { query: { cve: id, limit: 1 } }).catch(() => null),
    ]);
    return {
      kind,
      id,
      found: true,
      href: `${server}/workbench/cve/${cve.id}`,
      cvss: cve.cvss_score,
      severity: cve.severity,
      epss: cve.epss_score,
      kev: cve.is_kev,
      kevDue: cve.kev_due_date,
      exploit: cve.exploit_availability || cve.exploit_status,
      articles: cve.article_count,
      stack: stack.filter((i) => i.cve_id === id).map((i) => ({ asset: i.asset_name, posture: i.posture })),
      rules: rules ? rules.total : null,
    };
  }
  if (kind === "ttp") {
    const res = await request(`/api/ttps/by-technique/${encodeURIComponent(id)}`, { raw: true });
    if (res.status === 404) return { kind, id, found: false, server };
    const ttp = res.body;
    const end = new Date();
    const start = new Date(end.getTime() - 90 * 24 * 3600 * 1000);
    const [rules, recent] = await Promise.all([
      request("/api/detection-rules", { query: { technique: id, limit: 1 } }).catch(() => null),
      request(`/api/entities/ttp/${ttp.id}/entries-window`, {
        query: { start: start.toISOString(), end: end.toISOString(), limit: 5 },
      }).catch(() => ({ items: [] })),
    ]);
    return {
      kind,
      id,
      found: true,
      name: ttp.technique_name,
      href: `${server}/workbench/ttp/${ttp.id}`,
      rules: rules ? rules.total : null,
      recent: (recent.items || []).map((e) => ({
        title: e.title,
        feed: e.feed_title,
        published: e.published_at,
        href: `${server}/?entry=${encodeURIComponent(e.entry_id)}`,
      })),
    };
  }
  return null;
}

// ── send to report ────────────────────────────────────────────────────

async function draftReports() {
  const page = await request("/api/intel-reports", { query: { status: "draft", limit: 50 } });
  return (page.items || []).map((r) => ({ id: r.id, title: r.title }));
}

/** Add the page to IntelFeed if it isn't there yet, then attach that article to a draft report. */
async function sendToReport({ tabId, reportId, note, tagIds }) {
  const entry = await sendTab(tabId, { note, tagIds });
  if (entry.queued) {
    throw new Error("IntelFeed can't be reached, so the page is waiting to send. Add it to the report after it has been sent.");
  }
  await request(`/api/intel-reports/${reportId}/attach`, { method: "POST", body: { entry_ids: [entry.id] } });
  const { server } = await store.load();
  return { entryId: entry.id, href: `${server}/workbench/report/${reportId}` };
}

// ── the "save as detection rule" window ───────────────────────────────

async function pendingRule({ key }) {
  const data = (await chrome.storage.session.get(`rule:${key}`))[`rule:${key}`];
  if (!data) throw new Error("The selected text is no longer available. Select it again and use the right-click menu.");
  // The rule window keeps it from here.
  await chrome.storage.session.remove(`rule:${key}`);
  let entry = null;
  try {
    entry = await lookupEntry(data.url);
  } catch {
    entry = null;
  }
  return { ...data, entryId: entry?.id || null };
}

async function saveRule({ ruleType, title, content, url, entryId }) {
  const { server } = await store.load();
  const rule = await request("/api/detection-rules", {
    method: "POST",
    body: {
      rule_type: ruleType,
      title,
      rule_content: content,
      description: url ? `Saved from ${url}` : null,
      entry_id: entryId || null,
      is_draft: true,
      metadata: url ? { source_url: url, saved_with: CLIENT } : { saved_with: CLIENT },
    },
  });
  return { id: rule.id, href: `${server}/workbench/rule/${rule.id}` };
}

async function convertRule({ id, targetType }) {
  const { server } = await store.load();
  const out = await request(`/api/detection-rules/${id}/convert`, { method: "POST", body: { target_type: targetType } });
  return { id: out.rule_id, title: out.title, href: `${server}/workbench/rule/${out.rule_id}` };
}

// ── popup work ────────────────────────────────────────────────────────

async function capture(tabId, includeHtml) {
  const [result] = await chrome.scripting.executeScript({
    target: { tabId },
    func: capturePage,
    args: [includeHtml],
  });
  if (!result?.result) throw new Error("The browser does not allow extensions to read this page.");
  return result.result;
}

/** The tab's page, read by capture.js; or, for a PDF the browser's viewer shows, `{pdf: true}`. */
async function readTab(tabId, includeHtml) {
  try {
    return await capture(tabId, includeHtml);
  } catch (err) {
    const tab = await chrome.tabs.get(tabId);
    if (/^https?:/i.test(tab.url || "") && (isPdfUrl(tab.url) || (await servesPdf(tab.url)))) {
      return { pdf: true, url: tab.url, title: tab.title || "", selection: "" };
    }
    throw err;
  }
}

async function servesPdf(url) {
  try {
    const resp = await fetch(url, { method: "HEAD", credentials: "include" });
    return isPdfType(resp.headers.get("content-type"));
  } catch {
    return false;
  }
}

async function pageStatus(tabId) {
  const page = await readTab(tabId, false);
  // The popup still opens, with Send on, when the server can't be reached or
  // can't look the page up (an address over 4000 characters): the send then
  // waits in the outbox or gets the server's own error.
  let lookupError = null;
  const [entry, tags, follows, { features, disabledSites }, allSites] = await Promise.all([
    unlessSignedOut(lookupEntry(page.url), (err) => {
      lookupError = err;
      return null;
    }),
    unlessSignedOut(request("/api/tags"), () => []),
    page.pdf ? new Set() : followedFeeds().catch(() => new Set()),
    store.load(),
    chrome.permissions.contains(ALL_SITES),
  ]);
  const repo = page.pdf ? null : githubRepo(page);
  const site = siteOf(page.url);
  return {
    url: page.url,
    title: page.title,
    site,
    pdf: Boolean(page.pdf),
    hasSelection: Boolean(page.selection),
    selection: String(page.selection || "").slice(0, 4000),
    feeds: page.pdf ? [] : siteFeeds(page).map((f) => ({ ...f, followed: isFollowed(follows, f.url) })),
    repo: repo && { ...repo, followed: follows.has(repoUrl(repo)) },
    entry,
    checked: !lookupError,
    offline: Boolean(lookupError && isRetryable(lookupError)),
    tags: tags.map(({ id, name, color }) => ({ id, name, color })),
    allSites,
    highlight: { feature: features.highlight, site: !disabledSites.includes(site) },
  };
}

/** What a send answered with: remember it, and follow its results when it is new. */
async function afterSend(url, result, title) {
  lookups.set(stripHash(url), { entry: result, at: Date.now() });
  if (result.created) await watchResults(result.id, result.title || title);
}

async function sendTab(tabId, { note, tagIds }) {
  try {
    const page = await readTab(tabId, true);
    const result = page.pdf ? await sendPdf(page, { note, tagIds }) : await sendPage(page, { note, tagIds });
    const state = await getTab(tabId);
    if (state && !result.queued) await setTab(tabId, { ...state, collected: true });
    flash(tabId, result.queued ? "queued" : result.created ? "ok" : "seen");
    return result;
  } catch (err) {
    flash(tabId, "error");
    throw err;
  }
}

/** POST a page; when the server can't be reached, keep it in the outbox. */
async function sendPage(page, { note, tagIds }) {
  const body = ingestBody(page, { note, tagIds, client: CLIENT });
  try {
    const result = await request("/api/entries/ingest/page", { method: "POST", body });
    await afterSend(page.url, result, page.title);
    return result;
  } catch (err) {
    if (!isRetryable(err)) throw err;
    return queueSend({ kind: "page", body, title: page.title });
  }
}

async function sendLink(url, title) {
  const body = { url, client: CLIENT };
  try {
    const result = await request("/api/entries/ingest/page", { method: "POST", body });
    await afterSend(url, result, title);
    return result;
  } catch (err) {
    if (!isRetryable(err)) throw err;
    return queueSend({ kind: "link", body, title: title || url });
  }
}

// ── PDFs ──────────────────────────────────────────────────────────────
//
// The browser's PDF viewer can't be read by an extension, so the file itself
// is fetched (with the browser's cookies, so signed-in and intranet PDFs
// work) and uploaded. PDFs are not queued when the server is down: they can
// be tens of megabytes.

let capabilities = null; // {maxBytes, at}

async function maxPdfBytes() {
  if (capabilities && Date.now() - capabilities.at < FEEDS_MAX_AGE) return capabilities.maxBytes;
  const caps = await request("/api/entries/ingest/capabilities");
  capabilities = { maxBytes: (caps.max_file_mb || 50) * 1024 * 1024, at: Date.now() };
  return capabilities.maxBytes;
}

async function sendPdf(page, { note, tagIds }) {
  let blob;
  try {
    const resp = await fetch(page.url, { credentials: "include" });
    if (!resp.ok) throw new Error(`The PDF could not be downloaded (${resp.status}).`);
    blob = await resp.blob();
  } catch (err) {
    throw err instanceof TypeError ? new Error("The PDF could not be downloaded from this site.") : err;
  }
  const limit = await maxPdfBytes();
  if (blob.size > limit) {
    throw new Error(`This PDF is ${Math.ceil(blob.size / 1048576)} MB; IntelFeed accepts up to ${Math.round(limit / 1048576)} MB.`);
  }
  const form = new FormData();
  form.append("file", new Blob([blob], { type: "application/pdf" }), pdfFileName(page.url, page.title));
  form.append("url", page.url);
  if (note && note.trim()) form.append("note", note.trim());
  for (const id of tagIds || []) form.append("tag_ids", id);
  try {
    const out = await request("/api/entries/ingest/pdf", { method: "POST", form });
    const result = { id: out.id, title: out.title, url: out.url, created: true };
    await afterSend(page.url, result, page.title);
    return result;
  } catch (err) {
    const existing = err instanceof ApiError && err.status === 409 && err.details?.[0]?.entry_id;
    if (existing) {
      const result = { id: existing, title: page.title, created: false };
      lookups.set(stripHash(page.url), { entry: result, at: Date.now() });
      return result;
    }
    if (isRetryable(err)) throw new Error("IntelFeed can't be reached. Send the PDF again once it is back.");
    throw err;
  }
}

// ── the outbox ────────────────────────────────────────────────────────
//
// A page or link send that can't reach the server waits in storage and goes
// out, oldest first, after the next successful session renewal, on startup,
// every 5 minutes while anything waits, or from the popup's Send now.

async function queueSend(item) {
  const { outbox } = await store.load();
  const { queue, downgraded } = enqueue(outbox, item);
  await store.save({ outbox: queue });
  chrome.alarms.create(OUTBOX_ALARM, { periodInMinutes: 5 });
  return { queued: true, downgraded, waiting: queue.length };
}

let flushing = null;

function flushOutbox() {
  flushing ??= (async () => {
    let sent = 0;
    for (;;) {
      const { outbox, outboxFailed } = await store.load();
      const item = outbox[0];
      if (!item) break;
      try {
        const result = await request("/api/entries/ingest/page", { method: "POST", body: item.body });
        await afterSend(item.url, result, item.title);
        sent += 1;
        await store.save({ outbox: (await store.load()).outbox.slice(1) });
      } catch (err) {
        if (err instanceof NotSignedIn || isRetryable(err)) break; // try again later
        await store.save({
          outbox: (await store.load()).outbox.slice(1),
          outboxFailed: addFailed(outboxFailed, item, err.message),
        });
      }
    }
    if (!(await store.load()).outbox.length) chrome.alarms.clear(OUTBOX_ALARM);
    return sent;
  })().finally(() => {
    flushing = null;
  });
  return flushing;
}

async function outboxStatus() {
  const { outbox, outboxFailed } = await store.load();
  const pick = ({ title, url, queuedAt, kind }) => ({ title, url, queuedAt, kind });
  return { waiting: outbox.map(pick), failed: outboxFailed };
}

// ── results after a send ──────────────────────────────────────────────
//
// A new page goes through the pipeline (linking, AI analysis, scoring) over
// the next minutes. Poll each one once a minute for up to 30 minutes and say
// what came out of it.

const WATCH_FOR = 30 * 60 * 1000;

async function watchResults(entryId, title) {
  const { watching } = await store.load();
  if (watching.some((w) => w.entryId === entryId)) return;
  await store.save({ watching: [...watching, { entryId, title, sentAt: Date.now() }].slice(-20) });
  chrome.alarms.create(RESULTS_ALARM, { periodInMinutes: 1 });
}

async function pollResults() {
  const { watching, features } = await store.load();
  const keep = [];
  for (const w of watching) {
    if (Date.now() - w.sentAt > WATCH_FOR) continue;
    let results;
    try {
      results = await request(`/api/entries/ingest/${w.entryId}/results`);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) continue; // deleted, or no longer visible
      keep.push(w); // offline: next minute
      continue;
    }
    if (results.state === "processing") {
      keep.push(w);
      continue;
    }
    if (features.notifyResults) {
      chrome.notifications.create(`entry:${w.entryId}`, {
        type: "basic",
        iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
        title: `IntelFeed finished “${(w.title || "the page").slice(0, 80)}”`,
        message: notificationText(results),
      });
    }
  }
  await store.save({ watching: keep });
  if (!keep.length) chrome.alarms.clear(RESULTS_ALARM);
}

chrome.notifications.onClicked.addListener(async (id) => {
  if (!id.startsWith("entry:")) return;
  const { server } = await store.load();
  if (server) await chrome.tabs.create({ url: `${server}/?entry=${encodeURIComponent(id.slice(6))}` });
  chrome.notifications.clear(id);
});

// ── story context ─────────────────────────────────────────────────────

const coverages = new Map(); // url → {data, at}

async function pageCoverage({ url, title }) {
  const key = stripHash(url);
  const hit = coverages.get(key);
  if (hit && Date.now() - hit.at < LOOKUP_MAX_AGE) return hit.data;
  const data = await request("/api/entries/ingest/coverage", { query: { title, url: key } });
  if (coverages.size > 100) coverages.clear();
  coverages.set(key, { data, at: Date.now() });
  return data;
}

// ── telemetry source notes ────────────────────────────────────────────

let catalog = null; // {names, at}

async function telemetryOptions({ url, title }) {
  if (!catalog || Date.now() - catalog.at > FEEDS_MAX_AGE) {
    const [items, inventory] = await Promise.all([
      request("/api/telemetry-sources/catalog"),
      request("/api/telemetry-sources", { query: { limit: 500 } }).catch(() => ({ items: [] })),
    ]);
    const names = new Set([...items.map((i) => i.name), ...(inventory.items || []).map((i) => i.name)]);
    catalog = { names: [...names].sort((a, b) => a.localeCompare(b)), at: Date.now() };
  }
  const [suggestions, { telemetryPicks, noteKind }] = await Promise.all([
    request("/api/telemetry-sources/notes/suggest", { query: { url, title: title || "" } }).catch(() => []),
    store.load(),
  ]);
  return {
    names: catalog.names,
    suggestions,
    preferred: preferredSource(telemetryPicks, url, suggestions),
    lastKind: noteKind,
    // Entities the page highlighter already found here, as suggestions for an entity note
    pageEntities: (scans.get(stripHash(url))?.matches || [])
      .filter((m) => NOTE_ENTITY_TYPES.includes(m.type))
      .slice(0, 8)
      .map(({ type, id, name }) => ({ type, id, name })),
  };
}

async function searchNoteEntities({ q }) {
  const found = await request("/api/intelligence/search", {
    query: { q, limit: 8, entity_types: NOTE_ENTITY_TYPES.join(",") },
  });
  return (found.results || []).map(entityOption).filter(Boolean);
}

/** Save the page as a note on an entity, or as a note of its own. */
async function saveNote({ kind, entity, title, url, pageTitle, quote, content }) {
  const markdown = linkNoteMarkdown({ url, pageTitle, quote, content });
  const { server } = await store.load();
  if (kind === "entity") {
    await request("/api/entity-notes", {
      method: "POST",
      body: {
        entity_type: entity.type,
        entity_id: entity.id,
        title: (pageTitle || "").slice(0, 500) || null,
        content: markdown,
        note_type: "context",
      },
    });
    await store.save({ noteKind: kind });
    return { savedTo: entity.name, href: `${server}/workbench/${entity.type}/${encodeURIComponent(entity.id)}` };
  }
  await request("/api/notes", {
    method: "POST",
    body: { title: (title || pageTitle || url).slice(0, 500), content_markdown: markdown },
  });
  await store.save({ noteKind: kind });
  return { savedTo: "your notes", href: null };
}

async function saveTelemetryNote({ sourceName, url, pageTitle, quote, content }) {
  const note = await request("/api/telemetry-sources/notes", {
    method: "POST",
    body: {
      source_name: sourceName,
      url,
      page_title: (pageTitle || "").slice(0, 500) || null,
      quote: quote || null,
      content: content || null,
    },
  });
  const { telemetryPicks, server } = await store.load();
  await store.save({ telemetryPicks: rememberPick(telemetryPicks, url, note.source_name), noteKind: "telemetry" });
  return {
    sourceName: note.source_name,
    href: `${server}/workbench/explore?section=telemetry&source=${encodeURIComponent(note.source_name)}`,
  };
}

// A site that advertises no feed: the server looks at its usual feed
// addresses (POST /api/feeds/discover). One answer per site for a day.
const DISCOVER_MAX_AGE = 24 * 60 * 60 * 1000;
const discovered = new Map(); // origin → {feed, at}

async function discoverFeed({ url }) {
  const origin = new URL(url).origin;
  let hit = discovered.get(origin);
  if (!hit || Date.now() - hit.at > DISCOVER_MAX_AGE) {
    let feed = null;
    try {
      const found = await request("/api/feeds/discover", { method: "POST", body: { url } });
      feed = { url: found.url, title: found.title || "" };
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 422)) throw err;
    }
    if (discovered.size > 200) discovered.clear();
    hit = { feed, at: Date.now() };
    discovered.set(origin, hit);
  }
  if (!hit.feed) return null;
  const follows = await followedFeeds().catch(() => new Set());
  return { ...hit.feed, followed: isFollowed(follows, hit.feed.url) };
}

async function subscribe(body) {
  try {
    const feed = await request("/api/feeds", { method: "POST", body });
    followed = null;
    return { subscribed: true, feed };
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) return { subscribed: false, message: err.message };
    throw err;
  }
}

async function setSiteHighlight({ site, on, tabId }) {
  const { disabledSites } = await store.load();
  const next = new Set(disabledSites);
  if (on) next.delete(site);
  else next.add(site);
  await store.save({ disabledSites: [...next].sort() });
  if (tabId != null) chrome.tabs.sendMessage(tabId, { type: on ? "rescan" : "unhighlight" }).catch(() => {});
}

// ── messages ──────────────────────────────────────────────────────────

// From the extension's own pages (popup, settings).
const PAGE_HANDLERS = {
  async session() {
    const { server, username, access, features } = await store.load();
    const [allSites, registered] = await Promise.all([
      chrome.permissions.contains(ALL_SITES),
      chrome.scripting.getRegisteredContentScripts({ ids: [PAGE_SCRIPT] }),
    ]);
    return { server, username, signedIn: Boolean(access), features, allSites, pageScript: registered.length > 0 };
  },
  async signIn({ server, username, password }) {
    const result = await signIn(server, username, password);
    await loadTheme({ force: true }).catch(() => null);
    return result;
  },
  signOut: () => signOut(),
  me: () => request("/api/auth/me"),
  // The popup and settings page fetch it every time they open, so a theme picked in the app shows at once.
  refreshTheme: () => loadTheme({ force: true }),
  setFeatures: async ({ features }) => {
    await store.save({ features });
    await syncPageScript();
  },
  syncPageScript: () => syncPageScript(),
  pageStatus: ({ tabId }) => pageStatus(tabId),
  send: ({ tabId, note, tagIds }) => sendTab(tabId, { note, tagIds }),
  results: ({ entryId }) => request(`/api/entries/ingest/${entryId}/results`),
  coverage: (message) => pageCoverage(message),
  outbox: () => outboxStatus(),
  flushOutbox: () => flushOutbox(),
  discardOutbox: async () => {
    await store.save({ outbox: [], outboxFailed: [] });
    chrome.alarms.clear(OUTBOX_ALARM);
  },
  telemetryOptions: (message) => telemetryOptions(message),
  saveTelemetryNote: (message) => saveTelemetryNote(message),
  searchNoteEntities: (message) => searchNoteEntities(message),
  saveNote: (message) => saveNote(message),
  subscribe: ({ url, subreddit }) => subscribe(subreddit ? redditFeedBody(subreddit) : { url }),
  discoverFeed: (message) => discoverFeed(message),
  trackRepo: ({ repo }) => subscribe(repoFeedBody(repo)),
  setSiteHighlight: (message) => setSiteHighlight(message),
  update: () => updateStatus(),
  checkForUpdate: async () => {
    await checkForUpdate();
    return updateStatus();
  },
  reports: () => draftReports(),
  sendToReport: (message) => sendToReport(message),
  pendingRule: (message) => pendingRule(message),
  validateRule: ({ ruleType, content }) =>
    request("/api/detection-rules/validate", { method: "POST", body: { rule_type: ruleType, rule_content: content } }),
  saveRule: (message) => saveRule(message),
  convertRule: (message) => convertRule(message),
};

// From the page script running in a web page. Web pages themselves can't
// reach these (only the extension's own script in the page can), and none of
// them take a tab id from the page.
const CONTENT_HANDLERS = {
  pageSeen: (message, sender) => pageSeen(sender.tab.id, message),
  scan: (message) => scan(message),
  context: (message) => pageContext(message),
  watch: (message) => setWatch(message),
  profiles: () => intelProfiles(),
  articles: (message) => entityArticles(message),
  addToProfile: (message) => addCountryToProfile(message),
};

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id) return false;
  const fromExtensionPage = sender.url?.startsWith(chrome.runtime.getURL(""));
  const handler = fromExtensionPage
    ? PAGE_HANDLERS[message?.type]
    : sender.tab && sender.frameId === 0
      ? CONTENT_HANDLERS[message?.type]
      : null;
  if (!handler) return false;
  Promise.resolve()
    .then(() => handler(message, sender))
    .then(
      (data) => reply(fromExtensionPage ? { ok: true, data } : data),
      (err) =>
        reply(
          fromExtensionPage
            ? { ok: false, error: err?.message || String(err), notSignedIn: err instanceof NotSignedIn, status: err?.status }
            : { error: err?.message || String(err) },
        ),
    );
  return true;
});
