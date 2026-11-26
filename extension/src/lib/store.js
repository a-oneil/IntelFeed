// chrome.storage.local: the server, the signed-in session (the same
// access/refresh pair the web app holds — never the password), the feature
// switches, the sites highlighting is off for, the user's IntelFeed theme, and
// sends waiting for the server. Short-lived state lives elsewhere: per-tab
// badge state and the text for the rule window in chrome.storage.session,
// lookup caches in the background worker's memory.

const DEFAULT_FEATURES = {
  // Right-click "Look up in IntelFeed" on selected text.
  lookupMenu: true,
  // A dot on the toolbar button: green when the page is already in
  // IntelFeed, accent-colored when the site has a feed or repo you don't follow.
  pageDot: true,
  // Highlight known entities on the page, with a card on hover.
  highlight: true,
  // On a CVE page (NVD, cve.org, a vendor advisory) or an ATT&CK technique
  // page, a panel with what IntelFeed knows about it.
  contextPanel: true,
  // A notification when IntelFeed has finished with a page you sent, saying what it found.
  notifyResults: true,
};

const KEYS = [
  "server",
  "username",
  "access",
  "refresh",
  "features",
  "disabledSites",
  "theme",
  "update",
  // Sends waiting for the server (lib/outbox.js), and the ones it refused.
  "outbox",
  "outboxFailed",
  // Pages sent this session whose results haven't come back yet.
  "watching",
  // Telemetry source picked per part of a site (lib/telemetry.js).
  "telemetryPicks",
  // The kind of note last saved from the popup (lib/notes.js).
  "noteKind",
];

export async function load() {
  const data = await chrome.storage.local.get(KEYS);
  return {
    ...data,
    features: { ...DEFAULT_FEATURES, ...(data.features || {}) },
    disabledSites: data.disabledSites || [],
    outbox: data.outbox || [],
    outboxFailed: data.outboxFailed || [],
    watching: data.watching || [],
    telemetryPicks: data.telemetryPicks || {},
  };
}

export async function save(patch) {
  await chrome.storage.local.set(patch);
}

export async function clearSession() {
  await chrome.storage.local.remove(["access", "refresh"]);
}
