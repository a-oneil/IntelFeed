import { normalizeServer, originPattern } from "../lib/api.js";
import { drawLogos } from "../lib/logo.js";
import { call } from "../lib/messages.js";
import * as store from "../lib/store.js";
import { useTheme } from "../lib/theme.js";

useTheme();
drawLogos();
call("refreshTheme").catch(() => {});

const ALL_SITES = { origins: ["http://*/*", "https://*/*"] };
const $ = (id) => document.getElementById(id);

function result(id, text, tone) {
  const el = $(id);
  el.className = `${tone || "muted"} small`;
  el.textContent = text;
}

// ── sections and navigation ───────────────────────────────────────────
//
// One nav entry per <section class="panel" data-title>, one section shown at
// a time, the open one kept in the URL hash.

const panels = [...document.querySelectorAll("section.panel[data-title]")];

function buildNav() {
  const nav = $("nav");
  nav.replaceChildren();
  for (const panel of panels) {
    const a = document.createElement("a");
    a.href = `#${panel.id}`;
    a.textContent = panel.dataset.title;
    nav.append(a);
  }
}

function showSection() {
  const id = location.hash.slice(1);
  const current = panels.find((p) => p.id === id) || panels[0];
  for (const panel of panels) panel.hidden = panel !== current;
  for (const a of $("nav").querySelectorAll("a")) {
    a.setAttribute("aria-current", String(a.getAttribute("href") === `#${current.id}`));
  }
}

buildNav();
showSection();
window.addEventListener("hashchange", showSection);

// ── state ─────────────────────────────────────────────────────────────

function pageStatusText(session) {
  if (!session.signedIn) return ["Status: not running on web pages, because you are not signed in.", "warn"];
  if (!session.allSites) {
    return ["Status: not running on web pages, because the permission to read all websites has not been granted.", "warn"];
  }
  if (!session.features.pageDot && !session.features.highlight && !session.features.contextPanel) {
    return ["Status: not running on web pages, because all the features below are turned off.", "warn"];
  }
  if (!session.pageScript) {
    return ["Status: not running on web pages yet. Reload the extension from your browser's extensions page.", "warn"];
  }
  return ["Status: running on web pages. Pages that were open before you changed a setting need to be reloaded.", "ok"];
}

async function render() {
  const session = await call("session");
  const { disabledSites, theme } = await store.load();

  $("connection-dot").className = `status-dot ${session.signedIn ? "on" : session.server ? "off" : ""}`;
  $("connection-text").textContent = session.signedIn
    ? `${session.username} on ${new URL(session.server).host}`
    : session.server
      ? "Signed out"
      : "Not signed in";

  $("signed-in").classList.toggle("hidden", !session.signedIn);
  $("sign-in").classList.toggle("hidden", session.signedIn);
  if (session.signedIn) {
    $("who").textContent = session.username;
    $("server-link").textContent = session.server;
    $("server-link").href = session.server;
  } else {
    if (session.server && !$("server").value) $("server").value = session.server;
    if (session.username && !$("username").value) $("username").value = session.username;
    $("http-warning").classList.toggle("hidden", !/^http:\/\//i.test($("server").value.trim()));
  }

  for (const [key, on] of Object.entries(session.features)) {
    const box = $(`feature-${key}`);
    if (box) box.checked = on;
  }

  $("all-sites-off").classList.toggle("hidden", session.allSites || !session.signedIn);
  const [statusText, tone] = pageStatusText(session);
  result("page-status", statusText, tone);

  const list = $("disabled-sites");
  list.replaceChildren();
  for (const site of disabledSites) {
    const li = document.createElement("li");
    li.append(site);
    const remove = document.createElement("button");
    remove.type = "button";
    remove.title = `Turn highlighting back on for ${site}`;
    remove.setAttribute("aria-label", remove.title);
    remove.textContent = "×";
    remove.addEventListener("click", async () => {
      await store.save({ disabledSites: disabledSites.filter((s) => s !== site) });
      await render();
    });
    li.append(remove);
    list.append(li);
  }
  $("disabled-sites-block").classList.toggle("hidden", !disabledSites.length);

  $("version").textContent = chrome.runtime.getManifest().version;
  renderUpdate(await call("update"));
  if (theme?.name) {
    $("theme-name").textContent = `The extension uses the theme selected in your IntelFeed account. Current theme: ${theme.name}.`;
  }
}

function renderUpdate(update) {
  const el = $("update-status");
  el.replaceChildren();
  if (!update.checkedAt) return;
  const when = new Date(update.checkedAt).toLocaleString();
  if (update.newer) {
    el.className = "warn";
    el.append(`Version ${update.latest} is available. `);
    const a = document.createElement("a");
    a.href = update.url;
    a.target = "_blank";
    a.textContent = "Download it";
    el.append(a, ` (checked ${when}).`);
  } else {
    el.className = "ok";
    el.textContent = `You have the newest version (checked ${when}).`;
  }
}

$("check-update").addEventListener("click", async () => {
  const button = $("check-update");
  button.disabled = true;
  try {
    renderUpdate(await call("checkForUpdate"));
  } catch (err) {
    $("update-status").className = "error";
    $("update-status").textContent = `Could not reach GitHub: ${err.message}`;
  } finally {
    button.disabled = false;
  }
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && (changes.access || changes.theme || changes.disabledSites)) render();
});

// ── account ───────────────────────────────────────────────────────────

$("server").addEventListener("input", () => {
  $("http-warning").classList.toggle("hidden", !/^http:\/\//i.test($("server").value.trim()));
});

$("sign-in").addEventListener("submit", (event) => {
  event.preventDefault();
  let server;
  try {
    server = normalizeServer($("server").value);
  } catch (err) {
    return result("sign-in-result", err.message, "error");
  }
  // permissions.request must run inside the click, before anything is awaited.
  chrome.permissions
    .request({ origins: [originPattern(server)] })
    .then(async (ok) => {
      if (!ok) throw new Error("You need to allow the extension to connect to the server to sign in.");
      result("sign-in-result", "Signing in…");
      await call("signIn", { server, username: $("username").value.trim(), password: $("password").value });
      $("password").value = "";
      result("sign-in-result", "");
      await render();
    })
    .catch((err) => result("sign-in-result", err.message, "error"));
});

$("test").addEventListener("click", async () => {
  result("test-result", "Testing…");
  try {
    const me = await call("me");
    result("test-result", `Connected. Signed in as ${me.username}.`, "ok");
  } catch (err) {
    result("test-result", err.message, "error");
    if (err.notSignedIn) await render();
  }
});

$("sign-out").addEventListener("click", async () => {
  await call("signOut");
  await render();
});

// ── web pages ─────────────────────────────────────────────────────────

$("grant-all-sites").addEventListener("click", () => {
  // permissions.request must run inside the click, before anything is awaited.
  chrome.permissions
    .request(ALL_SITES)
    .then(async (ok) => {
      result("grant-result", ok ? "" : "Permission was not granted.", ok ? "" : "warn");
      if (ok) await call("syncPageScript");
      return render();
    })
    .catch((err) => result("grant-result", err.message, "error"));
});

for (const box of document.querySelectorAll('input[id^="feature-"]')) {
  box.addEventListener("change", async () => {
    const { features } = await call("session");
    features[box.id.slice("feature-".length)] = box.checked;
    await call("setFeatures", { features });
    await render();
  });
}

render().catch((err) => result("sign-in-result", err.message, "error"));
