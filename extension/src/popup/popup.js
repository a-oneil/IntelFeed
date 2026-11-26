import { summarize, threadSize } from "../lib/findings.js";
import { drawLogos } from "../lib/logo.js";
import { call } from "../lib/messages.js";
import { initialKind, TYPE_LABELS } from "../lib/notes.js";
import { useTheme } from "../lib/theme.js";

useTheme();
drawLogos();
call("refreshTheme").catch(() => {});

const $ = (id) => document.getElementById(id);
const selectedTags = new Set();
let session;
let tab;

function show(id) {
  for (const s of ["signed-out", "main"]) $(s).classList.toggle("hidden", s !== id);
}

/** The status row: a line of text, an optional muted second line, and the link on the right. */
function setStatus(text, tone = "muted", link, detail) {
  const el = $("status");
  el.className = `status ${tone}`;
  const body = document.createElement("div");
  body.className = "status-body";
  const main = document.createElement("div");
  main.className = "status-text";
  main.textContent = text;
  body.append(main);
  if (detail) {
    const sub = document.createElement("div");
    sub.className = "status-detail";
    sub.textContent = detail;
    body.append(sub);
  }
  el.replaceChildren(body);
  if (link) {
    const a = document.createElement("a");
    a.href = link.href;
    a.textContent = link.text;
    a.target = "_blank";
    a.className = "status-open";
    el.append(a);
  }
}

const entryLink = (id) => ({ href: `${session.server}/?entry=${encodeURIComponent(id)}`, text: "Open" });
const entryHref = (id) => `${session.server}/?entry=${encodeURIComponent(id)}`;

function link(href, text, className) {
  const a = document.createElement("a");
  a.href = href;
  a.target = "_blank";
  a.textContent = text;
  if (className) a.className = className;
  return a;
}

/** A story thread as one clickable block: label, title, size. */
function fillStory(el, thread) {
  el.replaceChildren();
  el.classList.toggle("hidden", !thread);
  if (!thread) return;
  el.href = `${session.server}/?thread=${encodeURIComponent(thread.slug)}`;
  const label = document.createElement("span");
  label.className = "story-label";
  label.textContent = "Story";
  const title = document.createElement("span");
  title.className = "story-title";
  title.textContent = thread.title;
  const size = document.createElement("span");
  size.className = "story-size";
  size.textContent = threadSize(thread);
  el.append(label, title, size);
}

const renderThread = (thread) => fillStory($("thread-block"), thread);

// ── what the pipeline found ───────────────────────────────────────────

const RESULT_POLL_MS = 5000;
let resultTimer = null;

async function renderResults(entryId) {
  clearTimeout(resultTimer);
  let r;
  try {
    r = await call("results", { entryId });
  } catch {
    return;
  }
  $("results-block").classList.remove("hidden");
  const list = $("results-list");
  list.replaceChildren();
  const chip = (type, id, text) => {
    const a = link(`${session.server}/workbench/${type}/${encodeURIComponent(id)}`, text, "chip");
    a.style.setProperty("--chip", `var(--entity-${type})`);
    list.append(a);
  };
  for (const a of r.actors) chip("threat_actor", a.id, a.name);
  for (const m of r.malware) chip("malware", m.id, m.name);
  for (const t of r.tools) chip("tool", t.id, t.name);
  for (const c of r.cves) chip("cve", c.id, c.cvss_score != null ? `${c.cve_id} · ${c.cvss_score}` : c.cve_id);
  for (const t of r.ttps) chip("ttp", t.id, t.technique_id);
  foundEntities = [
    ...r.actors.map((a) => ({ type: "threat_actor", id: a.id, name: a.name })),
    ...r.malware.map((m) => ({ type: "malware", id: m.id, name: m.name })),
    ...r.tools.map((t) => ({ type: "tool", id: t.id, name: t.name })),
    ...r.cves.map((c) => ({ type: "cve", id: c.id, name: c.cve_id })),
    ...r.ttps.map((t) => ({ type: "ttp", id: t.id, name: t.technique_id })),
  ];
  renderEntitySuggest();
  const extra = [];
  if (r.rule_count) extra.push(`${r.rule_count} detection ${r.rule_count === 1 ? "rule" : "rules"}`);
  if (r.observable_count) extra.push(`${r.observable_count} ${r.observable_count === 1 ? "indicator" : "indicators"}`);
  const found = summarize(r);
  const count = r.actors.length + r.malware.length + r.tools.length + r.cves.length + r.ttps.length;
  $("results-summary").textContent = r.state === "processing" ? "processing…" : count ? String(count) : "none";
  const state = $("results-state");
  if (r.state === "processing") {
    state.textContent = found
      ? `Still processing. So far: ${found}.`
      : "IntelFeed is still processing this page. If notifications are on in Settings, one says what it found when it is done.";
    // The popup stays open only while it is in use; poll gently until then.
    resultTimer = setTimeout(() => renderResults(entryId), RESULT_POLL_MS);
  } else {
    state.textContent = found ? extra.join(" · ") : "Nothing was found in it.";
  }
  if (r.thread) renderThread(r.thread);
}

// ── has this story already come in? ───────────────────────────────────

async function renderCoverage(status) {
  let c;
  try {
    c = await call("coverage", { url: status.url, title: status.title });
  } catch {
    return;
  }
  if (!c.outlet_count) return;
  $("coverage-title").textContent =
    c.outlet_count === 1 ? "Already covered by 1 site" : `Already covered by ${c.outlet_count} sites`;
  const list = $("coverage-list");
  list.replaceChildren();
  for (const e of c.entries) {
    const li = document.createElement("li");
    const meta = document.createElement("span");
    meta.className = "muted";
    meta.textContent = [e.feed_title, e.published_at ? new Date(e.published_at).toLocaleDateString() : null]
      .filter(Boolean)
      .join(" · ");
    li.append(link(entryHref(e.id), e.title), meta);
    list.append(li);
  }
  fillStory($("coverage-thread"), c.thread);
  $("coverage-block").classList.remove("hidden");
}

// ── sends waiting for the server ──────────────────────────────────────

async function renderOutbox() {
  let box;
  try {
    box = await call("outbox");
  } catch {
    return;
  }
  const n = box.waiting.length;
  $("outbox-block").classList.toggle("hidden", !n && !box.failed.length);
  $("outbox-text").textContent = n
    ? `${n} ${n === 1 ? "page is" : "pages are"} waiting to send. IntelFeed couldn’t be reached when you sent ${n === 1 ? "it" : "them"}.`
    : "";
  $("outbox-send").classList.toggle("hidden", !n);
  const failed = $("outbox-failed");
  failed.replaceChildren();
  for (const f of box.failed) {
    const li = document.createElement("li");
    li.textContent = `Not sent: ${f.title || f.url}. ${f.message}`;
    failed.append(li);
  }
  const discard = $("outbox-discard");
  discard.textContent = "Discard";
  discard.onclick = async () => {
    if (discard.dataset.armed !== "1") {
      discard.dataset.armed = "1";
      discard.textContent = n ? `Discard ${n === 1 ? "it" : `all ${n}`}?` : "Clear the list?";
      return;
    }
    delete discard.dataset.armed;
    await call("discardOutbox");
    renderOutbox();
  };
}

$("outbox-send").addEventListener("click", async () => {
  const button = $("outbox-send");
  button.disabled = true;
  button.textContent = "Sending…";
  try {
    await call("flushOutbox");
  } catch (err) {
    setStatus(err.message, "error");
  } finally {
    button.disabled = false;
    button.textContent = "Send now";
    renderOutbox();
  }
});

// ── send / note tabs ──────────────────────────────────────────────────

const CAPTIONS = {
  send: "Selected text. Saved as the article’s excerpt.",
  note: "Selected text. Saved in the note as a quote.",
};
let currentTab = "send";
let tabChosen = false; // once the user picks a tab or starts typing, stop switching for them

function selectTab(name) {
  currentTab = name;
  for (const t of ["send", "note"]) {
    $(`tab-${t}`).setAttribute("aria-selected", String(t === name));
    $(`${t}-form`).classList.toggle("hidden", t !== name);
  }
  $("selection-caption").textContent = CAPTIONS[name];
}

for (const t of ["send", "note"]) {
  $(`tab-${t}`).addEventListener("click", () => {
    tabChosen = true;
    selectTab(t);
  });
}
$("note").addEventListener("input", () => (tabChosen = true));

function renderSelection(status) {
  $("selection-block").classList.toggle("hidden", !status.selection);
  $("selection-text").textContent = status.selection || "";
  $("selection-caption").textContent = CAPTIONS[currentTab];
}

// ── save as note ──────────────────────────────────────────────────────

let noteKind = "note";
let pickedEntity = null; // {type, id, name}
let noteOpts = { names: [], preferred: "", pageEntities: [] };
let foundEntities = []; // what the pipeline linked to this article (renderResults)

function setKind(kind) {
  noteKind = kind;
  for (const b of document.querySelectorAll(".kind")) b.setAttribute("aria-checked", String(b.dataset.kind === kind));
  for (const k of ["telemetry", "entity", "note"]) $(`target-${k}`).classList.toggle("hidden", k !== kind);
  $("telemetry-result").textContent = "";
  updateSaveLabel();
}

for (const b of document.querySelectorAll(".kind")) {
  b.addEventListener("click", () => {
    setKind(b.dataset.kind);
    const focus = { telemetry: "telemetry-source", entity: pickedEntity ? null : "entity-search", note: null }[noteKind];
    if (focus) $(focus).focus();
  });
}

function updateSaveLabel() {
  const source = $("telemetry-source").value.trim();
  $("telemetry-suggested").classList.toggle("hidden", !noteOpts.preferred || source !== noteOpts.preferred);
  const target = { telemetry: source, entity: pickedEntity?.name, note: null }[noteKind];
  $("telemetry-save").textContent = target ? `Save to ${target}` : noteKind === "note" ? "Save note" : "Save";
}

function entityChip(e, tag = "span") {
  const el = document.createElement(tag);
  el.className = "chip";
  el.textContent = e.name;
  el.title = TYPE_LABELS[e.type] || e.type;
  el.style.setProperty("--chip", `var(--entity-${e.type})`);
  return el;
}

function pickEntity(e) {
  pickedEntity = e;
  $("entity-picked").classList.toggle("hidden", !e);
  $("entity-search-box").classList.toggle("hidden", Boolean(e));
  if (e) $("entity-picked-chip").replaceWith(Object.assign(entityChip(e), { id: "entity-picked-chip" }));
  $("entity-results").classList.add("hidden");
  $("entity-search").value = "";
  renderEntitySuggest();
  updateSaveLabel();
}

$("entity-clear").addEventListener("click", () => {
  pickEntity(null);
  $("entity-search").focus();
});

/** Entities on this page — from the highlighter or the article's results — one click to pick. */
function renderEntitySuggest() {
  const box = $("entity-suggest");
  const seen = new Set();
  const list = [...foundEntities, ...noteOpts.pageEntities].filter((e) => {
    const key = `${e.type}:${e.id}`;
    return !seen.has(key) && seen.add(key);
  });
  box.replaceChildren(
    ...list.slice(0, 8).map((e) => {
      const b = entityChip(e, "button");
      b.type = "button";
      b.addEventListener("click", () => pickEntity(e));
      return b;
    }),
  );
  box.classList.toggle("hidden", !list.length || Boolean(pickedEntity) || Boolean($("entity-search").value.trim()));
}

let searchTimer = null;
let options = [];
let active = -1;

function renderOptions() {
  const ul = $("entity-results");
  ul.replaceChildren();
  if (!options.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No matching entity";
    ul.append(li);
  }
  options.forEach((e, i) => {
    const li = document.createElement("li");
    li.setAttribute("role", "option");
    li.setAttribute("aria-selected", String(i === active));
    li.style.setProperty("--chip", `var(--entity-${e.type})`);
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = e.name;
    const type = document.createElement("span");
    type.className = "muted";
    type.textContent = TYPE_LABELS[e.type] || e.type;
    li.append(name, type);
    li.addEventListener("mousedown", (ev) => {
      ev.preventDefault();
      pickEntity(e);
    });
    ul.append(li);
  });
  ul.classList.remove("hidden");
}

$("entity-search").addEventListener("input", () => {
  clearTimeout(searchTimer);
  const q = $("entity-search").value.trim();
  renderEntitySuggest();
  if (!q) {
    $("entity-results").classList.add("hidden");
    return;
  }
  searchTimer = setTimeout(async () => {
    try {
      options = await call("searchNoteEntities", { q });
    } catch {
      options = [];
    }
    if ($("entity-search").value.trim() !== q) return;
    active = options.length ? 0 : -1;
    renderOptions();
  }, 200);
});

$("entity-search").addEventListener("keydown", (ev) => {
  if ($("entity-results").classList.contains("hidden")) return;
  if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
    ev.preventDefault();
    if (!options.length) return;
    active = (active + (ev.key === "ArrowDown" ? 1 : -1) + options.length) % options.length;
    renderOptions();
  } else if (ev.key === "Enter" && options[active]) {
    ev.preventDefault();
    pickEntity(options[active]);
  } else if (ev.key === "Escape") {
    ev.preventDefault();
    $("entity-results").classList.add("hidden");
  }
});

$("entity-search").addEventListener("blur", () => $("entity-results").classList.add("hidden"));
$("telemetry-source").addEventListener("input", updateSaveLabel);

async function renderNote(status) {
  $("note-title").value = status.title || "";
  try {
    noteOpts = await call("telemetryOptions", { url: status.url, title: status.title });
  } catch {
    $("telemetry-unavailable").classList.remove("hidden");
  }
  $("telemetry-names").replaceChildren(...noteOpts.names.map((n) => new Option(n)));
  $("telemetry-source").value = noteOpts.preferred;
  renderEntitySuggest();
  setKind(initialKind({ preferredSource: noteOpts.preferred, lastKind: noteOpts.lastKind }));
  // A page about a source (its docs, a blog post on it) is more likely a note than an article.
  if (noteOpts.preferred && !status.entry && !tabChosen) selectTab("note");

  const button = $("telemetry-save");
  const out = $("telemetry-result");
  const fail = (text, focus) => {
    out.className = "error small";
    out.textContent = text;
    if (focus) $(focus).focus();
  };
  button.onclick = async () => {
    const content = $("telemetry-note").value.trim();
    const sourceName = $("telemetry-source").value.trim();
    if (noteKind === "telemetry" && !sourceName) return fail("Pick the telemetry source this page is about.", "telemetry-source");
    if (noteKind === "entity" && !pickedEntity) return fail("Pick the entity this note is about.", "entity-search");
    button.disabled = true;
    out.className = "muted small";
    out.textContent = "Saving…";
    const page = { url: status.url, pageTitle: status.title, quote: status.selection, content };
    try {
      const result =
        noteKind === "telemetry"
          ? await call("saveTelemetryNote", { ...page, sourceName }).then((r) => ({
              savedTo: r.sourceName,
              href: r.href,
            }))
          : await call("saveNote", { ...page, kind: noteKind, entity: pickedEntity, title: $("note-title").value.trim() });
      out.className = "ok small";
      out.replaceChildren(`Saved to ${result.savedTo}. `);
      if (result.href) out.append(link(result.href, "Open it"));
      $("telemetry-note").value = "";
    } catch (err) {
      fail(err.message);
    } finally {
      button.disabled = false;
    }
  };
}

function renderTags(tags) {
  const box = $("tags");
  box.replaceChildren();
  for (const tag of tags) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "tag";
    b.textContent = tag.name;
    b.setAttribute("aria-pressed", "false");
    b.addEventListener("click", () => {
      const on = !selectedTags.has(tag.id);
      if (on) selectedTags.add(tag.id);
      else selectedTags.delete(tag.id);
      b.setAttribute("aria-pressed", String(on));
      renderTagsSummary();
    });
    box.append(b);
  }
  $("tags-block").classList.toggle("hidden", tags.length === 0);
  renderTagsSummary();
}

function renderTagsSummary() {
  $("tags-summary").textContent = selectedTags.size ? `${selectedTags.size} selected` : "";
}

function renderFeeds(feeds) {
  const list = $("feeds");
  list.replaceChildren();
  for (const feed of feeds) list.append(feedRow(feed));
  list.classList.toggle("hidden", feeds.length === 0);
}

/** Nothing advertised: ask IntelFeed to look at the site's usual feed addresses. */
async function discoverFeeds(status) {
  if (status.feeds.length || status.repo || status.pdf) return;
  let feed;
  try {
    feed = await call("discoverFeed", { url: status.url });
  } catch {
    return;
  }
  if (!feed) return;
  renderFeeds([feed]);
  updateSiteSection();
}

function feedRow(feed) {
  const li = document.createElement("li");
  const label = document.createElement("span");
  const name = document.createElement("span");
  name.textContent = feed.title || new URL(feed.url).pathname;
  const kind = document.createElement("span");
  kind.className = "muted";
  kind.textContent = feed.kind || "RSS feed";
  label.append(name, kind);
  label.title = feed.url;
  const b = document.createElement("button");
  b.type = "button";
  b.textContent = feed.followed ? "Following" : "Follow";
  b.disabled = feed.followed;
  b.addEventListener("click", async () => {
    b.disabled = true;
    try {
      const result = await call("subscribe", { url: feed.url, subreddit: feed.subreddit });
      b.textContent = result.subscribed ? "Following" : "Already followed";
      if (!result.subscribed) b.title = result.message;
    } catch (err) {
      b.disabled = false;
      b.textContent = "Retry";
      b.title = err.message;
      setStatus(err.message, "error");
    }
  });
  li.append(label, b);
  return li;
}

function renderRepo(repo) {
  $("repo-block").classList.toggle("hidden", !repo);
  if (!repo) return;
  $("repo-name").textContent = `${repo.owner}/${repo.repo}`;
  $("repo-branch").value = repo.branch;
  $("repo-paths").value = repo.paths.join("\n");
  const button = $("repo-track");
  if (repo.followed) {
    button.textContent = "Already followed";
    button.disabled = true;
  }
  button.onclick = async () => {
    const paths = $("repo-paths")
      .value.split("\n")
      .map((p) => p.trim())
      .filter(Boolean);
    const branch = $("repo-branch").value.trim() || repo.branch;
    button.disabled = true;
    try {
      const result = await call("trackRepo", { repo: { ...repo, branch, paths } });
      button.textContent = result.subscribed ? "Following" : "Already followed";
      if (!result.subscribed) button.title = result.message;
    } catch (err) {
      button.disabled = false;
      setStatus(err.message, "error");
    }
  };
}

function renderSite(status) {
  $("site-heading").textContent = status.site || "This site";
  $("all-sites-hint").classList.toggle("hidden", status.allSites);
  const show = status.allSites && status.highlight.feature;
  $("site-block").classList.toggle("hidden", !show);
  updateSiteSection();
  if (!show) return;
  const box = $("site-highlight");
  box.checked = status.highlight.site;
  box.onchange = () => call("setSiteHighlight", { site: status.site, on: box.checked, tabId: tab.id });
}

function updateSiteSection() {
  const parts = ["feeds", "repo-block", "site-block", "all-sites-hint"];
  $("site-section").classList.toggle("hidden", parts.every((id) => $(id).classList.contains("hidden")));
}

async function renderReports() {
  let reports;
  try {
    reports = await call("reports");
  } catch {
    return;
  }
  const pick = $("report-pick");
  pick.replaceChildren();
  if (!reports.length) {
    $("report-block").classList.add("hidden");
    return;
  }
  for (const r of reports) pick.append(new Option(r.title, r.id));
  $("report-block").classList.remove("hidden");
  $("report-add").onclick = async () => {
    const button = $("report-add");
    const out = $("report-result");
    button.disabled = true;
    out.className = "muted small";
    out.textContent = "Adding…";
    try {
      const result = await call("sendToReport", {
        tabId: tab.id,
        reportId: pick.value,
        note: $("note").value,
        tagIds: [...selectedTags],
      });
      out.className = "ok small";
      out.replaceChildren(`Added to "${pick.selectedOptions[0].textContent}". `);
      const a = document.createElement("a");
      a.href = result.href;
      a.target = "_blank";
      a.textContent = "Open the report";
      out.append(a);
    } catch (err) {
      out.className = "error small";
      out.textContent = err.message;
    } finally {
      button.disabled = false;
    }
  };
}

async function renderUpdate() {
  try {
    const update = await call("update");
    if (!update.newer) return;
    const banner = $("update-banner");
    banner.replaceChildren(`Version ${update.latest} of the extension is available (you have ${update.current}). `);
    const a = document.createElement("a");
    a.href = update.url;
    a.target = "_blank";
    a.textContent = "Download it";
    banner.append(a);
    banner.classList.remove("hidden");
  } catch {
    // no update information yet
  }
}

async function send() {
  const button = $("send");
  button.disabled = true;
  setStatus("Sending the page to IntelFeed…");
  try {
    const result = await call("send", {
      tabId: tab.id,
      note: $("note").value,
      tagIds: [...selectedTags],
    });
    if (result.queued) {
      setStatus(
        result.downgraded
          ? "IntelFeed can’t be reached. The page is too large to keep, so its address is saved and IntelFeed will fetch it when it is back."
          : "IntelFeed can’t be reached. The page is saved and will be sent when it is back.",
        "warn",
      );
      button.textContent = "Waiting to send";
      renderOutbox();
      return;
    }
    setStatus(
      result.created
        ? "Added to IntelFeed."
        : "This page was already in IntelFeed. Your note and tags were added to it.",
      "ok",
      entryLink(result.id),
    );
    $("coverage-block").classList.add("hidden");
    renderResults(result.id);
    button.textContent = "Sent";
  } catch (err) {
    if (err.notSignedIn) return show("signed-out");
    setStatus(err.message, "error");
    button.disabled = false;
  }
}

async function init() {
  session = await call("session");
  if (!session.signedIn) return show("signed-out");
  show("main");
  $("who").textContent = `Signed in as ${session.username} on ${new URL(session.server).host}`;

  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  $("page-title").textContent = tab?.title || "";
  try {
    $("page-host").textContent = new URL(tab.url).host;
  } catch {
    // no readable URL
  }
  if (!tab?.url || !/^https?:/i.test(tab.url)) {
    setStatus("Only web pages (http or https addresses) can be sent to IntelFeed.", "warn");
    $("send-form").classList.add("hidden");
    return;
  }

  try {
    const status = await call("pageStatus", { tabId: tab.id });
    const what = status.pdf ? "This PDF" : "This page";
    if (status.entry) {
      const where = status.entry.feed_title ? `From ${status.entry.feed_title}` : "";
      setStatus(`${what} is already in IntelFeed`, "ok", entryLink(status.entry.id), where);
      renderThread(status.entry.thread);
      renderResults(status.entry.id);
      // Nothing to send: drop the Send tab and keep Save as note and Add to report.
      document.querySelector(".tabs").classList.add("hidden");
      selectTab("note");
      $("note-form").after($("report-block"), $("report-result"));
    } else if (status.offline) {
      setStatus("IntelFeed can’t be reached. Send saves the page and sends it when IntelFeed is back.", "warn");
    } else if (!status.checked) {
      setStatus(`IntelFeed couldn’t check whether ${what.toLowerCase()} is already in it.`, "warn");
    } else {
      setStatus(`${what} is not in IntelFeed yet.`);
      if (!status.pdf) renderCoverage(status);
    }
    if (status.pdf) $("send").textContent = "Send PDF to IntelFeed";
    renderSelection(status);
    renderNote(status);
    renderTags(status.tags);
    renderFeeds(status.feeds);
    renderRepo(status.repo);
    renderSite(status);
    discoverFeeds(status);
    renderReports();
    $("send").disabled = false;
  } catch (err) {
    if (err.notSignedIn) return show("signed-out");
    setStatus(err.message, "error");
  }
}

$("send").addEventListener("click", send);
$("open-settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
$("all-sites-link").addEventListener("click", (e) => {
  e.preventDefault();
  chrome.tabs.create({ url: chrome.runtime.getURL("src/options/options.html#pages") });
});
$("open-settings-icon").addEventListener("click", () => chrome.runtime.openOptionsPage());

renderUpdate();
renderOutbox();
init().catch((err) => {
  show("main");
  setStatus(err.message, "error");
});
