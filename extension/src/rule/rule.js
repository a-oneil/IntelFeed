import { drawLogos } from "../lib/logo.js";
import { call } from "../lib/messages.js";
import { detectRuleType, RULE_TYPES, SHORT_NAMES } from "../lib/rule-format.js";
import { useTheme } from "../lib/theme.js";

useTheme();
drawLogos();

const $ = (id) => document.getElementById(id);
const LABELS = Object.fromEntries(RULE_TYPES);
let page;
let saved = null;

function options(select, chosen, { placeholder, skip } = {}) {
  select.replaceChildren();
  if (placeholder) {
    const o = new Option(placeholder, "");
    o.disabled = true;
    o.selected = !chosen;
    select.append(o);
  }
  for (const [value, label] of RULE_TYPES) {
    if (value === skip) continue;
    select.append(new Option(label, value, false, value === chosen));
  }
}

function defaultTitle(type) {
  const label = type ? SHORT_NAMES[type] : "Detection";
  return `${page.title || new URL(page.url).hostname} – ${label} rule`.slice(0, 500);
}

let checkTimer;
function scheduleCheck() {
  clearTimeout(checkTimer);
  checkTimer = setTimeout(check, 500);
}

async function check() {
  const ruleType = $("rule-type").value;
  const content = $("content").value;
  const box = $("check");
  const list = $("errors");
  list.replaceChildren();
  if (!ruleType) {
    box.className = "check warn small";
    box.textContent = "Choose the rule language to check the syntax.";
    return;
  }
  if (!content.trim()) {
    box.className = "check warn small";
    box.textContent = "The rule is empty.";
    return;
  }
  box.className = "check muted small";
  box.textContent = "Checking the syntax…";
  try {
    const result = await call("validateRule", { ruleType, content });
    const errors = result.errors.filter((e) => e.severity !== "warning");
    const warnings = result.errors.filter((e) => e.severity === "warning");
    if (result.valid) {
      box.className = "check ok small";
      box.textContent = warnings.length
        ? `The syntax is valid as ${LABELS[ruleType]}, with ${warnings.length} warning${warnings.length === 1 ? "" : "s"}.`
        : `The syntax is valid as ${LABELS[ruleType]}.`;
    } else {
      box.className = "check error small";
      box.textContent = `The syntax is not valid as ${LABELS[ruleType]}. You can still save it as a draft and fix it in IntelFeed.`;
    }
    for (const e of [...errors, ...warnings]) {
      const where = e.line ? `Line ${e.line}${e.column ? `, column ${e.column}` : ""}: ` : "";
      const li = document.createElement("li");
      li.textContent = `${where}${e.message}`;
      if (e.severity === "warning") li.style.color = "var(--warn)";
      list.append(li);
    }
  } catch (err) {
    box.className = "check error small";
    box.textContent = `Could not check the syntax: ${err.message}`;
  }
}

$("rule-type").addEventListener("change", () => {
  const title = $("title");
  if (!title.dataset.edited) title.value = defaultTitle($("rule-type").value);
  scheduleCheck();
});
$("title").addEventListener("input", () => ($("title").dataset.edited = "1"));
$("content").addEventListener("input", scheduleCheck);

$("form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("save");
  button.disabled = true;
  $("save-result").className = "muted small";
  $("save-result").textContent = "Saving…";
  try {
    saved = await call("saveRule", {
      ruleType: $("rule-type").value,
      title: $("title").value.trim(),
      content: $("content").value,
      url: page.url,
      entryId: page.entryId,
    });
    $("save-result").className = "ok small";
    $("save-result").replaceChildren("Saved as a draft. ");
    const a = document.createElement("a");
    a.href = saved.href;
    a.target = "_blank";
    a.textContent = "Open the rule in IntelFeed";
    $("save-result").append(a);
    button.textContent = "Saved";
    options($("target-type"), null, { placeholder: "Choose a rule language", skip: $("rule-type").value });
    $("convert").classList.remove("hidden");
  } catch (err) {
    button.disabled = false;
    $("save-result").className = "error small";
    $("save-result").textContent = err.message;
  }
});

$("convert-button").addEventListener("click", async () => {
  const targetType = $("target-type").value;
  if (!targetType || !saved) return;
  const button = $("convert-button");
  const li = document.createElement("li");
  li.className = "muted";
  li.textContent = `Converting to ${LABELS[targetType]}…`;
  $("converted").append(li);
  button.disabled = true;
  try {
    const out = await call("convertRule", { id: saved.id, targetType });
    li.className = "ok";
    li.replaceChildren(`Converted to ${LABELS[targetType]}. `);
    const a = document.createElement("a");
    a.href = out.href;
    a.target = "_blank";
    a.textContent = "Open it in IntelFeed";
    li.append(a);
  } catch (err) {
    li.className = "error";
    li.textContent = `Could not convert to ${LABELS[targetType]}: ${err.message}`;
  } finally {
    button.disabled = false;
  }
});

async function init() {
  const key = new URLSearchParams(location.search).get("key");
  try {
    page = await call("pendingRule", { key });
  } catch (err) {
    $("load-error").textContent = err.message;
    $("load-error").classList.remove("hidden");
    return;
  }
  $("source").textContent = `From: ${page.title || page.url} (${page.url})`;
  const guess = detectRuleType(page.text);
  options($("rule-type"), guess, { placeholder: guess ? null : "Choose the rule language" });
  $("guess").textContent = guess
    ? `Detected as ${LABELS[guess]}. Change it if that is wrong.`
    : "The language could not be detected. Choose it from the list.";
  $("title").value = defaultTitle(guess);
  $("content").value = page.text.replace(/\u00a0/g, " ").trim();
  $("form").classList.remove("hidden");
  check();
}

init();
