import assert from "node:assert/strict";
import { test } from "node:test";

import { applyTheme, contrastText, mergeTheme } from "../src/lib/theme.js";

test("the user's theme overrides the schema defaults and entity colors come from the schema", () => {
  const schema = {
    css_variables: { "bg-primary": "#0d1117", accent: "#f78166", "text-primary": "#e6edf3" },
    entity_types: { threat_actor: "#f97316" },
  };
  const t = mergeTheme(schema, { name: "Paper", css_variables: { "bg-primary": "#ffffff", accent: "#0969da" } });
  assert.equal(t.vars["bg-primary"], "#ffffff");
  assert.equal(t.vars.accent, "#0969da");
  assert.equal(t.vars["text-primary"], "#e6edf3");
  assert.equal(t.entityColors.threat_actor, "#f97316");
  assert.equal(t.name, "Paper");
});

test("applying sets the extension's tokens and the color scheme", () => {
  const props = {};
  const root = { style: { setProperty: (k, v) => (props[k] = v), colorScheme: "" } };
  applyTheme({ vars: { "bg-primary": "#ffffff", accent: "#0969da", danger: "#cf222e" } }, root);
  assert.deepEqual(props, { "--bg": "#ffffff", "--accent": "#0969da", "--error": "#cf222e", "--accent-text": "#ffffff" });
  assert.equal(root.style.colorScheme, "light");
  applyTheme({ vars: { "bg-primary": "#0d1117" } }, root);
  assert.equal(root.style.colorScheme, "dark");
});

test("text on the accent is black or white by the accent's luminance, like the app", () => {
  assert.equal(contrastText("#f78166"), "#000000"); // orange: white text was unreadable
  assert.equal(contrastText("#fb923c"), "#000000");
  assert.equal(contrastText("#0969da"), "#ffffff");
  assert.equal(contrastText("#fff"), "#000000");
  assert.equal(contrastText("var(--x)"), "#ffffff");
  const props = {};
  const root = { style: { setProperty: (k, v) => (props[k] = v), colorScheme: "" } };
  applyTheme({ vars: { accent: "#f78166", "accent-text": "#ffffff" } }, root);
  assert.equal(props["--accent-text"], "#000000");
});
