// The user's IntelFeed theme, applied to the popup, settings page and rule window. The background worker fetches it (loadTheme in background.js) and keeps it in storage; a page applies the stored copy before it renders anything else.

import * as store from "./store.js";

// IntelFeed theme variable → the extension's own token.
const TOKENS = {
  "bg-primary": "--bg",
  "bg-secondary": "--surface",
  border: "--border",
  "text-primary": "--text",
  "text-secondary": "--muted",
  accent: "--accent",
  success: "--ok",
  warning: "--warn",
  danger: "--error",
};

/** The stored theme from the schema's defaults, the instance default and the user's pick. */
export function mergeTheme(schema, theme) {
  return {
    vars: { ...(schema?.css_variables || schema?.base || {}), ...(theme?.css_variables || {}) },
    entityColors: schema?.entity_types || {},
    name: theme?.name || null,
  };
}

/** WCAG relative luminance (0 = black, 1 = white) of #rgb or #rrggbb, or null. */
function luminance(hex) {
  let m = String(hex).trim().replace("#", "");
  if (m.length === 3) m = [...m].map((c) => c + c).join("");
  if (!/^[0-9a-f]{6}$/i.test(m)) return null;
  const [r, g, b] = [0, 2, 4].map((i) => {
    const c = parseInt(m.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** Black or white, whichever reads on `hex` — the app's contrastText (frontend/src/utils/contrast.ts). */
export function contrastText(hex) {
  const l = luminance(hex);
  return l != null && l > 0.179 ? "#000000" : "#ffffff";
}

export function applyTheme(theme, root = document.documentElement) {
  if (!theme?.vars) return;
  for (const [name, token] of Object.entries(TOKENS)) {
    const value = theme.vars[name];
    if (value) root.style.setProperty(token, value);
  }
  // Text on the accent is worked out from the accent, as the app does, never taken from the theme: an orange accent needs black text, not white.
  if (theme.vars.accent) root.style.setProperty("--accent-text", contrastText(theme.vars.accent));
  for (const [type, color] of Object.entries(theme.entityColors || {})) {
    if (color) root.style.setProperty(`--entity-${type}`, color);
  }
  // The theme decides light or dark; native controls (scrollbars, checkboxes) follow it.
  const bg = theme.vars["bg-primary"];
  if (bg) root.style.colorScheme = isLight(bg) ? "light" : "dark";
}

function isLight(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(String(hex).trim());
  if (!m) return false;
  const n = parseInt(m[1], 16);
  const [r, g, b] = [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  return 0.299 * r + 0.587 * g + 0.114 * b > 150;
}

/** Apply the stored theme now, and again whenever the worker stores a newer one. */
export async function useTheme() {
  applyTheme((await store.load()).theme);
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.theme) applyTheme(changes.theme.newValue);
  });
}
