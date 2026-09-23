import { useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { Theme } from "@/api/types";
import { useAuthStore } from "@/stores/authStore";
import { contrastText, luminance, parseHex } from "@/utils/contrast";

export function useThemes() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated());
  return useQuery({
    queryKey: ["themes"],
    queryFn: async () => {
      const res = await api.get<Theme[]>("/themes");
      return res.data;
    },
    enabled: isAuthenticated,
  });
}

export function useSetThemePreference() {
  const queryClient = useQueryClient();
  const setUser = useAuthStore((s) => s.setUser);
  const user = useAuthStore((s) => s.user);
  return useMutation({
    mutationFn: async (body: { theme_id?: string; custom_css?: string; clear_theme?: boolean }) => {
      const res = await api.put("/themes/user/preferences", body);
      return res.data;
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["themes"] });
      // Update the auth store so the active theme indicator reflects the change
      if (user && variables.clear_theme) {
        setUser({ ...user, theme_id: null });
      } else if (user && variables.theme_id !== undefined) {
        setUser({ ...user, theme_id: variables.theme_id ?? null });
      }
    },
  });
}

/**
 * Admin-only: set or clear the instance-wide default theme.
 * The default applies to any user who hasn't picked a theme of their own.
 */
export function useSetDefaultTheme() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, clear }: { id: string; clear?: boolean }) => {
      const res = clear ? await api.delete(`/themes/${id}/default`) : await api.put(`/themes/${id}/default`);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["themes"] });
    },
  });
}

export function useDeleteTheme() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (themeId: string) => {
      await api.delete(`/themes/${themeId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["themes"] });
    },
  });
}

export function useCreateTheme() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: { name: string; css_variables: Record<string, string> }) => {
      const res = await api.post<Theme>("/themes", body);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["themes"] });
    },
  });
}

export function useUpdateTheme() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: { id: string; name?: string; css_variables?: Record<string, string> }) => {
      const res = await api.put<Theme>(`/themes/${id}`, body);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["themes"] });
    },
  });
}

export function useDuplicateTheme() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, name }: { id: string; name: string }) => {
      const res = await api.post<Theme>(`/themes/${id}/duplicate`, { name });
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["themes"] });
    },
  });
}

/**
 * Parse a hex color (#rgb or #rrggbb) into [r, g, b] (0-255).
 */

/**
 * Darken or lighten a hex color by a ratio (-1..1). Negative = darken, positive = lighten.
 */
function adjustColor(hex: string, amount: number): string {
  const rgb = parseHex(hex);
  if (!rgb) return hex;
  const adjusted = rgb.map((c) => {
    if (amount > 0) return Math.round(c + (255 - c) * amount);
    return Math.round(c * (1 + amount));
  });
  return `#${adjusted.map((c) => Math.max(0, Math.min(255, c)).toString(16).padStart(2, "0")).join("")}`;
}

/**
 * Which choice the cached palette came from. A palette the person picked for
 * themselves ("user") survives logout — they see their own colors on the login
 * screen. A palette that only reflects the admin-set instance default
 * ("default") does not, so this browser follows the default when it changes.
 */
export type ThemeSource = "user" | "default";

const THEME_SOURCE_KEY = "intelfeed-theme-source";

export function applyTheme(theme: Theme, source?: ThemeSource) {
  const root = document.documentElement;

  // Accumulate every variable we set so we can persist the exact same set for
  // pre-render application by theme-init.js (prevents a flash of the baked-in
  // default palette on hard refresh).
  const vars: Record<string, string> = { ...theme.css_variables };

  // Auto-compute contrast-safe text colors for any color used as a background
  const accent = theme.css_variables["accent"];
  if (accent) {
    vars["accent-text"] = contrastText(accent);
    // Auto-generate hover if not explicitly set by the theme
    if (!theme.css_variables["accent-hover"]) {
      const isLight = luminance(...(parseHex(accent) ?? [0, 0, 0])) > 0.179;
      vars["accent-hover"] = adjustColor(accent, isLight ? -0.15 : 0.2);
    }
  }

  // Filled severity chips need a foreground that contrasts with the fill — and
  // the fills are theme-controlled, so a static token can't be right across all
  // 48 themes. Derive them the same way accent-text is derived above. Falls back
  // to the index.css default fill when a theme doesn't override that severity.
  const SEVERITY_FALLBACKS: Record<string, string> = {
    "severity-critical": "#dc2626",
    "severity-high": "#fb923c",
    "severity-medium": "#d29922",
    "severity-low": "#3fb950",
    "severity-info": "#58a6ff",
  };
  for (const [key, fallback] of Object.entries(SEVERITY_FALLBACKS)) {
    vars[`${key}-fg`] = contrastText(vars[key] ?? fallback);
  }

  // Same problem one level up: --danger is theme-managed and is used as a FILL
  // by delete/confirm buttons, which were painting #fff on it (3.35:1 on the
  // default #f85149). --accent-text can't serve there — it is derived from the
  // accent, not from this fill — so --danger gets its own derived foreground.
  vars["danger-fg"] = contrastText(vars["danger"] ?? "#f85149");

  for (const [key, value] of Object.entries(vars)) {
    root.style.setProperty(`--${key}`, value);
  }

  // Persist the applied theme ID + full variable set for instant, flash-free
  // restore before React mounts (see public/theme-init.js)
  localStorage.setItem("intelfeed-theme-id", theme.id);
  try {
    localStorage.setItem("intelfeed-theme-vars", JSON.stringify(vars));
  } catch {
    // Quota or serialization failure is non-fatal — we just lose the fast path
  }
  // Update PWA status bar / title bar color to match theme background
  const bgPrimary = theme.css_variables["bg-primary"];
  if (bgPrimary) {
    document.querySelector<HTMLMetaElement>('meta[name="theme-color"]')?.setAttribute("content", bgPrimary);
    localStorage.setItem("intelfeed-theme-bg", bgPrimary);
  }
  // Omitted source = "keep whatever this browser already recorded" (theme
  // edits re-apply the active theme without changing where it came from).
  if (source) localStorage.setItem(THEME_SOURCE_KEY, source);
  // Update favicon to match theme accent color
  updateFavicon(theme.css_variables["accent"]);
}

/**
 * Re-assert the cached palette from localStorage. Used on logout: the themes
 * endpoint needs auth, so the signed-out app can't re-fetch the theme the user
 * picked — but the exact variable set it applied is already cached here.
 */
function applyCachedVars(): boolean {
  const raw = localStorage.getItem("intelfeed-theme-vars");
  if (!raw) return false;
  try {
    const vars = JSON.parse(raw) as Record<string, string>;
    const root = document.documentElement;
    for (const [key, value] of Object.entries(vars)) {
      root.style.setProperty(`--${key}`, value);
    }
    const bg = localStorage.getItem("intelfeed-theme-bg");
    if (bg) document.querySelector<HTMLMetaElement>('meta[name="theme-color"]')?.setAttribute("content", bg);
    updateFavicon(vars["accent"]);
    return true;
  } catch {
    return false;
  }
}

function updateFavicon(color: string | undefined) {
  if (!color) return;
  const svg = `<svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M12 2L21.2 7.5V16.5L12 22L2.8 16.5V7.5Z" stroke="${color}" stroke-width="1.4" stroke-linejoin="round" fill="none"/>
  <path d="M12 2L21.2 16.5L2.8 16.5Z" stroke="${color}" stroke-width="0.7" stroke-linejoin="round" fill="none" opacity="0.6"/>
  <path d="M21.2 7.5L12 22L2.8 7.5Z" stroke="${color}" stroke-width="0.7" stroke-linejoin="round" fill="none" opacity="0.6"/>
  <circle cx="12" cy="2" r="1.1" fill="${color}"/><circle cx="21.2" cy="7.5" r="1.1" fill="${color}"/>
  <circle cx="21.2" cy="16.5" r="1.1" fill="${color}"/><circle cx="12" cy="22" r="1.1" fill="${color}"/>
  <circle cx="2.8" cy="16.5" r="1.1" fill="${color}"/><circle cx="2.8" cy="7.5" r="1.1" fill="${color}"/>
  <circle cx="15.5" cy="7.5" r="0.8" fill="${color}"/><circle cx="18.3" cy="12" r="0.8" fill="${color}"/>
  <circle cx="15.5" cy="16.5" r="0.8" fill="${color}"/><circle cx="8.5" cy="16.5" r="0.8" fill="${color}"/>
  <circle cx="5.7" cy="12" r="0.8" fill="${color}"/><circle cx="8.5" cy="7.5" r="0.8" fill="${color}"/>
  <circle cx="8.5" cy="15.5" r="1.3" fill="${color}"/>
  <path d="M8.5 12.5C10.16 12.5 11.5 13.84 11.5 15.5" stroke="${color}" stroke-width="1.4" stroke-linecap="round" fill="none"/>
  <path d="M8.5 9.8C11.65 9.8 14.2 12.35 14.2 15.5" stroke="${color}" stroke-width="1.4" stroke-linecap="round" fill="none"/>
</svg>`;
  const blob = new Blob([svg], { type: "image/svg+xml" });
  const url = URL.createObjectURL(blob);
  const link = document.querySelector<HTMLLinkElement>('link[rel="icon"][type="image/svg+xml"]');
  if (link) {
    const oldUrl = link.href.startsWith("blob:") ? link.href : null;
    link.href = url;
    if (oldUrl) URL.revokeObjectURL(oldUrl);
  }
}

export function clearTheme() {
  const root = document.documentElement;
  const vars = [
    "bg-primary", "bg-secondary", "bg-tertiary", "bg-hover",
    "text-primary", "text-secondary", "text-muted",
    "accent", "accent-hover", "accent-text", "border",
    "danger", "danger-fg", "success", "warning",
    "sidebar-bg", "sidebar-hover", "sidebar-active",
    "card-bg", "card-border",
    "severity-critical", "severity-high", "severity-medium", "severity-low", "severity-info",
    "severity-critical-fg", "severity-high-fg", "severity-medium-fg", "severity-low-fg", "severity-info-fg",
    "heatmap-empty", "heatmap-1", "heatmap-2", "heatmap-3", "heatmap-4", "heatmap-5",
  ];
  for (const v of vars) {
    root.style.removeProperty(`--${v}`);
  }
  localStorage.removeItem("intelfeed-theme-id");
  localStorage.removeItem("intelfeed-theme-vars");
  localStorage.removeItem(THEME_SOURCE_KEY);
  // Reset PWA status bar to default
  document.querySelector<HTMLMetaElement>('meta[name="theme-color"]')?.setAttribute("content", "#0d1117");
  localStorage.removeItem("intelfeed-theme-bg");
}

const DEFAULT_THEME_NAME = "GitHub Dark";

/**
 * Public (no auth): the instance default theme, fetched to style pre-auth
 * pages like login and register. Resolves to null when no default is set.
 */
function usePublicDefaultTheme(enabled: boolean) {
  return useQuery({
    queryKey: ["default-theme-public"],
    queryFn: async () => {
      const res = await api.get<Theme | null>("/themes/default");
      return res.data ?? null;
    },
    enabled,
    staleTime: 5 * 60 * 1000,
  });
}

/**
 * Auto-applies the user's saved theme on login. Users without a theme of their
 * own get the admin-set instance default, then the localStorage cache, then
 * GitHub Dark as the last resort.
 *
 * Logged out (login/register), two cases:
 *   - This browser remembers a palette its user picked for themselves: keep it,
 *     so signing out doesn't repaint the app in someone else's colors.
 *   - Anyone else — a first visit, or a browser that was only ever following
 *     the instance default: apply the instance default from the public
 *     endpoint, so a fresh user meets the app the way the admin dressed it.
 */
export function useAutoTheme() {
  const user = useAuthStore((s) => s.user);
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated());
  const { data: themes } = useThemes();
  const { data: publicDefault } = usePublicDefaultTheme(!isAuthenticated);

  useEffect(() => {
    if (isAuthenticated) return;
    const source = localStorage.getItem(THEME_SOURCE_KEY);
    const cachedId = localStorage.getItem("intelfeed-theme-id");
    // Browsers cached from before the source marker existed: a cached theme
    // that isn't the instance default can only have come from a personal pick.
    const legacyPersonal = source === null && !!cachedId && !!publicDefault && cachedId !== publicDefault.id;
    // Logging out is a client-side route change, not a reload, so the palette
    // is still on <html> — but re-assert it from cache so this path is the same
    // whether the user logged out or arrived on /login cold.
    if ((source === "user" || legacyPersonal) && applyCachedVars()) return;
    if (publicDefault) applyTheme(publicDefault, "default");
  }, [isAuthenticated, publicDefault]);

  useEffect(() => {
    if (!themes || themes.length === 0) return;

    // If user has a saved theme preference, apply it
    if (user?.theme_id) {
      const userTheme = themes.find((t) => t.id === user.theme_id);
      if (userTheme) {
        applyTheme(userTheme, "user");
        return;
      }
    }

    // User is loaded and has no theme of their own (or it no longer exists):
    // the admin-set instance default wins over any stale local cache
    if (user) {
      const instanceDefault = themes.find((t) => t.is_default);
      if (instanceDefault) {
        applyTheme(instanceDefault, "default");
        return;
      }
    }

    // Try to apply from localStorage cache for instant restore
    const cachedId = localStorage.getItem("intelfeed-theme-id");
    if (cachedId) {
      const cached = themes.find((t) => t.id === cachedId);
      if (cached) {
        applyTheme(cached);
        return;
      }
    }

    // Fall back to GitHub Dark
    const defaultTheme = themes.find((t) => t.name === DEFAULT_THEME_NAME);
    if (defaultTheme) {
      applyTheme(defaultTheme, "default");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.theme_id, user != null, themes]);
}
