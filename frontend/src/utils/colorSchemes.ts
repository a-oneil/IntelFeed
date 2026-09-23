// Shared color scales for cross-cutting badge/indicator domains (TLP, severity).
// Entity-type colors live in entityTheme.ts. Severity resolves through the
// --severity-* CSS variables set at runtime by applyTheme(), with the theme
// defaults as fallbacks.

export const TLP_COLORS: Record<string, string> = {
  "TLP:CLEAR": "#6b7280",
  "TLP:GREEN": "#22c55e",
  "TLP:AMBER": "#f59e0b",
  "TLP:AMBER+STRICT": "#f59e0b",
  "TLP:RED": "#ef4444",
};

export function getTLPColor(tlp: string | null | undefined, fallback = "#888"): string {
  if (!tlp) return fallback;
  return TLP_COLORS[tlp.toUpperCase()] ?? fallback;
}

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--severity-critical, #dc2626)",
  high: "var(--severity-high, #ea580c)",
  medium: "var(--severity-medium, #f59e0b)",
  low: "var(--severity-low, #22c55e)",
  info: "var(--severity-info, #3b82f6)",
};

export function getSeverityColor(
  severity: string | null | undefined,
  fallback = "var(--text-muted, #888)",
): string {
  if (!severity) return fallback;
  return SEVERITY_COLORS[severity.toLowerCase()] ?? fallback;
}
