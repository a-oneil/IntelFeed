/** Dollars as the AI cards print them: cents normally, a third place for sub-cent figures. */
export function formatUsd(value: string | number | null | undefined, digits: 2 | 3 | 4 = 2): string {
  const n = Number(value ?? 0);
  if (!Number.isFinite(n)) return "$0.00";
  if (n > 0 && n < 0.01 && digits === 2) return `$${n.toFixed(3)}`;
  return `$${n.toFixed(digits)}`;
}

/** 48,200 → "48.2K", 70,413,600 → "70.4M"; small counts stay exact. */
export function compactCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  return n >= 10_000 ? `${(n / 1000).toFixed(1)}K` : n.toLocaleString();
}
