/**
 * WCAG contrast helpers.
 *
 * Extracted from `hooks/useThemes.ts`, which used them privately to derive
 * `--accent-text`. Anything that paints text on a colour chosen at runtime —
 * a user's tag colour, an entity tint, a severity fill — needs the same logic,
 * and hardcoding `#fff` there is how several filled chips ended up at 1.2–3.4:1.
 */

/** Parse #rgb or #rrggbb. Returns null for anything else. */
export function parseHex(hex: string): [number, number, number] | null {
  const m = hex.replace("#", "");
  if (m.length === 3) {
    return [parseInt(m[0] + m[0], 16), parseInt(m[1] + m[1], 16), parseInt(m[2] + m[2], 16)];
  }
  if (m.length === 6) {
    return [parseInt(m.slice(0, 2), 16), parseInt(m.slice(2, 4), 16), parseInt(m.slice(4, 6), 16)];
  }
  return null;
}

/** WCAG relative luminance (0 = black, 1 = white). */
export function luminance(r: number, g: number, b: number): number {
  const [rs, gs, bs] = [r / 255, g / 255, b / 255].map((c) =>
    c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4),
  );
  return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
}

/**
 * "#ffffff" or "#000000", whichever contrasts better with `hex`.
 * Crossover luminance is ~0.179. Falls back to white for unparseable input
 * (e.g. a `var(--token)` string), which is the pre-existing behaviour.
 */
export function contrastText(hex: string): string {
  const rgb = parseHex(hex);
  if (!rgb) return "#ffffff";
  return luminance(...rgb) > 0.179 ? "#000000" : "#ffffff";
}
