/**
 * The IntelFeed mark: a hexagon with the hexagram of network lines inside it, nodes where the lines cross, and a feed signal whose dot sits on the bottom-left crossing. The same drawing scripts/dev/render_icons.cjs renders the favicons and app icons from.
 *
 * Two weights: SMALL (heavier lines and nodes) for 32px and below, where the thin lines of FULL blur; FULL above that.
 */

export interface MarkWeights {
  hex: number;
  net: number;
  netOpacity: number;
  node: number;
  feed: number;
  wave: number;
}

export const MARK_WEIGHTS: Record<"SMALL" | "FULL", MarkWeights> = {
  SMALL: { hex: 1.7, net: 0.85, netOpacity: 0.65, node: 0.95, feed: 1.5, wave: 1.65 },
  FULL: { hex: 1.35, net: 0.7, netOpacity: 0.6, node: 0.8, feed: 1.3, wave: 1.4 },
};

export const HEXAGON = "M12 2L21.2 7.5V16.5L12 22L2.8 16.5V7.5Z";
export const HEXAGRAM = ["M12 2L21.2 16.5L2.8 16.5Z", "M21.2 7.5L12 22L2.8 7.5Z"];
/** Crossings of the hexagram that carry a node. Bottom-left is the feed dot; left and bottom-right are left bare, where they would crowd the feed signal. */
export const NODES: [number, number][] = [[8.5, 7.5], [15.5, 7.5], [18.3, 12]];
export const FEED_DOT: [number, number] = [8.5, 16.5];
export const WAVES = ["M8.5 13.5C10.16 13.5 11.5 14.84 11.5 16.5", "M8.5 10.8C11.65 10.8 14.2 13.35 14.2 16.5"];

/** The mark as an SVG document, for the favicon. */
export function markSvg(color: string, w: MarkWeights = MARK_WEIGHTS.SMALL, px = 32): string {
  const dots = (points: [number, number][], r: number) =>
    points.map(([x, y]) => `<circle cx="${x}" cy="${y}" r="${r}"/>`).join("");
  return `<svg width="${px}" height="${px}" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="none">
<path d="${HEXAGON}" stroke="${color}" stroke-width="${w.hex}" stroke-linejoin="round"/>
${HEXAGRAM.map((d) => `<path d="${d}" stroke="${color}" stroke-width="${w.net}" stroke-linejoin="round" opacity="${w.netOpacity}"/>`).join("")}
<g fill="${color}">${dots(NODES, w.node)}${dots([FEED_DOT], w.feed)}</g>
${WAVES.map((d) => `<path d="${d}" stroke="${color}" stroke-width="${w.wave}" stroke-linecap="round"/>`).join("")}
</svg>`;
}
