// The IntelFeed mark: a hexagon with the hexagram of network lines inside it, nodes where the lines cross, and a feed signal whose dot sits on the bottom-left crossing, on a 24x24 grid. The same drawing scripts/dev/render_icons.cjs and the app (frontend/src/utils/brandMark.ts) use. SMALL is the weight for 32px and below, where thinner lines blur.

const SMALL = { hex: 1.7, net: 0.85, netOpacity: 0.65, node: 0.95, feed: 1.5, wave: 1.65 };

const HEXAGON = "M12 2L21.2 7.5V16.5L12 22L2.8 16.5V7.5Z";
const HEXAGRAM = ["M12 2L21.2 16.5L2.8 16.5Z", "M21.2 7.5L12 22L2.8 7.5Z"];
// Crossings that carry a node. Bottom-left is the feed dot; left and bottom-right are left bare, where they would crowd the feed signal.
const NODES = [[8.5, 7.5], [15.5, 7.5], [18.3, 12]];
const FEED_DOT = [8.5, 16.5];
const WAVES = ["M8.5 13.5C10.16 13.5 11.5 14.84 11.5 16.5", "M8.5 10.8C11.65 10.8 14.2 13.35 14.2 16.5"];

/** The mark as SVG markup in `color` (currentColor by default). */
export function markSvg(color = "currentColor", w = SMALL) {
  const dots = (points, r) => points.map(([x, y]) => `<circle cx="${x}" cy="${y}" r="${r}"/>`).join("");
  return `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
<path d="${HEXAGON}" stroke="${color}" stroke-width="${w.hex}" stroke-linejoin="round"/>
${HEXAGRAM.map((d) => `<path d="${d}" stroke="${color}" stroke-width="${w.net}" stroke-linejoin="round" opacity="${w.netOpacity}"/>`).join("")}
<g fill="${color}">${dots(NODES, w.node)}${dots([FEED_DOT], w.feed)}</g>
${WAVES.map((d) => `<path d="${d}" stroke="${color}" stroke-width="${w.wave}" stroke-linecap="round"/>`).join("")}
</svg>`;
}

/** Draw the mark at `size` px in `color` on a 2D canvas context. */
export function drawMark(ctx, size, color, w = SMALL) {
  ctx.clearRect(0, 0, size, size);
  ctx.save();
  ctx.scale(size / 24, size / 24);
  ctx.strokeStyle = color;
  ctx.fillStyle = color;
  ctx.lineJoin = "round";
  ctx.lineCap = "round";
  ctx.lineWidth = w.hex;
  ctx.stroke(new Path2D(HEXAGON));
  ctx.globalAlpha = w.netOpacity;
  ctx.lineWidth = w.net;
  for (const d of HEXAGRAM) ctx.stroke(new Path2D(d));
  ctx.globalAlpha = 1;
  for (const [points, r] of [[NODES, w.node], [[FEED_DOT], w.feed]]) {
    for (const [x, y] of points) {
      ctx.beginPath();
      ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fill();
    }
  }
  ctx.lineWidth = w.wave;
  for (const d of WAVES) ctx.stroke(new Path2D(d));
  ctx.restore();
}
