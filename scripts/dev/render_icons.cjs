// Renders every IntelFeed icon from the mark below, so the web app, the PWA, the Android app and the browser extension share one set of artwork.
//
// The mark is a hexagon with a hexagram of network lines inside it, nodes where the lines cross, and a feed signal whose dot sits on the bottom-left crossing. It comes in two weights:
//   SMALL — heavier lines and nodes, for anything drawn at 32px or smaller (favicons, the extension's toolbar icon), where FULL's thin lines blur.
//   FULL  — on the app's dark tile, for launcher, home-screen and store icons.
//
// The in-app logos draw the same mark as vectors, from their own copies of the coordinates and weights: frontend/src/utils/brandMark.ts, extension/src/lib/mark.js, and android/app/src/main/res/drawable/ic_logo.xml, ic_notification.xml and ic_launcher_foreground.xml. When the mark changes, update all of them.
//
// Dev-only: uses Playwright's Chromium from the frontend's node_modules, so run `pnpm install` and `pnpm exec playwright install chromium` in frontend/ first.
//   node scripts/dev/render_icons.cjs

const path = require("path");
const fs = require("fs");

const ROOT = path.join(__dirname, "../..");
const pwDir = path.join(ROOT, "frontend/node_modules/.pnpm");
const pw = fs.existsSync(pwDir) && fs.readdirSync(pwDir).filter((d) => /^playwright@/.test(d)).sort().pop();
if (!pw) {
  console.error("Playwright not found. Run `pnpm install` and `pnpm exec playwright install chromium` in frontend/.");
  process.exit(1);
}
const { chromium } = require(path.join(pwDir, pw, "node_modules/playwright"));

const ACCENT = "#f78166";
const TILE = "#0d1117";

const WEIGHTS = {
  SMALL: { hex: 1.7, net: 0.85, netOpacity: 0.65, node: 0.95, feed: 1.5, wave: 1.65 },
  FULL: { hex: 1.35, net: 0.7, netOpacity: 0.6, node: 0.8, feed: 1.3, wave: 1.4 },
};
// Crossings that carry a node. Bottom-left is the feed dot; left and bottom-right are left bare, because a node there would crowd the feed signal.
const NODES = [[8.5, 7.5], [15.5, 7.5], [18.3, 12]];

function mark(w, color = ACCENT) {
  const dots = (points, r) => points.map(([x, y]) => `<circle cx="${x}" cy="${y}" r="${r}"/>`).join("");
  return `<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="none">
<path d="M12 2L21.2 7.5V16.5L12 22L2.8 16.5V7.5Z" stroke="${color}" stroke-width="${w.hex}" stroke-linejoin="round"/>
<path d="M12 2L21.2 16.5L2.8 16.5Z" stroke="${color}" stroke-width="${w.net}" stroke-linejoin="round" opacity="${w.netOpacity}"/>
<path d="M21.2 7.5L12 22L2.8 7.5Z" stroke="${color}" stroke-width="${w.net}" stroke-linejoin="round" opacity="${w.netOpacity}"/>
<g fill="${color}">${dots(NODES, w.node)}<circle cx="8.5" cy="16.5" r="${w.feed}"/></g>
<path d="M8.5 13.5C10.16 13.5 11.5 14.84 11.5 16.5" stroke="${color}" stroke-width="${w.wave}" stroke-linecap="round"/>
<path d="M8.5 10.8C11.65 10.8 14.2 13.35 14.2 16.5" stroke="${color}" stroke-width="${w.wave}" stroke-linecap="round"/>
</svg>`;
}

const SMALL = mark(WEIGHTS.SMALL);
const FULL = mark(WEIGHTS.FULL);

const sized = (svg, px) => svg.replace("<svg", `<svg width="${px}" height="${px}"`);

/**
 * One icon's page.
 *   bare:  the small mark, no background
 *   tile:  the full mark on the dark tile. radius is a fraction of the size ("50%" for a circle); mark is how much of the tile it fills.
 */
function page(size, { bare, radius = 0.2, mark = 0.8 }) {
  const body = (inner) => `<body style="margin:0;background:transparent">${inner}</body>`;
  if (bare) return body(`<div style="width:${size}px;height:${size}px">${sized(SMALL, size)}</div>`);
  const r = radius === "50%" ? "50%" : `${Math.round(size * radius)}px`;
  return body(
    `<div style="width:${size}px;height:${size}px;border-radius:${r};background:${TILE};display:flex;align-items:center;justify-content:center">${sized(FULL, Math.round(size * mark))}</div>`,
  );
}

const ANDROID_DENSITIES = { mdpi: 48, hdpi: 72, xhdpi: 96, xxhdpi: 144, xxxhdpi: 192 };

const ICONS = [
  // Browser extension
  ...[16, 32].map((s) => [`extension/icons/icon-${s}.png`, s, { bare: true }]),
  ...[48, 128].map((s) => [`extension/icons/icon-${s}.png`, s, {}]),
  // Web app: favicons, iOS home screen (iOS rounds the corners itself), PWA
  ["frontend/public/favicon-16x16.png", 16, { bare: true }],
  ["frontend/public/favicon-32x32.png", 32, { bare: true }],
  ["frontend/public/apple-touch-icon.png", 180, { radius: 0, mark: 0.7 }],
  ["frontend/public/icon-192.png", 192, {}],
  ["frontend/public/icon-512.png", 512, {}],
  // Maskable: full bleed, the mark inside the 80% safe-zone circle
  ["frontend/public/icon-maskable-512.png", 512, { radius: 0, mark: 0.6 }],
  // Android launcher before adaptive icons (API 24-25)
  ...Object.entries(ANDROID_DENSITIES).flatMap(([d, s]) => [
    [`android/app/src/main/res/mipmap-${d}/ic_launcher.png`, s, { radius: 0.2, mark: 0.72 }],
    [`android/app/src/main/res/mipmap-${d}/ic_launcher_round.png`, s, { radius: "50%", mark: 0.66 }],
  ]),
];

/** The README's logo: the full mark and the wordmark. "Intel" is a mid gray that is readable on both GitHub's light and dark pages, "Feed" is the accent color. */
function docsLogo() {
  const inner = FULL.replace(/^<svg[^>]*>\n?/, "")
    .replace(/<\/svg>$/, "")
    .trim()
    .split("\n")
    .map((line) => `    ${line}`)
    .join("\n");
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 300 76" width="300" height="76" role="img" aria-label="IntelFeed">
  <title>IntelFeed</title>
  <g transform="translate(6 8) scale(2.3333)" fill="none">
${inner}
  </g>
  <text x="80" y="49" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
        font-size="38" font-weight="700" letter-spacing="-0.5">
    <tspan fill="#7d8590">Intel</tspan><tspan fill="${ACCENT}">Feed</tspan>
  </text>
</svg>
`;
}

(async () => {
  fs.writeFileSync(path.join(ROOT, "docs/assets/intelfeed-logo.svg"), docsLogo());
  console.log("docs/assets/intelfeed-logo.svg");

  // The scalable favicon is the small mark itself; useThemes.ts recolors it to the theme's accent.
  fs.writeFileSync(path.join(ROOT, "frontend/public/favicon.svg"), sized(SMALL, 32) + "\n");
  console.log("frontend/public/favicon.svg");

  const browser = await chromium.launch();
  for (const [file, size, opts] of ICONS) {
    const p = await browser.newPage({ viewport: { width: size, height: size }, deviceScaleFactor: 1 });
    await p.setContent(page(size, opts));
    await p.screenshot({ path: path.join(ROOT, file), omitBackground: true });
    await p.close();
    console.log(file);
  }
  await browser.close();
})();
