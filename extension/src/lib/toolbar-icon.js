// The toolbar icon in the user's accent, as the app's favicon follows the
// theme. icons/icon-16.png and icon-32.png (scripts/dev/render_icons.cjs) are
// the same mark in the default accent, shown until a theme is stored.

import { drawMark } from "./mark.js";

/** Set the toolbar icon to the mark in `color`; without one, the packaged icons. */
export async function setToolbarIcon(color) {
  if (!color || typeof OffscreenCanvas === "undefined") return;
  const imageData = {};
  for (const size of [16, 32]) {
    const ctx = new OffscreenCanvas(size, size).getContext("2d");
    drawMark(ctx, size, color);
    imageData[size] = ctx.getImageData(0, 0, size, size);
  }
  await chrome.action.setIcon({ imageData });
}
