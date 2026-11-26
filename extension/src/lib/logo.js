// The IntelFeed mark in the page headers (lib/mark.js), drawn in currentColor
// so it takes the theme's accent like the app's own logo does.

import { markSvg } from "./mark.js";

/** Fill every element marked data-logo with the mark. The markup is lib/mark.js's own constants. */
export function drawLogos(root = document) {
  const template = new DOMParser().parseFromString(markSvg(), "image/svg+xml").documentElement;
  for (const el of root.querySelectorAll("[data-logo]")) el.replaceChildren(document.importNode(template, true));
}
