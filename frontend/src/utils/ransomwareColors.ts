/** Ransomware group → CSS var color. Mirrors the backend `group_color_slug`
 * (app/schemas/ransomware.py): known groups get a CVD-validated categorical color,
 * everything else falls back to grey. Colour is always paired with the label. */

const GROUP_SLUGS = new Set(["lockbit", "clop", "akira", "qilin", "play", "ransomhub"]);

/** Accepts the backend `group_color` slug (preferred) or a raw group name. */
export function ransomwareGroupColor(slugOrName: string | null | undefined): string {
  if (!slugOrName) return "var(--rgroup-other)";
  const key = slugOrName.trim().toLowerCase().replace("cl0p", "clop");
  return GROUP_SLUGS.has(key) ? `var(--rgroup-${key})` : "var(--rgroup-other)";
}
