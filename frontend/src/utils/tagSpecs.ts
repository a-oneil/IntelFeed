/**
 * The `tags` list of an automation `add_tags` action.
 *
 * Each item is a bare tag name, or a name plus the presentation to give the tag
 * if the rule has to create it: colour, chip promotion, tooltip. The backend
 * applies that presentation on create only — an existing tag keeps its own look.
 */
export interface NewTagSpec {
  name: string;
  color?: string;
  description?: string;
  chip?: boolean;
}

export type TagSpec = string | NewTagSpec;

export const DEFAULT_TAG_COLOR = "#6B7280";

export function tagSpecName(spec: TagSpec): string {
  return typeof spec === "string" ? spec : spec.name;
}

/** Coerce a stored `tags` config value (array or legacy comma string) to specs. */
export function toTagSpecs(value: unknown): TagSpec[] {
  if (typeof value === "string") return value.split(",").map((s) => s.trim()).filter(Boolean);
  if (!Array.isArray(value)) return [];
  return value.filter(
    (v): v is TagSpec =>
      (typeof v === "string" && v.trim() !== "") ||
      (typeof v === "object" && v !== null && typeof (v as NewTagSpec).name === "string" && (v as NewTagSpec).name.trim() !== ""),
  );
}

/**
 * A spec with nothing beyond its name collapses back to a bare string, so a
 * rule that never set a colour or chip saves exactly the shape it always did.
 */
export function normalizeTagSpec(spec: TagSpec): TagSpec {
  if (typeof spec === "string") return spec;
  const { name, color, description, chip } = spec;
  const out: NewTagSpec = { name };
  if (color && color.toLowerCase() !== DEFAULT_TAG_COLOR.toLowerCase()) out.color = color;
  // Kept untrimmed: this runs on every keystroke, and trimming would eat the
  // space between words as it's typed. The server trims on create.
  if (description?.trim()) out.description = description;
  if (chip) out.chip = true;
  return Object.keys(out).length === 1 ? name : out;
}

/** Rebuild specs from an edited list of names, keeping what each surviving name carried. */
export function specsFromNames(names: string[], previous: TagSpec[]): TagSpec[] {
  const byName = new Map(previous.map((s) => [tagSpecName(s), s]));
  return names.map((n) => byName.get(n) ?? n);
}
