/**
 * Who answered an AI call, in the words the cards show.
 *
 * Results carry `provider_name` and `key_owner_id` (the person whose key
 * paid), and `_fallback_reason` on the parsed result when a person's key
 * could not answer and the instance's provider took the call. Copilot gets
 * the same facts on its `done` frame and `/config`. The reason codes come
 * from the backend's FALLBACK_REASONS; the text here is the reader-facing
 * version, with a verb for what to do next.
 */

export const FALLBACK_REASON_TEXT: Record<string, string> = {
  no_key: "You have no personal AI key for this task, so it ran on the instance's provider.",
  key_disabled: "Your personal key is disabled, so this ran on the instance's provider.",
  key_paused: "Your personal key is paused after a rate-limit response, so this ran on the instance's provider.",
  type_not_allowed: "Your personal key's provider type is no longer allowed here, so this ran on the instance's provider.",
  endpoint_blocked: "Your personal key's endpoint is not allowed on this instance, so this ran on the instance's provider.",
  monthly_cap: "Your personal key reached its monthly spend cap, so this ran on the instance's provider.",
  daily_cap: "Your personal key reached its daily request cap, so this ran on the instance's provider.",
};

/** The reader-facing sentence for a fallback reason code, or null when there was no fallback. */
export function fallbackMessage(reason: unknown): string | null {
  if (typeof reason !== "string" || !reason) return null;
  return FALLBACK_REASON_TEXT[reason] ?? `Your personal key could not answer (${reason}), so this ran on the instance's provider.`;
}

/** What to offer next to a fallback: the cap can be raised, a key can be fixed. */
export function fallbackFixLabel(reason: unknown): string {
  return reason === "monthly_cap" ? "Raise my cap" : "My AI settings";
}

