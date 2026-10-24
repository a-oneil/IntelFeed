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
  no_key: "You have no personal AI key for this prompt, so it ran on the instance's provider.",
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

/**
 * What to offer next to a fallback or a refusal: a missing key is added, a
 * cap is raised, anything else is fixed on the My AI page.
 */
export function fallbackFixLabel(reason: unknown): string {
  if (reason === "no_key") return "Add a key";
  if (reason === "monthly_cap" || reason === "daily_cap") return "Raise my cap";
  return "My AI settings";
}

/** The short form of a blocked reason, for a prompt row's "instance · key paused". */
export const BLOCKED_REASON_SHORT: Record<string, string> = {
  no_key: "no key",
  key_disabled: "key disabled",
  key_paused: "key paused",
  type_not_allowed: "type not allowed",
  endpoint_blocked: "endpoint blocked",
  monthly_cap: "over monthly cap",
  daily_cap: "over daily cap",
};

export function blockedReasonShort(reason: unknown): string | null {
  if (typeof reason !== "string" || !reason) return null;
  return BLOCKED_REASON_SHORT[reason] ?? reason.replace(/_/g, " ");
}

/** A cap reason: the fix is raising the cap, not adding a key. */
export function isCapReason(reason: unknown): boolean {
  return reason === "monthly_cap" || reason === "daily_cap";
}

