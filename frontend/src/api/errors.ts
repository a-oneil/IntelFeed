interface ErrorDetail {
  field?: string;
  loc?: Array<string | number>;
  message?: string;
  msg?: string;
}

/**
 * The error envelope on an axios failure ({error: {code, message, details}}),
 * or the thrown message. A validation refusal says only "Request validation
 * failed" at the top; the reason lives in details, so the first one is
 * appended (with its field, when named) and someone typing 0 as a cap sees why.
 */
export interface ApiErrorInfo {
  code: string | null;
  message: string;
  /** The envelope's raw `details` (a validation list or a {reason, ...} object), or null. */
  details: Record<string, unknown> | unknown[] | null;
}

/** True when the failure carries the API's {error: {...}} envelope. */
export function hasErrorEnvelope(err: unknown): boolean {
  return !!(err as { response?: { data?: { error?: unknown } } })?.response?.data?.error;
}

export function apiErrorInfo(err: unknown): ApiErrorInfo {
  const data = (err as { response?: { data?: { error?: { code?: string; message?: string; details?: unknown } } } })
    ?.response?.data;
  if (data?.error) {
    let message = data.error.message ?? "Request failed";
    const details = data.error.details;
    if (Array.isArray(details) && details.length > 0) {
      const first = details[0] as ErrorDetail;
      const reason = first?.message ?? first?.msg;
      if (reason) {
        const field = first.field || (Array.isArray(first.loc) ? first.loc.filter((p) => p !== "body").join(".") : "");
        message = `${message}: ${field ? `${field} — ` : ""}${reason}`;
      }
    }
    const exposed =
      details && typeof details === "object" ? (details as Record<string, unknown> | unknown[]) : null;
    return { code: data.error.code ?? null, message, details: exposed };
  }
  return { code: null, message: err instanceof Error ? err.message : "Request failed", details: null };
}

/**
 * The `reason` an AI refusal names in its details (`user_ai_key_required`
 * carries {reason: "no_key" | "monthly_cap" | ...}), or null.
 */
export function apiErrorReason(err: unknown): string | null {
  const { details } = apiErrorInfo(err);
  if (!details || Array.isArray(details)) return null;
  const reason = details.reason;
  return typeof reason === "string" && reason ? reason : null;
}
