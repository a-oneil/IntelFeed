/** The error envelope on an axios failure ({error: {code, message}}), or the thrown message. */
export function apiErrorInfo(err: unknown): { code: string | null; message: string } {
  const data = (err as { response?: { data?: { error?: { code?: string; message?: string } } } })?.response?.data;
  if (data?.error) {
    return { code: data.error.code ?? null, message: data.error.message ?? "Request failed" };
  }
  return { code: null, message: err instanceof Error ? err.message : "Request failed" };
}
