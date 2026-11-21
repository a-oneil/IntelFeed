import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("sonner", () => ({ toast: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { toast } from "sonner";
import { useAuthStore } from "@/stores/authStore";
import { SLOW_SERVER_TOAST_ID, queryClient, timeoutDetail, toastTimeout } from "../queryClient";

const timeout = (url = "/entries/count", method = "get") => ({
  code: "ECONNABORTED",
  message: "timeout of 15000ms exceeded",
  config: { url, method, timeout: 15000 },
});

const user = (role: string) =>
  ({ id: "u1", username: "x", role, is_active: true, settings: {}, theme_id: null, custom_css: null, last_login: null, created_at: "" }) as never;

describe("timeout toasts", () => {
  beforeEach(() => {
    vi.mocked(toast.error).mockClear();
    useAuthStore.setState({ user: null });
  });

  it("is one plain message for everyone, shared by id so a page stalls into one toast", () => {
    useAuthStore.setState({ user: user("analyst") });
    toastTimeout(timeout(), "query");
    toastTimeout(timeout("/entries"), "query");
    expect(toast.error).toHaveBeenCalledTimes(2);
    for (const call of vi.mocked(toast.error).mock.calls) {
      expect(call[0]).toMatch(/server is busy/i);
      expect(call[0]).not.toMatch(/15000ms/);
      expect(call[1]).toMatchObject({ id: SLOW_SERVER_TOAST_ID, description: undefined });
    }
  });

  it("tells an admin which call gave up and how long it waited", () => {
    useAuthStore.setState({ user: user("admin") });
    toastTimeout(timeout("/entries/count"), "query");
    expect(vi.mocked(toast.error).mock.calls[0][1]).toMatchObject({
      id: SLOW_SERVER_TOAST_ID,
      description: "GET /entries/count gave up after 15s.",
    });
    expect(timeoutDetail({})).toBeUndefined();
  });

  it("says an action did not finish, rather than that panels are loading", () => {
    toastTimeout(timeout("/feeds", "post"), "mutation");
    expect(vi.mocked(toast.error).mock.calls[0][0]).toMatch(/did not finish that action/);
  });

  it("waits a few seconds before retrying a timed-out query, and backs off otherwise", () => {
    const retryDelay = queryClient.getDefaultOptions().queries?.retryDelay as (n: number, e: unknown) => number;
    expect(retryDelay(0, timeout())).toBe(3000);
    expect(retryDelay(0, new Error("boom"))).toBe(1000);
    expect(retryDelay(1, new Error("boom"))).toBe(2000);
  });
});
