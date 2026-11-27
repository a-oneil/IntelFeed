import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useTts } from "../useTts";

const mocks = vi.hoisted(() => ({
  post: vi.fn(),
  play: vi.fn(),
  loading: vi.fn(),
  dismiss: vi.fn(),
  success: vi.fn(),
}));

vi.mock("@/api/client", () => ({ default: { post: mocks.post } }));
vi.mock("@/stores/authStore", () => ({
  selectIsVisitor: () => false,
  useAuthStore: { getState: () => ({ accessToken: "test-token" }) },
}));
vi.mock("@/stores/playerStore", () => ({
  usePlayerStore: (select: (state: { play: typeof mocks.play }) => unknown) => select({ play: mocks.play }),
}));
vi.mock("sonner", () => ({ toast: { loading: mocks.loading, dismiss: mocks.dismiss, success: mocks.success } }));

const args = { source: "entry" as const, id: "entry-1", track: { entryId: "entry-1", title: "Article", feedTitle: "Feed" } };
const ready = { data: { status: "ready", cache_key: "audio-1" } };

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => { resolve = r; });
  return { promise, resolve };
}

describe("useTts cancellation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("still plays through the global player after the caller unmounts", async () => {
    // A day divider scrolled out of the virtual list, or a closed reader, must not drop the audio the user asked for.
    const response = deferred<typeof ready>();
    mocks.post.mockReturnValueOnce(response.promise);
    const { result, unmount } = renderHook(() => useTts());
    let pending!: ReturnType<typeof result.current.start>;
    act(() => { pending = result.current.start(args); });
    unmount();
    response.resolve(ready);
    expect(await pending).toBe(true);
    expect(mocks.play).toHaveBeenCalledTimes(1);
  });

  it("stops polling when canceled and clears preparing state", async () => {
    vi.useFakeTimers();
    mocks.post.mockResolvedValue({ data: { status: "pending", cache_key: "audio-1" } });
    const { result } = renderHook(() => useTts());
    let pending!: ReturnType<typeof result.current.start>;
    await act(async () => { pending = result.current.start(args); });
    expect(result.current.isPreparing).toBe(true);
    act(() => { result.current.cancel(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1500); });
    expect(await pending).toBeNull();
    expect(result.current.isPreparing).toBe(false);
    expect(mocks.post).toHaveBeenCalledTimes(1);
    expect(mocks.play).not.toHaveBeenCalled();
  });

  it("keeps a superseded request canceled when a new request starts", async () => {
    const oldResponse = deferred<typeof ready>();
    const newResponse = deferred<typeof ready>();
    mocks.post.mockReturnValueOnce(oldResponse.promise).mockReturnValueOnce(newResponse.promise);
    const { result } = renderHook(() => useTts());
    let oldRequest!: ReturnType<typeof result.current.start>;
    let newRequest!: ReturnType<typeof result.current.start>;
    act(() => { oldRequest = result.current.start(args); });
    act(() => { newRequest = result.current.start(args); });
    await act(async () => { oldResponse.resolve(ready); await oldRequest; });
    expect(await oldRequest).toBeNull();
    expect(result.current.isPreparing).toBe(true);
    expect(mocks.play).not.toHaveBeenCalled();
    await act(async () => { newResponse.resolve(ready); await newRequest; });
    expect(await newRequest).toBe(true);
    expect(result.current.isPreparing).toBe(false);
    expect(mocks.play).toHaveBeenCalledTimes(1);
  });

  it("still requests browser fallback on a real preparation failure", async () => {
    mocks.post.mockRejectedValueOnce(new Error("Piper unavailable"));
    const { result } = renderHook(() => useTts());
    await act(async () => { expect(await result.current.start(args)).toBe(false); });
    expect(result.current.isPreparing).toBe(false);
    expect(mocks.play).not.toHaveBeenCalled();
  });
});
