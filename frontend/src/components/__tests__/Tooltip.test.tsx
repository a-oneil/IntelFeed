import { render, screen, fireEvent, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Tooltip } from "../Tooltip";

const rect = (r: Partial<DOMRect>): DOMRect =>
  ({ x: 0, y: 0, top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0,
     toJSON: () => ({}), ...r } as DOMRect);

/** jsdom measures everything as 0x0, so stand in real geometry: a category row
 *  hard against the left window edge, and a card far wider than the space to
 *  its left — the shape that used to hang off-screen. */
function mockGeometry() {
  vi.spyOn(Element.prototype, "getBoundingClientRect").mockImplementation(function (
    this: Element,
  ) {
    return this.getAttribute("role") === "tooltip"
      ? rect({ top: 0, left: 0, right: 560, bottom: 120, width: 560, height: 120 })
      : rect({ top: 100, left: 12, right: 112, bottom: 120, width: 100, height: 20 });
  });
}

/** Swap in a matchMedia that answers the given queries true, everything else
 *  false — the setup mock's default is a desktop with a mouse. */
function mockMedia(matching: RegExp) {
  const real = window.matchMedia;
  window.matchMedia = ((query: string) => ({ ...real(query), matches: matching.test(query) })) as typeof window.matchMedia;
  return () => {
    window.matchMedia = real;
  };
}

describe("Tooltip", () => {
  beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }));
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("shows after the hover delay and hides on leave", () => {
    render(
      <Tooltip content={<span>3 feeds</span>}>
        <span>Vendor Research</span>
      </Tooltip>,
    );
    const trigger = screen.getByText("Vendor Research").parentElement!;

    fireEvent.mouseEnter(trigger);
    act(() => void vi.advanceTimersByTime(200));
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();

    act(() => void vi.advanceTimersByTime(300));
    expect(screen.getByRole("tooltip")).toHaveTextContent("3 feeds");

    fireEvent.mouseLeave(trigger);
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });

  it("clamps a wide card to the viewport instead of hanging off the left edge", () => {
    mockGeometry();
    render(
      <Tooltip position="bottom" content={<span>a very wide stat stack</span>}>
        <span>Vendor Research</span>
      </Tooltip>,
    );
    const trigger = screen.getByText("Vendor Research").parentElement!;

    fireEvent.mouseEnter(trigger);
    act(() => void vi.advanceTimersByTime(400));

    const card = screen.getByRole("tooltip");
    // Centred on the row the card would start at 12 + 50 - 280 = -218; the
    // clamp pulls it back to the 8px viewport margin.
    expect(parseFloat(card.style.left)).toBe(8);
    expect(parseFloat(card.style.left) + 560).toBeLessThanOrEqual(window.innerWidth);
  });

  it.each([
    ["a touch device", /nothing-matches/],
    ["mobile width", /hover: hover|pointer: fine|max-width: 767px/],
  ])("renders nothing on %s", (_label, matching) => {
    const restore = mockMedia(matching);
    try {
      render(
        <Tooltip content={<span>3 feeds</span>}>
          <span>Vendor Research</span>
        </Tooltip>,
      );
      fireEvent.mouseEnter(screen.getByText("Vendor Research").parentElement!);
      act(() => void vi.advanceTimersByTime(1000));
      expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
    } finally {
      restore();
    }
  });

  it("closes on scroll rather than drifting away from its row", () => {
    render(
      <Tooltip content={<span>3 feeds</span>}>
        <span>Vendor Research</span>
      </Tooltip>,
    );
    fireEvent.mouseEnter(screen.getByText("Vendor Research").parentElement!);
    act(() => void vi.advanceTimersByTime(400));
    expect(screen.getByRole("tooltip")).toBeInTheDocument();

    act(() => void fireEvent.scroll(window));
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });
});
