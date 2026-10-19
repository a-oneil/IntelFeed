import { render, screen, fireEvent, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Hint } from "../primitives/Hint";

const COPY = {
  title: "Priority Queue",
  body: "The unread pile re-ordered by signal score instead of by time.",
  aside: "Scored on source reliability, entity heat and what you've read before.",
};

/** Swap in a matchMedia that answers the given queries true, everything else
 *  false — the setup mock's default is a desktop with a mouse. */
function mockMedia(matching: RegExp) {
  const real = window.matchMedia;
  window.matchMedia = ((query: string) => ({ ...real(query), matches: matching.test(query) })) as typeof window.matchMedia;
  return () => {
    window.matchMedia = real;
  };
}

describe("Hint", () => {
  beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }));
  afterEach(() => vi.useRealTimers());

  it("renders the control unchanged and no card until hovered", () => {
    render(
      <Hint {...COPY}>
        <button className="chip">Priority Queue</button>
      </Hint>,
    );
    const btn = screen.getByRole("button", { name: "Priority Queue" });
    expect(btn).toHaveClass("chip");
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });

  it("shows the card only after the hover delay, then hides on leave", () => {
    render(
      <Hint {...COPY}>
        <button>Priority Queue</button>
      </Hint>,
    );
    const btn = screen.getByRole("button");

    fireEvent.mouseEnter(btn);
    act(() => void vi.advanceTimersByTime(200));
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();

    act(() => void vi.advanceTimersByTime(300));
    const card = screen.getByRole("tooltip");
    expect(card).toHaveTextContent(COPY.title);
    expect(card).toHaveTextContent(COPY.body);
    expect(card).toHaveTextContent(COPY.aside);
    expect(btn).toHaveAttribute("aria-describedby", card.id);

    fireEvent.mouseLeave(btn);
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });

  it("shows immediately on keyboard focus — the delay is a hover courtesy", () => {
    render(
      <Hint {...COPY}>
        <button>Priority Queue</button>
      </Hint>,
    );
    fireEvent.focus(screen.getByRole("button"));
    act(() => void vi.advanceTimersByTime(0));
    expect(screen.getByRole("tooltip")).toBeInTheDocument();
  });

  it("keeps the call site's own handlers", () => {
    const onMouseEnter = vi.fn();
    const onClick = vi.fn();
    render(
      <Hint {...COPY}>
        <button onMouseEnter={onMouseEnter} onClick={onClick}>
          Priority Queue
        </button>
      </Hint>,
    );
    const btn = screen.getByRole("button");
    fireEvent.mouseEnter(btn);
    fireEvent.click(btn);
    expect(onMouseEnter).toHaveBeenCalledOnce();
    expect(onClick).toHaveBeenCalledOnce();
  });

  it("renders no card at all when disabled", () => {
    render(
      <Hint {...COPY} disabled>
        <button>Priority Queue</button>
      </Hint>,
    );
    fireEvent.mouseEnter(screen.getByRole("button"));
    act(() => void vi.advanceTimersByTime(1000));
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });

  it("closes when its control is clicked — activating it answers the question", () => {
    render(
      <Hint {...COPY}>
        <button>Priority Queue</button>
      </Hint>,
    );
    const btn = screen.getByRole("button");
    fireEvent.mouseEnter(btn);
    act(() => void vi.advanceTimersByTime(500));
    expect(screen.getByRole("tooltip")).toBeInTheDocument();

    fireEvent.click(btn);
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });

  it("does not resurrect an open card after being disabled and re-enabled", () => {
    // The matrix header disables the hint while its peek popover is open. The
    // bare child it hands back has no leave handler, so without a reset the
    // hover anchor would survive and the card would come back on re-enable.
    const { rerender } = render(
      <Hint {...COPY}>
        <button>Priority Queue</button>
      </Hint>,
    );
    fireEvent.mouseEnter(screen.getByRole("button"));
    act(() => void vi.advanceTimersByTime(500));
    expect(screen.getByRole("tooltip")).toBeInTheDocument();

    rerender(
      <Hint {...COPY} disabled>
        <button>Priority Queue</button>
      </Hint>,
    );
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();

    rerender(
      <Hint {...COPY}>
        <button>Priority Queue</button>
      </Hint>,
    );
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });

  it("omits the aside line when there isn't one", () => {
    render(
      <Hint title="Documentation" body="Guides for every part of IntelFeed.">
        <button>Docs</button>
      </Hint>,
    );
    fireEvent.focus(screen.getByRole("button"));
    act(() => void vi.advanceTimersByTime(0));
    expect(screen.getByRole("tooltip").querySelectorAll("span")).toHaveLength(1);
  });

  it.each([
    ["a touch device — a tap would need a second tap to dismiss", /nothing-matches/],
    ["mobile width, mouse or not — the card would cover what it explains", /hover: hover|pointer: fine|max-width: 767px/],
  ])("renders no card on %s", (_label, matching) => {
    const restore = mockMedia(matching);
    try {
      render(
        <Hint {...COPY}>
          <button>Priority Queue</button>
        </Hint>,
      );
      const btn = screen.getByRole("button");
      fireEvent.mouseEnter(btn);
      fireEvent.focus(btn);
      act(() => void vi.advanceTimersByTime(1000));
      expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
    } finally {
      restore();
    }
  });

  it("closes on scroll rather than drifting away from its control", () => {
    render(
      <Hint {...COPY}>
        <button>Priority Queue</button>
      </Hint>,
    );
    fireEvent.focus(screen.getByRole("button"));
    act(() => void vi.advanceTimersByTime(0));
    expect(screen.getByRole("tooltip")).toBeInTheDocument();

    act(() => void fireEvent.scroll(window));
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });
});
