import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ErrorBoundary } from "@/components/ErrorBoundary";

// Suppress console.error output from ErrorBoundary.componentDidCatch and React internals
const originalConsoleError = console.error;
beforeEach(() => {
  console.error = vi.fn();
});
afterEach(() => {
  console.error = originalConsoleError;
});

function ProblemChild({ shouldThrow = true }: { shouldThrow?: boolean }) {
  if (shouldThrow) {
    throw new Error("Test explosion");
  }
  return <div>Child rendered successfully</div>;
}

describe("ErrorBoundary", () => {
  it("renders children when no error occurs", () => {
    render(
      <ErrorBoundary>
        <div>All good here</div>
      </ErrorBoundary>
    );
    expect(screen.getByText("All good here")).toBeInTheDocument();
  });

  it("catches errors and shows fallback UI", () => {
    render(
      <ErrorBoundary>
        <ProblemChild />
      </ErrorBoundary>
    );
    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
    expect(screen.queryByText("Child rendered successfully")).not.toBeInTheDocument();
  });

  it("displays the error message", () => {
    render(
      <ErrorBoundary>
        <ProblemChild />
      </ErrorBoundary>
    );
    expect(screen.getByText("Test explosion")).toBeInTheDocument();
  });

  it("reloads the page when Try Again is clicked", () => {
    const reload = vi.fn();
    const originalLocation = window.location;
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...originalLocation, reload },
    });

    render(
      <ErrorBoundary>
        <ProblemChild />
      </ErrorBoundary>
    );
    fireEvent.click(screen.getByText("Try Again"));

    expect(reload).toHaveBeenCalledOnce();
    Object.defineProperty(window, "location", {
      configurable: true,
      value: originalLocation,
    });
  });

  describe("stale chunk after a deploy", () => {
    const originalLocation = window.location;
    let reload: ReturnType<typeof vi.fn>;

    function ChunkFail(): never {
      throw new TypeError(
        "error loading dynamically imported module: https://intelfeed.cc/assets/SettingsPage-Bi0eanzo.js"
      );
    }

    beforeEach(() => {
      sessionStorage.clear();
      reload = vi.fn();
      Object.defineProperty(window, "location", {
        configurable: true,
        value: { ...originalLocation, reload },
      });
    });
    afterEach(() => {
      Object.defineProperty(window, "location", {
        configurable: true,
        value: originalLocation,
      });
    });

    it("reloads once on its own", () => {
      render(
        <ErrorBoundary>
          <ChunkFail />
        </ErrorBoundary>
      );
      expect(reload).toHaveBeenCalledOnce();
    });

    it("does not loop when the chunk is still missing after the reload", () => {
      sessionStorage.setItem("intelfeed-chunk-reload-at", String(Date.now()));
      render(
        <ErrorBoundary>
          <ChunkFail />
        </ErrorBoundary>
      );
      expect(reload).not.toHaveBeenCalled();
      expect(screen.getByText("Something went wrong")).toBeInTheDocument();
    });

    it("leaves other errors alone", () => {
      render(
        <ErrorBoundary>
          <ProblemChild />
        </ErrorBoundary>
      );
      expect(reload).not.toHaveBeenCalled();
    });
  });

  it("renders custom fallback when provided", () => {
    const customFallback = <div>Custom error page</div>;

    render(
      <ErrorBoundary fallback={customFallback}>
        <ProblemChild />
      </ErrorBoundary>
    );

    expect(screen.getByText("Custom error page")).toBeInTheDocument();
    expect(screen.queryByText("Something went wrong")).not.toBeInTheDocument();
    expect(screen.queryByText("Try Again")).not.toBeInTheDocument();
  });
});
