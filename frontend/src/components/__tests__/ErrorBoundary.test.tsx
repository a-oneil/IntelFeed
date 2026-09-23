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

  it("resets state and re-renders children when Try Again is clicked", () => {
    let shouldThrow = true;

    function ConditionalChild() {
      if (shouldThrow) {
        throw new Error("Temporary failure");
      }
      return <div>Recovered child</div>;
    }

    render(
      <ErrorBoundary>
        <ConditionalChild />
      </ErrorBoundary>
    );

    expect(screen.getByText("Something went wrong")).toBeInTheDocument();

    // Fix the child before clicking Try Again
    shouldThrow = false;
    fireEvent.click(screen.getByText("Try Again"));

    expect(screen.getByText("Recovered child")).toBeInTheDocument();
    expect(screen.queryByText("Something went wrong")).not.toBeInTheDocument();
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
