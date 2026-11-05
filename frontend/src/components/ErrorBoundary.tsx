import { Component, ErrorInfo, ReactNode } from "react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

// Chrome, Firefox and Safari spell a failed lazy-chunk import differently.
const CHUNK_ERROR =
  /Failed to fetch dynamically imported module|error loading dynamically imported module|Importing a module script failed/i;
const RELOAD_KEY = "intelfeed-chunk-reload-at";
const RELOAD_GUARD_MS = 10_000;

// After a deploy the old hashed chunks are gone; one reload picks up the new
// build. The timestamp guard stops a loop if the chunk is genuinely missing.
function reloadForStaleChunk(error: Error): boolean {
  if (!CHUNK_ERROR.test(error.message)) return false;
  try {
    const last = Number(sessionStorage.getItem(RELOAD_KEY) || 0);
    if (Date.now() - last < RELOAD_GUARD_MS) return false;
    sessionStorage.setItem(RELOAD_KEY, String(Date.now()));
  } catch {
    return false;
  }
  window.location.reload();
  return true;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    if (reloadForStaleChunk(error)) return;
    if (import.meta.env.DEV) {
      console.error("ErrorBoundary caught:", error, errorInfo);
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        this.props.fallback || (
          <div style={{ padding: "2rem", textAlign: "center" }}>
            <h2>Something went wrong</h2>
            <p style={{ color: "var(--text-secondary)", marginTop: "0.5rem" }}>
              {this.state.error?.message}
            </p>
            {/* Reload rather than reset: after a deploy the old chunk is gone and
                React.lazy caches the rejected import, so a reset re-throws at once. */}
            <button
              onClick={() => window.location.reload()}
              style={{
                marginTop: "1rem",
                padding: "0.5rem 1rem",
                background: "var(--accent)",
                color: "#fff",
                border: "none",
                borderRadius: "4px",
              }}
            >
              Try Again
            </button>
          </div>
        )
      );
    }
    return this.props.children;
  }
}
