import { Component, ErrorInfo, ReactNode } from "react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
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
            <button
              onClick={() => this.setState({ hasError: false, error: null })}
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
