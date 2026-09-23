import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import Markdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import { RouteFallback } from "@/components/RouteFallback";

// Assistant messages cite IntelFeed objects as relative links (/?entry=…,
// /workbench/…). On this public page a normal full-page navigation into the
// app is correct; external links open in a new tab.
const markdownComponents: Components = {
  a: ({ href, children, ...props }) => {
    const isInternal = !!href && href.startsWith("/") && !href.startsWith("//");
    if (isInternal) {
      return (
        <a {...props} href={href}>
          {children}
        </a>
      );
    }
    return (
      <a {...props} href={href} target="_blank" rel="noopener noreferrer">
        {children}
      </a>
    );
  },
};

interface SharedMessage {
  role: string;
  content: string;
}

interface SharedConversation {
  title: string | null;
  scope_type: string;
  messages: SharedMessage[];
}

/**
 * Public, read-only view of a shared copilot conversation. No auth — fetches the
 * unauthenticated /api/shared/copilot/{token} endpoint directly.
 */
export function SharedCopilotPage() {
  const { token } = useParams<{ token: string }>();
  const [data, setData] = useState<SharedConversation | null>(null);
  const [state, setState] = useState<"loading" | "ok" | "error">("loading");

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/shared/copilot/${token}`)
      .then((r) => {
        if (!r.ok) throw new Error("not found");
        return r.json();
      })
      .then((d: SharedConversation) => {
        if (!cancelled) {
          setData(d);
          setState("ok");
        }
      })
      .catch(() => {
        if (!cancelled) setState("error");
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  // The app shell (App.tsx) is a fixed-height flex row with overflow:hidden,
  // so this page must own its scrolling or long conversations get clipped.
  const page: React.CSSProperties = {
    height: "100%",
    overflowY: "auto",
  };
  const wrap: React.CSSProperties = {
    maxWidth: 760,
    margin: "0 auto",
    padding: "32px 20px 80px",
    color: "var(--text-primary, #e5e5e5)",
  };

  if (state === "loading") {
    return (
      <div style={page}>
        <RouteFallback />
      </div>
    );
  }
  if (state === "error" || !data) {
    return (
      <div style={page}>
        <div style={wrap}>
          <h1 style={{ fontSize: 20 }}>Conversation not found</h1>
          <p style={{ color: "var(--text-muted, #999)" }}>
            This shared link is invalid or has been revoked.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div style={page}>
    <div style={wrap}>
      <div
        style={{
          fontSize: 12,
          letterSpacing: 1,
          textTransform: "uppercase",
          color: "var(--accent, #f97316)",
          marginBottom: 6,
        }}
      >
        ✦ IntelFeed Copilot
      </div>
      <h1 style={{ fontSize: 22, margin: "0 0 24px" }}>
        {data.title || "Shared conversation"}
      </h1>
      {data.messages.map((m, i) => (
        <div
          key={i}
          style={{
            borderLeft: `2px solid ${
              m.role === "user"
                ? "var(--border, #444)"
                : "var(--accent, #f97316)"
            }`,
            padding: "4px 0 4px 12px",
            margin: "0 0 20px",
          }}
        >
          <div
            style={{
              fontSize: 11,
              textTransform: "uppercase",
              letterSpacing: 1,
              color: "var(--text-muted, #999)",
              marginBottom: 4,
            }}
          >
            {m.role === "user" ? "You" : "IntelFeed"}
          </div>
          <div style={{ lineHeight: 1.6 }}>
            {m.role === "user" ? (
              m.content
            ) : (
              <Markdown remarkPlugins={[remarkGfm]} components={markdownComponents}>{m.content}</Markdown>
            )}
          </div>
        </div>
      ))}
      <p style={{ marginTop: 40, fontSize: 12, color: "var(--text-muted, #999)" }}>
        Read-only shared conversation · <a href="/">Open IntelFeed</a>
      </p>
    </div>
    </div>
  );
}
