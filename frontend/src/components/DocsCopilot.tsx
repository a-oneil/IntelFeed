import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import Markdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import { streamCopilotChat } from "@/hooks/useAI";
import { useUIStore, type DocsChatMessage } from "@/stores/uiStore";
import { ToolTraceChip } from "@/components/ToolTraceChip";
import styles from "./DocsCopilot.module.css";

/**
 * The docs landing page's chat. A deliberately smaller surface than the global
 * copilot dock: no conversation history, slash commands, pinned context or
 * confirmable writes — this window exists to answer "how does IntelFeed do X"
 * from the documentation, and the backend puts it in docs mode off the
 * `/documentation` route it sends as context.
 */
const SUGGESTED_QUESTIONS = [
  "How do I add a new feed?",
  "What does the Priority Queue rank on?",
  "How does watching an entity work?",
  "How do I turn an article into a detection rule?",
];

export function DocsCopilot({ docSlug }: { docSlug?: string }) {
  // The thread lives in the store, not in this component: the docs page
  // unmounts whenever you follow a link out of it, and a chat that restarted
  // every time you went to read the page it just cited was useless.
  const { conversationId, messages, streaming = false } = useUIStore((s) => s.docsChat);
  const setDocsChat = useUIStore((s) => s.setDocsChat);
  const resetDocsChat = useUIStore((s) => s.resetDocsChat);
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);

  const setMessages = useCallback(
    (update: (prev: DocsChatMessage[]) => DocsChatMessage[]) =>
      setDocsChat((prev) => ({ ...prev, messages: update(prev.messages) })),
    [setDocsChat],
  );
  const setConversationId = useCallback(
    (id: string | null) => setDocsChat((prev) => ({ ...prev, conversationId: id })),
    [setDocsChat],
  );
  const setStreaming = useCallback(
    (value: boolean) => setDocsChat((prev) => ({ ...prev, streaming: value })),
    [setDocsChat],
  );
  const abortRef = useRef<AbortController | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  // Docs answers cite pages as /documentation/<slug>; route those through the
  // SPA router so following a citation doesn't reload the app.
  const markdownComponents: Components = {
    a: ({ href, children, ...props }) => {
      const internal = !!href && href.startsWith("/") && !href.startsWith("//");
      if (internal) {
        return (
          <a
            {...props}
            href={href}
            onClick={(e) => {
              e.preventDefault();
              navigate(href);
            }}
          >
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

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, streaming]);

  const send = useCallback(
    (question: string) => {
      const trimmed = question.trim();
      if (!trimmed || streaming) return;

      setInput("");
      setError(null);
      setStreaming(true);
      setMessages((prev) => [
        ...prev,
        { role: "user", content: trimmed },
        { role: "assistant", content: "", traces: [] },
      ]);

      // Mutate only the trailing assistant turn — it is the one being streamed.
      const patchLast = (fn: (m: DocsChatMessage) => DocsChatMessage) =>
        setMessages((prev) => {
          const next = [...prev];
          next[next.length - 1] = fn(next[next.length - 1]);
          return next;
        });

      const controller = new AbortController();
      abortRef.current = controller;

      void streamCopilotChat(
        {
          question: trimmed,
          conversationId,
          // No confirm cards here, so ask for read tools only.
          context: { route: "/documentation", read_only: true, ...(docSlug ? { doc_slug: docSlug } : {}) },
          onChunk: (text) => patchLast((m) => ({ ...m, content: m.content + text })),
          onToolCall: (call) =>
            patchLast((m) => ({
              ...m,
              traces: [...(m.traces ?? []), { id: call.id, name: call.name, args: call.args, status: "pending" }],
            })),
          onToolResult: (result) =>
            patchLast((m) => ({
              ...m,
              traces: (m.traces ?? []).map((t) =>
                t.id === result.id ? { ...t, status: result.status, summary: result.summary } : t,
              ),
            })),
          onDone: (id) => {
            if (id) setConversationId(id);
            setStreaming(false);
          },
          onError: (message) => {
            setError(message);
            setStreaming(false);
            // Drop the empty assistant placeholder so the error isn't shown
            // under a blank bubble.
            setMessages((prev) => {
              const last = prev[prev.length - 1];
              return last && last.role === "assistant" && !last.content ? prev.slice(0, -1) : prev;
            });
          },
        },
        controller.signal,
      );
    },
    [conversationId, docSlug, streaming, setMessages, setConversationId, setStreaming],
  );

  const reset = () => {
    abortRef.current?.abort();
    resetDocsChat();
    setError(null);
    setStreaming(false);
  };

  const empty = messages.length === 0;

  return (
    <section className={styles.panel} aria-label="Ask the documentation">
      <header className={styles.header}>
        <span className={styles.star} aria-hidden="true">✦</span>
        <div className={styles.headerText}>
          <h2 className={styles.headerTitle}>Ask about IntelFeed</h2>
          <p className={styles.headerSub}>
            Answers come from the documentation on this site, with a link to the page used.
          </p>
        </div>
        {!empty && (
          <button className={styles.reset} onClick={reset} type="button">
            New question
          </button>
        )}
      </header>

      <div className={styles.thread} ref={scrollRef}>
        {empty && (
          <div className={styles.suggestions}>
            {SUGGESTED_QUESTIONS.map((q) => (
              <button key={q} className={styles.suggestion} onClick={() => send(q)} type="button">
                {q}
              </button>
            ))}
          </div>
        )}

        {messages.map((m, i) => (
          <div key={i} className={m.role === "user" ? styles.userTurn : styles.assistantTurn}>
            {m.traces && m.traces.length > 0 && (
              <div className={styles.traces}>
                {m.traces.map((t) => (
                  <ToolTraceChip key={t.id} trace={t} />
                ))}
              </div>
            )}
            {m.role === "assistant" ? (
              <div className={styles.markdown} data-untrusted-content="">
                <Markdown remarkPlugins={[remarkGfm]} components={markdownComponents}>
                  {m.content}
                </Markdown>
                {streaming && i === messages.length - 1 && !m.content && (
                  <span className={styles.thinking}>Reading the docs…</span>
                )}
              </div>
            ) : (
              m.content
            )}
          </div>
        ))}

        {error && <p className={styles.error}>{error}</p>}
      </div>

      <form
        className={styles.composer}
        onSubmit={(e) => {
          e.preventDefault();
          send(input);
        }}
      >
        <input
          className={styles.input}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="How do I…?"
          aria-label="Ask a question about IntelFeed"
          disabled={streaming}
        />
        <button className={styles.send} type="submit" disabled={streaming || !input.trim()}>
          {streaming ? "…" : "Ask"}
        </button>
      </form>
    </section>
  );
}
