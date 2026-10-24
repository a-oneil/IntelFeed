import { useState, useRef, useEffect, useCallback } from "react";
import { apiErrorInfo } from "@/api/errors";
import type { AskAgentMessage } from "@/hooks/useAI";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import styles from "./AskAgentPanel.module.css";

interface AskAgentPanelProps {
  entryId?: string;
  onClose: () => void;
  /**
   * Ask function for shared (unauthenticated) pages — hits the share-token
   * entry_qa endpoint. This panel only exists for that surface now; the
   * authenticated app routes all article Q&A through the global copilot.
   */
  askFn?: (
    question: string,
    history: AskAgentMessage[],
  ) => Promise<{ answer: string; remaining_today?: number | null }>;
  /**
   * Questions left on this link today, when the parent tracks it (a task run
   * on the same link spends the same budget). Omit to let the panel keep its
   * own count from the answers it gets.
   */
  remaining?: number | null;
  onRemaining?: (remaining: number) => void;
}

/**
 * Minimal article Q&A chat for shared entry pages. Non-streaming, no
 * persistence — the visitor has no account to persist to.
 */
export function AskAgentPanel({ onClose, askFn, remaining: remainingProp, onRemaining }: AskAgentPanelProps) {
  const [messages, setMessages] = useState<AskAgentMessage[]>([]);
  const [input, setInput] = useState("");
  const [pending, setPending] = useState(false);
  // Questions left on this link today, from the last answer. The link has a
  // daily budget of its own because it answers without a login. The parent's
  // count wins when it has one, since task runs on the page spend it too.
  const [localRemaining, setLocalRemaining] = useState<number | null>(null);
  const remaining = remainingProp ?? localRemaining;

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSubmit = useCallback(async () => {
    const question = input.trim();
    if (!question || pending || !askFn) return;

    const history = [...messages];
    setMessages((prev) => [...prev, { role: "user", content: question }, { role: "assistant", content: "" }]);
    setInput("");
    setPending(true);
    try {
      const result = await askFn(question, history);
      setMessages((prev) => {
        const next = [...prev];
        next[next.length - 1] = { role: "assistant", content: result.answer };
        return next;
      });
      if (typeof result.remaining_today === "number") {
        setLocalRemaining(result.remaining_today);
        onRemaining?.(result.remaining_today);
      }
    } catch (err) {
      const message = apiErrorInfo(err).message;
      setMessages((prev) => {
        const next = [...prev];
        next[next.length - 1] = { role: "assistant", content: `Error: ${message}` };
        return next;
      });
    } finally {
      setPending(false);
    }
  }, [input, pending, askFn, messages, onRemaining]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  return (
    <div className={styles.panel}>
      <div className={styles.header}>
        <span className={styles.headerTitle}>
          Ask Agent <span className={styles.headerNote}>instance AI</span>
        </span>
        <div className={styles.headerActions}>
          {remaining != null && (
            <span className={styles.remaining}>
              {remaining} {remaining === 1 ? "question" : "questions"} left on this link today
            </span>
          )}
          <button className={styles.closeBtn} onClick={onClose} title="Close">
            &times;
          </button>
        </div>
      </div>

      <div className={styles.messages}>
        {messages.length === 0 && (
          <div className={styles.emptyHint}>Ask a question about this article...</div>
        )}
        {messages.map((msg, i) => {
          const isLast = i === messages.length - 1;
          const isEmptyPending = isLast && pending && msg.role === "assistant" && !msg.content;
          return (
            <div
              key={i}
              className={`${styles.message} ${msg.role === "user" ? styles.messageUser : styles.messageAssistant}`}
            >
              <div className={styles.messageRole}>{msg.role === "user" ? "You" : "Agent"}</div>
              <div className={styles.messageContent} data-untrusted-content={msg.role === "assistant" ? "" : undefined}>
                {isEmptyPending ? (
                  <span className={styles.thinking}>Thinking...</span>
                ) : msg.role === "assistant" ? (
                  <Markdown remarkPlugins={[remarkGfm]}>{msg.content}</Markdown>
                ) : (
                  msg.content
                )}
              </div>
            </div>
          );
        })}
        <div ref={messagesEndRef} />
      </div>

      <div className={styles.inputArea}>
        <textarea
          ref={inputRef}
          className={styles.input}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Ask a question..."
          rows={1}
          disabled={pending}
        />
        <button
          className={styles.sendBtn}
          onClick={handleSubmit}
          disabled={!input.trim() || pending}
          title="Send"
        >
          &rarr;
        </button>
      </div>
      <div className={styles.footerNote}>
        Answers on this page come from the IntelFeed instance's AI, not the person who shared it.
      </div>
    </div>
  );
}
