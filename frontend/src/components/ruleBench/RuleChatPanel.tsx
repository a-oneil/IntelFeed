import { useEffect, useRef } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { ChatMessage } from "@/hooks/useDetectionRules";
import styles from "./RuleChatPanel.module.css";

/** Code fences are the only part of an answer that can go back into the rule. */
function extractCodeBlocks(content: string): string[] {
  const blocks: string[] = [];
  const regex = /```(?:\w+)?\n([\s\S]*?)```/g;
  let match;
  while ((match = regex.exec(content)) !== null) blocks.push(match[1].trim());
  return blocks;
}

interface RuleChatPanelProps {
  messages: ChatMessage[];
  input: string;
  streaming: boolean;
  onInput: (value: string) => void;
  onSend: () => void;
  onStop: () => void;
  onClear: () => void;
  onClose: () => void;
  /** In the shelf the toolbar owns Close — hide the panel's own header chrome. */
  embedded?: boolean;
  onApplyCode: (code: string) => void;
}

export function RuleChatPanel({
  messages,
  input,
  streaming,
  onInput,
  onSend,
  onStop,
  onClear,
  onClose,
  embedded = false,
  onApplyCode,
}: RuleChatPanelProps) {
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  return (
    <div className={styles.chatPanel}>
      {(!embedded || messages.length > 0) && (
        <div className={styles.chatHeader}>
          {!embedded && <span className={styles.chatTitle}>AI Rule Assistant</span>}
          <div className={styles.chatHeaderActions}>
            {messages.length > 0 && (
              <button type="button" className={styles.chatClearBtn} onClick={onClear}>Clear</button>
            )}
            {!embedded && (
              <button type="button" className={styles.chatClose} onClick={onClose} aria-label="Close assistant">&times;</button>
            )}
          </div>
        </div>
      )}
      <div className={styles.chatMessages}>
        {messages.length === 0 && (
          <div className={styles.chatEmpty}>
            Ask the AI assistant to help develop, improve, or explain your detection rule.
          </div>
        )}
        {messages.map((msg, idx) => {
          const blocks = msg.role === "assistant" && msg.content ? extractCodeBlocks(msg.content) : [];
          return (
            <div key={idx} className={msg.role === "user" ? styles.chatMsgUser : styles.chatMsgAssistant}>
              <div className={styles.chatMsgRole}>{msg.role === "user" ? "You" : "AI"}</div>
              <div className={styles.chatMsgContent} data-untrusted-content={msg.role === "assistant" ? "" : undefined}>
                {msg.role === "assistant" && msg.content ? (
                  <Markdown remarkPlugins={[remarkGfm]}>{msg.content}</Markdown>
                ) : (
                  msg.content || (streaming && idx === messages.length - 1 ? "..." : "")
                )}
              </div>
              {blocks.length > 0 && (
                <div className={styles.chatApplyBar}>
                  {blocks.map((code, cIdx) => (
                    <button
                      key={cIdx}
                      type="button"
                      className={styles.chatApplyBtn}
                      onClick={() => onApplyCode(code)}
                    >
                      Apply {blocks.length > 1 ? `block ${cIdx + 1}` : "to editor"}
                    </button>
                  ))}
                </div>
              )}
            </div>
          );
        })}
        <div ref={endRef} />
      </div>
      <div className={styles.chatInputBar}>
        <input
          className={styles.chatInput}
          value={input}
          onChange={(e) => onInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); onSend(); } }}
          placeholder="Ask about this rule..."
          disabled={streaming}
        />
        {streaming ? (
          <button type="button" className={styles.chatStopBtn} onClick={onStop}>Stop</button>
        ) : (
          <button type="button" className={styles.chatSendBtn} onClick={onSend} disabled={!input.trim()}>Send</button>
        )}
      </div>
    </div>
  );
}
