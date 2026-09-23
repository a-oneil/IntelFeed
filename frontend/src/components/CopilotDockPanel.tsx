import { useState, useRef, useEffect, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import Markdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  streamCopilotChat,
  useConversations,
  useDeleteConversation,
  type AskAgentMessage,
  type CopilotConfirmRequest,
  type CopilotConfirmResponse,
} from "@/hooks/useAI";
import { useCopilotContext } from "@/hooks/useCopilotContext";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { useCopilotAuthStatus, useCopilotConfig } from "@/hooks/useCopilotAuth";
import { useUIStore } from "@/stores/uiStore";
import { useAuthStore } from "@/stores/authStore";
import CopilotReauthModal from "@/components/CopilotReauthModal";
import api from "@/api/client";
import { ResizeHandle } from "@/components/ResizeHandle";
import { ToolTraceChip, type ToolTrace } from "@/components/ToolTraceChip";
import { ConfirmCard, type ConfirmState } from "@/components/ConfirmCard";
import { ContextPill } from "@/components/ContextPill";
import { SlashCommandMenu } from "@/components/SlashCommandMenu";
import {
  filterCopilotCommands,
  type CopilotCommand,
} from "@/components/copilotCommands";
import type { CopilotContext } from "@/hooks/useAI";
import styles from "./CopilotDockPanel.module.css";
import { RailToggle } from "@/components/primitives";

/** An assistant turn can interleave tool-trace chips with streamed text. */
interface CopilotMessage extends AskAgentMessage {
  traces?: ToolTrace[];
  /** A proposed write attached to this turn, awaiting user confirmation. */
  confirm?: CopilotConfirmRequest;
}

const SUGGESTED_PROMPTS = [
  "What's trending in the last 24 hours?",
  "Summarize recent ransomware activity",
  "Which CVEs are being actively exploited?",
  "Draft a Sigma rule for this article",
];

export function CopilotDockPanel() {
  const open = useUIStore((s) => s.copilotOpen);
  const closeCopilot = useUIStore((s) => s.closeCopilot);
  const width = useUIStore((s) => s.copilotWidth);
  const setWidth = useUIStore((s) => s.setCopilotWidth);
  const collapsed = useUIStore((s) => s.copilotCollapsed);
  const setCollapsed = useUIStore((s) => s.setCopilotCollapsed);
  const conversationId = useUIStore((s) => s.copilotActiveConversationId);
  const setConversationId = useUIStore((s) => s.setCopilotActiveConversationId);
  const copilotSeed = useUIStore((s) => s.copilotSeed);
  const copilotSeedNonce = useUIStore((s) => s.copilotSeedNonce);
  const clearCopilotSeed = useUIStore((s) => s.clearCopilotSeed);

  const ambientContext = useCopilotContext();
  const isMobile = useIsMobile();
  const navigate = useNavigate();

  // The copilot prompt asks the model to cite IntelFeed objects as relative
  // links (/?entry=…, /workbench/cve/…). Route those through the SPA router so
  // pivoting doesn't reload the app; everything else opens in a new tab.
  const markdownComponents = useMemo<Components>(
    () => ({
      a: ({ href, children, ...props }) => {
        const isInternal = !!href && href.startsWith("/") && !href.startsWith("//");
        if (isInternal) {
          return (
            <a
              {...props}
              href={href}
              onClick={(e) => {
                e.preventDefault();
                navigate(href);
                if (isMobile) closeCopilot();
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
    }),
    [navigate, isMobile, closeCopilot],
  );

  const [contextDismissed, setContextDismissed] = useState(false);
  // A context pinned by a seed ("Ask Copilot" buttons). When set, it overrides
  // the route-derived ambient context for the whole seeded thread until the
  // user starts a new thread or dismisses the context pill.
  const [lockedContext, setLockedContext] = useState<CopilotContext | null>(
    null,
  );
  // Human-readable name for the pinned entity/entry/campaign (from the seed), so
  // the ContextPill shows "Threat Actor: Qilin" instead of a raw UUID.
  const [lockedLabel, setLockedLabel] = useState<string | undefined>(undefined);
  // Effective context: the locked (seeded) context wins; otherwise the ambient
  // route context. Null once the user dismisses it for this thread.
  const context = contextDismissed ? null : (lockedContext ?? ambientContext);

  // Copilot Claude sign-in health — surfaces an inline re-auth banner when the
  // OAuth session has expired (admin-only, since only admins can re-auth).
  // Only relevant when copilot runs on the Claude Code CLI: other providers
  // (e.g. Ollama) have no OAuth session, so the status check + banner are
  // skipped entirely for them.
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  const { data: copilotConfig } = useCopilotConfig();
  const usesClaudeCode = copilotConfig?.provider_type === "claude_code";
  const { data: authStatus, refetch: refetchAuthStatus } = useCopilotAuthStatus({
    enabled: isAdmin && usesClaudeCode,
  });
  const needsReauth = isAdmin && usesClaudeCode && authStatus?.valid === false;
  const [reauthOpen, setReauthOpen] = useState(false);

  const [messages, setMessages] = useState<CopilotMessage[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  // Lifecycle of each proposed write, keyed by action_id.
  const [confirmStates, setConfirmStates] = useState<
    Record<string, ConfirmState>
  >({});
  // Slash-command menu: open only while the input is a leading-"/" query.
  const [slashOpen, setSlashOpen] = useState(false);
  const [slashIndex, setSlashIndex] = useState(0);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  // Mirrors `streaming` so the re-entrancy guard reads live state even when
  // called from an effect whose closure predates the latest setStreaming.
  const streamingRef = useRef(false);
  streamingRef.current = streaming;

  const deleteConversation = useDeleteConversation();
  const queryClient = useQueryClient();

  const { data: conversationsPage } = useConversations(
    { scope_type: "global" },
    open,
  );
  const conversations = conversationsPage?.items ?? [];

  useEffect(() => {
    if (open && !collapsed) {
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open, collapsed]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    // Cancel any in-flight stream on unmount.
    return () => abortRef.current?.abort();
  }, []);

  const submitQuestion = useCallback(
    async (raw: string, contextOverride?: CopilotContext | null) => {
      const question = raw.trim();
      if (!question || streamingRef.current) return;
      streamingRef.current = true;
      // A seeded auto-submit passes its context explicitly to avoid racing the
      // still-committing `lockedContext` state; otherwise use effective context.
      const effectiveContext =
        contextOverride !== undefined ? contextOverride : context;

      const userMsg: CopilotMessage = { role: "user", content: question };
      setMessages((prev) => [
        ...prev,
        userMsg,
        { role: "assistant", content: "", traces: [] },
      ]);
      setInput("");
      setStreaming(true);

      const controller = new AbortController();
      abortRef.current = controller;

      let assistantText = "";
      let errored = false;

      // Mutate the trailing assistant message in place for streamed updates.
      const updateAssistant = (mutate: (m: CopilotMessage) => CopilotMessage) => {
        setMessages((prev) => {
          const next = [...prev];
          const last = next[next.length - 1];
          if (last && last.role === "assistant") {
            next[next.length - 1] = mutate(last);
          }
          return next;
        });
      };

      await streamCopilotChat(
        {
          question,
          conversationId,
          context: effectiveContext,
          onChunk: (text) => {
            assistantText += text;
            updateAssistant((m) => ({ ...m, content: assistantText }));
          },
          onToolCall: (call) => {
            updateAssistant((m) => ({
              ...m,
              traces: [
                ...(m.traces ?? []),
                { ...call, status: "pending" as const },
              ],
            }));
          },
          onToolResult: (result) => {
            updateAssistant((m) => ({
              ...m,
              traces: (m.traces ?? []).map((t) =>
                t.id === result.id
                  ? { ...t, status: result.status, summary: result.summary }
                  : t,
              ),
            }));
          },
          onConfirmRequest: (req) => {
            // Attach the proposed write to the current assistant turn and seed
            // its lifecycle so a ConfirmCard renders after the message.
            updateAssistant((m) => ({ ...m, confirm: req }));
            setConfirmStates((prev) => ({
              ...prev,
              [req.action_id]: { status: "pending" },
            }));
          },
          onError: (message) => {
            errored = true;
            updateAssistant((m) => ({
              ...m,
              content: assistantText
                ? `${assistantText}\n\n_Error: ${message}_`
                : `Error: ${message}`,
            }));
          },
          onDone: (newConversationId) => {
            // Adopt the backend-authoritative conversation id.
            if (newConversationId) setConversationId(newConversationId);
          },
        },
        controller.signal,
      );

      setStreaming(false);
      abortRef.current = null;

      // Backend is authoritative for persistence: it appends both turns and
      // owns the conversation id (adopted above via `onDone`). Just refresh the
      // History list so the new/updated thread shows up.
      if (!errored && assistantText.trim()) {
        queryClient.invalidateQueries({ queryKey: ["ai-conversations"] });
      }

      // A failed or empty turn is often an expired Claude sign-in — re-check the
      // auth status so the re-auth banner appears right when it's relevant.
      // Only meaningful on the Claude Code CLI provider.
      if (isAdmin && usesClaudeCode && (errored || !assistantText.trim())) {
        refetchAuthStatus();
      }
    },
    [conversationId, context, queryClient, setConversationId, isAdmin, usesClaudeCode, refetchAuthStatus],
  );

  // Consume a seed from external "Ask Copilot" buttons. Keyed on the nonce so a
  // repeat seed with the same shape still fires; guarded against the initial 0.
  const lastSeedNonce = useRef(0);
  useEffect(() => {
    if (copilotSeedNonce === 0 || copilotSeedNonce === lastSeedNonce.current) {
      return;
    }
    lastSeedNonce.current = copilotSeedNonce;
    const seed = copilotSeed;
    if (!seed) return;

    // Abort any in-flight stream so the seeded turn isn't dropped by the
    // re-entrancy guard in submitQuestion, and reset the local thread view.
    abortRef.current?.abort();
    abortRef.current = null;
    streamingRef.current = false;
    setStreaming(false);
    // The store already cleared activeConversationId for a fresh thread.
    setMessages([]);
    setConfirmStates({});
    setShowHistory(false);
    setSlashOpen(false);

    // Pin the seeded context for the whole thread (overrides route context).
    // Split the display `label` out of the context object: it's presentation
    // only and must not travel in the CopilotContext sent to the backend.
    let pinned: CopilotContext | null = null;
    if (seed.lockContext && seed.context) {
      const { label, ...rest } = seed.context;
      pinned = rest;
      setLockedContext(pinned);
      setLockedLabel(label);
      setContextDismissed(false);
    } else {
      setLockedContext(null);
      setLockedLabel(undefined);
    }

    // Auto-submit the starter prompt as the first message, passing the pinned
    // context explicitly so it doesn't race the just-set `lockedContext` state.
    // Falls back to the current effective context when nothing was pinned.
    // Context-only seeds (the generic "Ask Copilot" buttons) skip this — the
    // context is pinned and the input focused so the analyst asks their own
    // question.
    if (seed.prompt) {
      submitQuestion(seed.prompt, pinned ?? context);
    } else {
      requestAnimationFrame(() => inputRef.current?.focus());
    }

    clearCopilotSeed();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [copilotSeedNonce]);

  const resolveConfirm = useCallback(
    async (req: CopilotConfirmRequest, approved: boolean) => {
      const current = confirmStates[req.action_id];
      // Only act on a still-pending card (avoid double-submits).
      if (current && current.status !== "pending") return;

      setConfirmStates((prev) => ({
        ...prev,
        [req.action_id]: { status: "in_flight", approved },
      }));

      try {
        const { data } = await api.post<CopilotConfirmResponse>(
          "/ai/copilot/confirm",
          { action_id: req.action_id, approved },
        );

        if (data.status === "executed") {
          setConfirmStates((prev) => ({
            ...prev,
            [req.action_id]: {
              status: "executed",
              summary: data.result?.summary ?? "Done.",
              link: data.result?.link,
            },
          }));
          // Surface the outcome as an assistant message in the thread.
          if (data.result?.summary) {
            const link = data.result.link;
            const content = link
              ? `[${data.result.summary}](${link})`
              : data.result.summary;
            setMessages((prev) => [
              ...prev,
              { role: "assistant", content },
            ]);
          }
          // The write may have created/changed a campaign; refresh views + history.
          queryClient.invalidateQueries({ queryKey: ["campaigns"] });
          queryClient.invalidateQueries({ queryKey: ["ai-conversations"] });
        } else if (data.status === "cancelled") {
          setConfirmStates((prev) => ({
            ...prev,
            [req.action_id]: { status: "cancelled" },
          }));
        } else {
          setConfirmStates((prev) => ({
            ...prev,
            [req.action_id]: {
              status: "error",
              message: data.message ?? "Action failed.",
            },
          }));
        }
      } catch (err) {
        // If the user was cancelling, treat a failed POST as cancelled locally;
        // otherwise surface the error on the card.
        if (approved) {
          const message =
            err instanceof Error ? err.message : "Failed to apply action";
          setConfirmStates((prev) => ({
            ...prev,
            [req.action_id]: { status: "error", message },
          }));
        } else {
          setConfirmStates((prev) => ({
            ...prev,
            [req.action_id]: { status: "cancelled" },
          }));
        }
      }
    },
    [confirmStates, queryClient],
  );

  // A card is awaiting the user while its action is pending or in flight.
  const hasUnresolvedConfirm = messages.some((m) => {
    if (!m.confirm) return false;
    const s = confirmStates[m.confirm.action_id];
    return !s || s.status === "pending" || s.status === "in_flight";
  });

  // Slash commands are gated by the same conditions as the input: never while
  // streaming or with a pending confirm. The menu triggers only on a leading
  // "/" in an otherwise-empty (single-token) input.
  const inputGated = streaming || hasUnresolvedConfirm;
  const isSlashQuery = input.startsWith("/") && !input.includes("\n");
  const slashMatches =
    slashOpen && !inputGated && isSlashQuery
      ? filterCopilotCommands(input.slice(1), copilotConfig?.enabled_tools)
      : [];
  const slashMenuVisible = slashMatches.length > 0;

  const selectCommand = useCallback((command: CopilotCommand) => {
    // Fill the input with the template so the user can tweak before sending —
    // never auto-send.
    setInput(command.prompt);
    setSlashOpen(false);
    setSlashIndex(0);
    inputRef.current?.focus();
  }, []);

  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const value = e.target.value;
    setInput(value);
    // Open on a leading "/" (single line); close as soon as it stops being one.
    if (value.startsWith("/") && !value.includes("\n")) {
      setSlashOpen(true);
      setSlashIndex(0);
    } else {
      setSlashOpen(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    // While the slash menu is showing, arrows/Enter/Esc drive it instead of the
    // textarea/submit.
    if (slashMenuVisible) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSlashIndex((i) => (i + 1) % slashMatches.length);
        return;
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setSlashIndex((i) => (i - 1 + slashMatches.length) % slashMatches.length);
        return;
      }
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        const chosen = slashMatches[slashIndex] ?? slashMatches[0];
        if (chosen) selectCommand(chosen);
        return;
      }
      if (e.key === "Escape") {
        e.preventDefault();
        setSlashOpen(false);
        return;
      }
    }
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      submitQuestion(input);
    }
  };

  const handleShare = useCallback(async () => {
    const id = useUIStore.getState().copilotActiveConversationId;
    if (!id) {
      toast.error("Ask something first — sharing needs a saved conversation");
      return;
    }
    try {
      const { data } = await api.post<{ share_token: string; path: string }>(
        `/ai/conversations/${id}/share`,
      );
      await navigator.clipboard.writeText(`${window.location.origin}${data.path}`);
      toast.success("Public read-only link copied to clipboard");
    } catch {
      toast.error("Failed to create share link");
    }
  }, []);

  const startNewThread = useCallback(() => {
    abortRef.current?.abort();
    setConversationId(null);
    setMessages([]);
    setConfirmStates({});
    setShowHistory(false);
    setInput("");
    setSlashOpen(false);
    setContextDismissed(false);
    setLockedContext(null);
    setLockedLabel(undefined);
    inputRef.current?.focus();
  }, [setConversationId]);

  const resumeConversation = useCallback(
    async (id: string) => {
      abortRef.current?.abort();
      setShowHistory(false);
      try {
        const { data } = await api.get<{ messages: AskAgentMessage[] }>(
          `/ai/conversations/${id}`,
        );
        setMessages(
          data.messages.map((m) => ({ role: m.role, content: m.content })),
        );
        setConfirmStates({});
        setConversationId(id);
        setLockedContext(null);
        setLockedLabel(undefined);
      } catch {
        toast.error("Failed to load conversation");
      }
    },
    [setConversationId],
  );

  const handleDelete = useCallback(
    async (id: string, e: React.MouseEvent) => {
      e.stopPropagation();
      try {
        await deleteConversation.mutateAsync(id);
        if (id === conversationId) {
          setConversationId(null);
          setMessages([]);
        }
      } catch {
        toast.error("Failed to delete conversation");
      }
    },
    [deleteConversation, conversationId, setConversationId],
  );

  if (!open) return null;

  return (
    <div className={styles.dockGroup} role="complementary" aria-label="IntelFeed copilot">
      {/* Persistent toggle rail on the panel's left edge — same expand/collapse
          mechanism as the sidebars: slim strip, chevron flips with state,
          content shifts because the whole group is in normal flex flow. The ×
          in the header below is the only thing that fully closes the panel. */}
      {!isMobile && (
        <RailToggle
          side="right"
          collapsed={collapsed}
          onToggle={() => setCollapsed(!collapsed)}
          label="copilot"
          verbs={["Expand", "Collapse"]}
        />
      )}

      {(!collapsed || isMobile) && (
        <div className={styles.dock} style={isMobile ? undefined : { width }}>
          <ResizeHandle
            className={styles.resize}
            // Panel is docked right: dragging left (negative delta) widens it.
            onResize={(delta) => setWidth(width - delta)}
          />
          <div className={styles.header}>
            <span className={styles.headerTitle}>✦ Copilot</span>
            <div className={styles.headerActions}>
              <button
                className={styles.headerBtn}
                onClick={startNewThread}
                title="Start a new thread"
              >
                + New
              </button>
              <button
                className={`${styles.headerBtn} ${showHistory ? styles.headerBtnActive : ""}`}
                onClick={() => setShowHistory((v) => !v)}
                title="Past conversations"
              >
                History ({conversations.length})
              </button>
              <button
                className={styles.headerBtn}
                onClick={handleShare}
                disabled={!conversationId}
                title={
                  conversationId
                    ? "Copy a public read-only link to this conversation"
                    : "Ask something first to enable sharing"
                }
              >
                Share
              </button>
              <button
                className={styles.iconBtn}
                onClick={closeCopilot}
                title="Close"
                aria-label="Close copilot"
              >
                &times;
              </button>
            </div>
          </div>

          {needsReauth && (
            <div className={styles.reauthBanner}>
              <span className={styles.reauthText}>
                ⚠ Copilot sign-in expired — responses will fail until you re-authenticate.
              </span>
              <button className={styles.reauthBtn} onClick={() => setReauthOpen(true)}>
                Re-authenticate
              </button>
            </div>
          )}

          <CopilotReauthModal
            open={reauthOpen}
            onClose={() => setReauthOpen(false)}
            onSuccess={() => refetchAuthStatus()}
          />

          {showHistory && (
            <div className={styles.historyDropdown}>
              {conversations.length === 0 ? (
                <div className={styles.historyEmpty}>No past conversations.</div>
              ) : (
                conversations.map((c) => (
                  <div
                    key={c.id}
                    className={`${styles.historyRow} ${c.id === conversationId ? styles.historyRowActive : ""}`}
                    onClick={() => resumeConversation(c.id)}
                  >
                    <span className={styles.historyRowTitle}>
                      {c.title || "Untitled"}
                    </span>
                    <span className={styles.historyRowMeta}>
                      {c.message_count} msgs
                    </span>
                    <button
                      className={styles.historyDeleteBtn}
                      onClick={(e) => handleDelete(c.id, e)}
                      title="Delete conversation"
                    >
                      &times;
                    </button>
                  </div>
                ))
              )}
            </div>
          )}

          {context && (
            <ContextPill
              context={context}
              // The seed label only describes the locked context; when the
              // effective context is the route-derived ambient one, omit it so
              // the pill falls back to the id/type.
              labels={
                lockedLabel && context === lockedContext
                  ? {
                      entity: context.entity_id ? lockedLabel : undefined,
                      entry: context.entry_id ? lockedLabel : undefined,
                      campaign: context.campaign_id ? lockedLabel : undefined,
                    }
                  : undefined
              }
              onDismiss={() => setContextDismissed(true)}
            />
          )}

          <div className={styles.messages}>
            {messages.length === 0 && (
              <div className={styles.empty}>
                <div className={styles.emptyHint}>
                  Ask about threats, entities, detections, or anything in your feed.
                </div>
                <div className={styles.suggestions}>
                  {SUGGESTED_PROMPTS.map((p) => (
                    <button
                      key={p}
                      className={styles.suggestion}
                      onClick={() => submitQuestion(p)}
                    >
                      {p}
                    </button>
                  ))}
                </div>
              </div>
            )}
            {messages.map((msg, i) => {
              const isLast = i === messages.length - 1;
              const isEmptyStreaming =
                isLast &&
                streaming &&
                msg.role === "assistant" &&
                !msg.content &&
                (msg.traces?.length ?? 0) === 0;
              return (
                <div
                  key={i}
                  className={`${styles.message} ${msg.role === "user" ? styles.messageUser : styles.messageAssistant}`}
                >
                  <div className={styles.messageRole}>
                    {msg.role === "user" ? "You" : "IntelFeed"}
                  </div>
                  {msg.traces && msg.traces.length > 0 && (
                    <div className={styles.traces}>
                      {msg.traces.map((t) => (
                        <ToolTraceChip key={t.id} trace={t} />
                      ))}
                    </div>
                  )}
                  <div className={styles.messageContent}>
                    {isEmptyStreaming ? (
                      <span className={styles.thinking}>Thinking...</span>
                    ) : msg.role === "assistant" ? (
                      <Markdown remarkPlugins={[remarkGfm]} components={markdownComponents}>{msg.content}</Markdown>
                    ) : (
                      msg.content
                    )}
                  </div>
                  {msg.confirm && (
                    <ConfirmCard
                      request={msg.confirm}
                      state={
                        confirmStates[msg.confirm.action_id] ?? {
                          status: "pending",
                        }
                      }
                      onConfirm={() => resolveConfirm(msg.confirm!, true)}
                      onCancel={() => resolveConfirm(msg.confirm!, false)}
                    />
                  )}
                </div>
              );
            })}
            <div ref={messagesEndRef} />
          </div>

          <div className={styles.inputArea}>
            {slashMenuVisible && (
              <SlashCommandMenu
                commands={slashMatches}
                activeIndex={slashIndex}
                onSelect={selectCommand}
                onHover={setSlashIndex}
              />
            )}
            <textarea
              ref={inputRef}
              className={styles.input}
              value={input}
              onChange={handleInputChange}
              onKeyDown={handleKeyDown}
              placeholder={
                hasUnresolvedConfirm
                  ? "Resolve the pending action above to continue…"
                  : "Ask Copilot anything… (type / for commands)"
              }
              rows={1}
              disabled={streaming || hasUnresolvedConfirm}
            />
            <button
              className={styles.sendBtn}
              onClick={() => submitQuestion(input)}
              disabled={!input.trim() || streaming || hasUnresolvedConfirm}
              title="Send"
            >
              &rarr;
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
