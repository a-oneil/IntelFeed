import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getTokenAtCursor } from "@/utils/queryParser";
import { NO_SUGGESTIONS, type OmniSuggestion, type OmniToken, type SuggestionSource } from "./types";

/** Debounced mirror of `value`. `ms <= 0` disables the timer entirely. */
export function useDebouncedValue<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    if (ms <= 0) return;
    const t = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return ms <= 0 ? value : debounced;
}

// ── "/" ownership ───────────────────────────────────────
//
// Two global "/" listeners already exist in this app and only avoid colliding
// because AppHeader suppresses HeaderSearch on workbench routes. That invariant
// is invisible and easy to break, so `/` is never claimed automatically — a
// surface has to ask for it — and a second claimant is loud in development.
const slashOwners = new Set<string>();

function claimSlashKey(label: string) {
  slashOwners.add(label);
  if (import.meta.env.DEV && slashOwners.size > 1) {
    // eslint-disable-next-line no-console
    console.warn(
      `[OmniSearchInput] Two mounted inputs both claim the "/" shortcut: ` +
        `${[...slashOwners].join(", ")}. Both will preventDefault and fight over focus; ` +
        `exactly one instance per route may set ownsSlashKey.`,
    );
  }
  return () => slashOwners.delete(label);
}

export interface UseOmniSearchInputOptions<S extends OmniSuggestion> {
  /** Controlled query text. The surface owns where it lives. */
  value: string;
  /** Called with the next query text — on typing and on accepting a suggestion. */
  onChange: (next: string) => void;
  /** The input element. Supply one if the surface needs to focus/blur it itself. */
  inputRef: React.RefObject<HTMLInputElement | null>;
  /** Element that click-outside is measured against. */
  containerRef: React.RefObject<HTMLElement | null>;
  /** See `SuggestionSource` — a hook, stable identity required. */
  suggestionSource?: SuggestionSource<S>;
  /** ArrowDown past the end returns to 0 (and ArrowUp past the top to the end). */
  wrap?: boolean;
  /** ArrowUp past the top lands on -1 ("nothing selected") rather than clamping at 0. */
  allowDeselect?: boolean;
  /** Debounce for `debouncedValue`. 0 disables it. Default 300. */
  debounceMs?: number;
  /** Claim the global "/" focus shortcut. Never automatic — see the note above. */
  ownsSlashKey?: boolean;
  /** Name used in the double-claim warning. */
  slashKeyOwnerLabel?: string;
  /** Escape ladder rung 2 — fired only when the suggestion dropdown was not open. */
  onEscape?: () => void;
  /** Fires after a suggestion has been spliced into the query. */
  onSuggestionApplied?: (suggestion: S) => void;
  /**
   * Keys layered on top of the base map. Runs after the Escape ladder and after
   * the suggestion keys, and only if neither handled the event. Return true to
   * mark the event handled.
   */
  extraKeys?: (e: React.KeyboardEvent) => boolean | void;
  /** Notified whenever the dropdown opens or closes. */
  onOpenChange?: (open: boolean) => void;
}

export interface OmniSearchInputState<S extends OmniSuggestion> {
  /** Token under the caret, or null when the dropdown is closed / the caret is on whitespace. */
  token: OmniToken | null;
  /** Whatever `suggestionSource` returned this render. */
  suggestions: readonly S[];
  open: boolean;
  setOpen: (open: boolean) => void;
  /** -1 means "nothing selected" and is a real state when `allowDeselect`. */
  activeIndex: number;
  setActiveIndex: React.Dispatch<React.SetStateAction<number>>;
  /** Move the selection by `delta`, honouring `wrap` / `allowDeselect`. */
  moveActive: (delta: number) => void;
  /** Splice a suggestion over the caret token and restore the caret after it. */
  applySuggestion: (suggestion: S) => void;
  /** Debounced `value`, for surfaces that fetch results as you type. */
  debouncedValue: string;
  /** Attach to each rendered item so the active one can be scrolled into view. */
  registerItem: (index: number) => (el: HTMLElement | null) => void;
  /** Spread onto the `<input>`. */
  inputProps: {
    ref: React.RefObject<HTMLInputElement | null>;
    value: string;
    onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
    onFocus: () => void;
    onKeyDown: (e: React.KeyboardEvent) => void;
  };
}

/**
 * The shared search *input* layer: caret tokenisation, suggestion splice, one
 * selection state machine, debounce, click-outside, the Escape ladder and the
 * optional "/" shortcut.
 *
 * It deliberately owns nothing about *results*: fetching and rendering stay with
 * each surface, which is why the dropdown a surface draws can be a flat completion
 * list, a grouped entity panel, or a modal command list without this hook caring.
 */
export function useOmniSearchInput<S extends OmniSuggestion>(
  options: UseOmniSearchInputOptions<S>,
): OmniSearchInputState<S> {
  const {
    value,
    onChange,
    inputRef,
    containerRef,
    suggestionSource,
    wrap = false,
    allowDeselect = true,
    debounceMs = 300,
    ownsSlashKey = false,
    slashKeyOwnerLabel = "unnamed",
    onEscape,
    onSuggestionApplied,
    extraKeys,
    onOpenChange,
  } = options;

  const [open, setOpenState] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const itemRefs = useRef<(HTMLElement | null)[]>([]);

  const setOpen = setOpenState;

  // Notify the surface out-of-band rather than from inside the state updater, so a
  // StrictMode double-invoke can't fire the callback twice.
  const onOpenChangeRef = useRef(onOpenChange);
  onOpenChangeRef.current = onOpenChange;
  const prevOpenRef = useRef(open);
  useEffect(() => {
    if (prevOpenRef.current === open) return;
    prevOpenRef.current = open;
    onOpenChangeRef.current?.(open);
  }, [open]);

  // The token under the caret is what gets completed and replaced. `getTokenAtCursor`
  // walks outward from the caret rather than regexing the text before it, so a caret
  // parked in the middle of a token still completes that whole token.
  const token = useMemo<OmniToken | null>(() => {
    const input = inputRef.current;
    if (!input || !open) return null;
    const cursorPos = input.selectionStart ?? value.length;
    const cursor = getTokenAtCursor(value, cursorPos);
    const text = value.slice(cursor.startPos, cursor.endPos);
    if (!text) return null;
    return {
      text,
      kind: cursor.type,
      field: cursor.field,
      partialValue: cursor.partialValue,
      startPos: cursor.startPos,
      endPos: cursor.endPos,
    };
  }, [value, open, inputRef]);

  // Called unconditionally — `suggestionSource` is a hook by contract.
  const sourced = suggestionSource?.(token, open && !!token);
  // Falls back to a module-level constant, not a fresh `[]`: the reset effect below
  // keys off this identity, and a new array each render would loop.
  const suggestions = (sourced ?? NO_SUGGESTIONS) as readonly S[];

  // Reset selection when suggestions change
  useEffect(() => {
    setActiveIndex(-1);
  }, [suggestions]);

  // Keep the active item visible in whatever scroll container it lives in.
  useEffect(() => {
    if (activeIndex < 0) return;
    // Optional-call: jsdom does not implement scrollIntoView.
    itemRefs.current[activeIndex]?.scrollIntoView?.({ block: "nearest" });
  }, [activeIndex]);

  const moveActive = useCallback(
    (delta: number) => {
      const len = suggestions.length;
      if (len === 0) return;
      setActiveIndex((prev) => {
        const next = prev + delta;
        if (wrap) {
          // -1 is not reachable while wrapping; the list is a ring.
          const base = prev < 0 && delta < 0 ? len : prev;
          return (((base + delta) % len) + len) % len;
        }
        const floor = allowDeselect ? -1 : 0;
        return Math.max(floor, Math.min(next, len - 1));
      });
    },
    [suggestions.length, wrap, allowDeselect],
  );

  const applySuggestion = useCallback(
    (suggestion: S) => {
      if (!token) return;
      const before = value.slice(0, token.startPos);
      const after = value.slice(token.endPos);
      // A completed value ends the token; a field name still needs its value typed,
      // so don't append the space that would push the caret past the colon.
      // Note: the surrounding text is spliced verbatim — interior whitespace the
      // user typed is preserved, deliberately.
      const trailing = suggestion.type === "value" ? " " : "";
      onChange(`${before}${suggestion.insert}${trailing}${after}`);
      setActiveIndex(-1);
      if (suggestion.type === "value") setOpen(false);
      setTimeout(() => {
        inputRef.current?.focus();
        const caret = before.length + suggestion.insert.length + trailing.length;
        inputRef.current?.setSelectionRange(caret, caret);
      }, 0);
      onSuggestionApplied?.(suggestion);
    },
    [token, value, onChange, inputRef, setOpen, onSuggestionApplied],
  );

  // Global "/" shortcut to focus search. Opt-in only — see `claimSlashKey`.
  useEffect(() => {
    if (!ownsSlashKey) return;
    const release = claimSlashKey(slashKeyOwnerLabel);
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      const isInput =
        target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable;
      if (e.key === "/" && !isInput) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handler);
    return () => {
      window.removeEventListener("keydown", handler);
      release();
    };
  }, [ownsSlashKey, slashKeyOwnerLabel, inputRef]);

  // Close suggestions when clicking outside
  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      const node = containerRef.current;
      if (node && !node.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open, containerRef, setOpen]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      // Escape ladder, rung 1: an open dropdown swallows Escape and stops it there,
      // so a layout-level global Escape handler doesn't also fire.
      if (e.key === "Escape") {
        if (open && suggestions.length > 0) {
          setOpen(false);
          e.stopPropagation();
          return;
        }
        onEscape?.();
        return;
      }

      if (suggestions.length > 0 && open) {
        if (e.key === "ArrowDown") {
          e.preventDefault();
          moveActive(1);
          return;
        }
        if (e.key === "ArrowUp") {
          e.preventDefault();
          moveActive(-1);
          return;
        }
        if (e.key === "Enter" && activeIndex >= 0) {
          e.preventDefault();
          applySuggestion(suggestions[activeIndex]);
          return;
        }
        if (e.key === "Tab") {
          e.preventDefault();
          applySuggestion(suggestions[activeIndex >= 0 ? activeIndex : 0]);
          return;
        }
      }

      extraKeys?.(e);
    },
    [open, suggestions, activeIndex, moveActive, applySuggestion, onEscape, extraKeys, setOpen],
  );

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      onChange(e.target.value);
      setOpen(true);
    },
    [onChange, setOpen],
  );

  const handleFocus = useCallback(() => setOpen(true), [setOpen]);

  const registerItem = useCallback(
    (index: number) => (el: HTMLElement | null) => {
      itemRefs.current[index] = el;
    },
    [],
  );

  const debouncedValue = useDebouncedValue(value, debounceMs);

  return {
    token,
    suggestions,
    open,
    setOpen,
    activeIndex,
    setActiveIndex,
    moveActive,
    applySuggestion,
    debouncedValue,
    registerItem,
    inputProps: {
      ref: inputRef,
      value,
      onChange: handleChange,
      onFocus: handleFocus,
      onKeyDown: handleKeyDown,
    },
  };
}
