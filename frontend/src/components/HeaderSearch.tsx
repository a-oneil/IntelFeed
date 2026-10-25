import { useCallback, useEffect, useMemo, useRef } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useUIStore, type SearchScope } from "@/stores/uiStore";
import { useSearchAutocomplete } from "@/hooks/useSearchAutocomplete";
import {
  OmniSearchInput,
  NO_SUGGESTIONS,
  type OmniSearchInputHandle,
  type SuggestionSource,
} from "@/components/search";
import { useIntelSuggestions } from "@/components/search/EntityResults";
import { queryFieldColor } from "@/components/search/queryFields";
import styles from "./HeaderSearch.module.css";

interface Props {
  inputRef: React.RefObject<HTMLInputElement | null>;
}

/**
 * The `in:` chip's three states, in Tab order.
 *
 * The chip no longer decides *where* results appear — /search is the only
 * surface that renders them — it decides *what that page contains*.
 */
const SCOPE_CYCLE: SearchScope[] = ["everything", "workbench", "feeds"];

// The chip decides what the results page renders, so the placeholder should
// name that — a field that says "entries & intelligence" while the chip reads
// `in: feeds` is describing a search the user is not running.
const SCOPE_PLACEHOLDER: Record<SearchScope, string> = {
  everything: "Search entries & intelligence... ( / )",
  workbench: "Search intelligence — actors, malware, CVEs, TTPs... ( / )",
  feeds: "Search entries — articles, titles, content... ( / )",
};

/** The shape both completion dictionaries are normalised to. */
interface HeaderSuggestion {
  insert: string;
  type?: string;
  text: string;
  description?: string;
  category?: string;
}

/**
 * Which dictionary the field completes against.
 *
 * The entries grammar is completed by `GET /search/autocomplete` (the backend
 * decides whether a token is a bare field prefix or a `field:value`, and answers
 * with field names or DB-backed values). The intelligence grammar is completed
 * from the local `INTEL_FILTER_FIELDS` dictionary, because `/intelligence/search`
 * has no autocomplete endpoint and knows fields the unified one does not
 * (`cve.severity`, `ttp.tactic`, ...).
 *
 * This is module state rather than a prop because `SuggestionSource` is a **hook**
 * with a fixed signature: the composite below has to call both underlying hooks
 * unconditionally and in a stable order, so it cannot receive the scope as an
 * argument, and swapping the whole source between renders would change the hook
 * sequence. Exactly one `HeaderSearch` is mounted at a time (MainLayout and
 * SidebarLayout are mutually exclusive), and the component assigns this during
 * its own render, immediately before the input renders.
 */
let suggestionDictionary: "server" | "intel" = "server";

const useScopedSuggestions: SuggestionSource<HeaderSuggestion> = (token, enabled) => {
  const mode = suggestionDictionary;
  const { data } = useSearchAutocomplete(token?.text ?? "", enabled && mode === "server");
  const intel = useIntelSuggestions(token, enabled && mode === "intel");
  return useMemo(() => {
    if (mode === "intel") {
      if (intel.length === 0) return NO_SUGGESTIONS;
      return intel.map((s) => ({
        insert: s.insert,
        type: s.type,
        text: s.insert,
        description: s.hint,
        category: "entity",
      }));
    }
    // Falls back to a module-level constant, not a fresh `[]`: the shared hook's
    // selection reset effect keys off this identity, and a new array each render
    // would loop — a frozen tab, not a failing test (R6).
    return data ?? NO_SUGGESTIONS;
  }, [mode, intel, data]);
};

/**
 * The one search field in the app — an input and nothing more.
 *
 * It used to render its own results dropdown, which answered the same query as
 * the in-page panel with different data and covered it. Now typing anything
 * routes to /search, which owns the answer, its facet rail, and its own reader.
 */
export function HeaderSearch({ inputRef }: Props) {
  const navigate = useNavigate();
  const location = useLocation();
  const headerSearchQuery = useUIStore((s) => s.headerSearchQuery);
  const setHeaderSearchQuery = useUIStore((s) => s.setHeaderSearchQuery);
  const scope = useUIStore((s) => s.searchScope);
  const setScope = useUIStore((s) => s.setSearchScope);
  const searchRef = useRef<OmniSearchInputHandle>(null);

  const onSearchPage = location.pathname === "/search";

  // See `suggestionDictionary` — assigned during render, read by the composite
  // suggestion hook when the input renders a moment later.
  suggestionDictionary = scope === "workbench" ? "intel" : "server";

  // Leaving /search abandons the query, so returning to the reader doesn't come
  // back to a field still holding the last search.
  //
  // Keyed on the *transition* away, not on "not currently on /search": typing
  // from the feed reader sets the query one render before `navigate` lands, and
  // a plain `!onSearchPage` guard would clear every keystroke in that gap — the
  // field could never accumulate a query anywhere but on the search page.
  const wasOnSearchPage = useRef(onSearchPage);
  useEffect(() => {
    if (wasOnSearchPage.current && !onSearchPage) setHeaderSearchQuery("");
    wasOnSearchPage.current = onSearchPage;
  }, [onSearchPage, setHeaderSearchQuery]);

  /**
   * Any typing sends the user to the surface that can answer.
   *
   * The scope rides along unchanged: it is the user's setting, not the route's.
   * Searching from the workbench used to seed `in: workbench` and from the
   * reader `in: feeds`, which silently narrowed a search the user never asked
   * to narrow. It stays wherever they last put it, defaulting to `everything`.
   */
  const openSearchPage = useCallback(() => {
    if (onSearchPage) return;
    navigate("/search");
  }, [onSearchPage, navigate]);

  // Arriving at /search from the feed reader crosses a layout boundary
  // (MainLayout → SidebarLayout), and each layout renders its own AppHeader —
  // so this field unmounts and a fresh one mounts mid-word. The query itself
  // lives in the store and survives; focus and the caret do not. Restore both
  // on the frame after mount so the user keeps typing into the same word.
  useEffect(() => {
    if (!onSearchPage || !headerSearchQuery) return;
    const el = inputRef.current;
    if (!el || document.activeElement === el) return;
    el.focus();
    el.setSelectionRange(el.value.length, el.value.length);
    // Mount-only: re-running on every keystroke would fight a deliberate blur.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const cycleScope = useCallback(() => {
    setScope(SCOPE_CYCLE[(SCOPE_CYCLE.indexOf(scope) + 1) % SCOPE_CYCLE.length]);
    inputRef.current?.focus();
  }, [scope, setScope, inputRef]);

  const handleClear = () => {
    setHeaderSearchQuery("");
    searchRef.current?.close();
    inputRef.current?.blur();
  };

  // Keys the shared input doesn't claim. It handles the Escape ladder and the
  // suggestion arrows/Tab/Enter first, so Tab only reaches the scope chip when
  // no completion is on offer — completions keep their Tab.
  const handleExtraKeys = (e: React.KeyboardEvent) => {
    if (e.key === "Tab" && !e.shiftKey) {
      e.preventDefault();
      cycleScope();
      return true;
    }
    if (e.key === "Enter") {
      openSearchPage();
      return true;
    }
    return false;
  };

  // Escape ladder rung 2 (rung 1 — closing an open completion list — is the
  // shared input's): clear the field.
  const handleEscape = () => {
    setHeaderSearchQuery("");
    inputRef.current?.blur();
  };

  return (
    <div className={styles.wrapper}>
      {/* Scope changes are silent to a screen reader otherwise — Tab moves the
          chip without moving focus. */}
      <span className={styles.srOnly} aria-live="polite">Search scope: {scope}</span>
      <OmniSearchInput<HeaderSuggestion>
        inputRef={inputRef}
        controlRef={searchRef}
        value={headerSearchQuery}
        onChange={(next) => {
          setHeaderSearchQuery(next);
          if (next.trim()) openSearchPage();
        }}
        onFocus={() => {
          if (headerSearchQuery.trim()) openSearchPage();
        }}
        // ArrowUp past the top deselects (-1 is a real state) and neither arrow wraps.
        wrap={false}
        allowDeselect
        // The autocomplete query is already cheap and heavily cached (60s staleTime),
        // and the token has to keep up with the caret, so it stays undebounced.
        // The results page runs its own debounce.
        debounceMs={0}
        // The only claimant now that the field renders on every desktop route.
        // The workbench's mobile overlay keeps its own, because "/" there has to
        // *open* the overlay before there is an input to focus.
        ownsSlashKey
        slashKeyOwnerLabel="HeaderSearch"
        onEscape={handleEscape}
        extraKeys={handleExtraKeys}
        suggestionSource={useScopedSuggestions}
        placeholder={SCOPE_PLACEHOLDER[scope]}
        classes={{
          wrapper: styles.omniWrapper,
          inputRow: `${styles.inputRow} ${onSearchPage && headerSearchQuery ? styles.inputRowActive : ""}`,
          input: styles.input,
          dropdown: styles.suggestionsDropdown,
        }}
        leading={
          <>
            <svg className={styles.searchIcon} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
            <button
              type="button"
              className={styles.scopeChip}
              // Keep the caret where it was — the chip is a control, not a destination.
              onMouseDown={(e) => e.preventDefault()}
              onClick={cycleScope}
              aria-label={`Search scope: ${scope}. Activate, or press Tab in the field, to change it.`}
              title="Search scope — Tab to cycle"
            >
              <span className={styles.scopeChipKey}>in:</span>
              {scope}
            </button>
          </>
        }
        trailing={
          headerSearchQuery && (
            <button className={styles.clearBtn} onClick={handleClear} title="Clear search">
              &times;
            </button>
          )
        }
        renderSuggestion={(item, ctx) => (
          <button
            ref={ctx.ref}
            className={`${styles.suggestionItem} ${ctx.active ? styles.suggestionSelected : ""}`}
            onMouseDown={(e) => { e.preventDefault(); ctx.select(); }}
            onMouseEnter={ctx.activate}
          >
            {/* Coloured by the field's own namespace, from the same table the
                query-language reference uses — a `cve:` completion is CVE red
                on every theme. */}
            <span
              className={styles.suggestionDot}
              style={{ backgroundColor: queryFieldColor(item.insert || item.text) }}
            />
            <span className={styles.suggestionName}>{item.text}</span>
            {item.description && <span className={styles.suggestionCount}>{item.description}</span>}
          </button>
        )}
      />
    </div>
  );
}
