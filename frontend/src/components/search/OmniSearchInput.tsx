import { Fragment, useImperativeHandle, useRef, type ReactNode, type Ref } from "react";
import { useOmniSearchInput, type UseOmniSearchInputOptions } from "./useOmniSearchInput";
import type { OmniSuggestion, SuggestionSource } from "./types";
import styles from "./OmniSearchInput.module.css";

/** Class names a surface can override. Anything omitted falls back to the module defaults. */
export interface OmniSearchClasses {
  /** Positioning context for the dropdown; click-outside is measured against it. */
  wrapper: string;
  /** The bordered row holding icon + input + trailing content. */
  inputRow: string;
  input: string;
  /** The floating panel under the input. */
  dropdown: string;
}

/** What `renderSuggestion` gets for one row of the default dropdown. */
export interface OmniSuggestionContext {
  index: number;
  active: boolean;
  /** Put this on the row element so the active row can be scrolled into view. */
  ref: (el: HTMLElement | null) => void;
  /** Accept this suggestion. */
  select: () => void;
  /** Make this row the active one (mouse-enter). */
  activate: () => void;
}

/** Imperative escape hatch for surfaces that need to close or focus from outside. */
export interface OmniSearchInputHandle {
  open: () => void;
  close: () => void;
  focus: () => void;
  blur: () => void;
}

type SharedOptions<S extends OmniSuggestion> = Omit<
  UseOmniSearchInputOptions<S>,
  "inputRef" | "containerRef" | "suggestionSource"
>;

export interface OmniSearchInputProps<S extends OmniSuggestion> extends SharedOptions<S> {
  /**
   * Where suggestions come from. A **hook** — stable identity required, and it must
   * return `NO_SUGGESTIONS` (not a fresh `[]`) when it has nothing. See `SuggestionSource`.
   */
  suggestionSource?: SuggestionSource<S>;
  /** Supply one when the surface needs to focus/blur the input itself. */
  inputRef?: React.RefObject<HTMLInputElement | null>;
  controlRef?: Ref<OmniSearchInputHandle>;
  placeholder?: string;
  "aria-label"?: string;
  autoFocus?: boolean;
  /** Rendered before the input — typically a magnifier icon. */
  leading?: ReactNode;
  /** Rendered after the input — clear buttons, result counts, chips. */
  trailing?: ReactNode;
  classes?: Partial<OmniSearchClasses>;
  /** Draws one row of the default dropdown. */
  renderSuggestion?: (suggestion: S, ctx: OmniSuggestionContext) => ReactNode;
  /** Extra content inside the wrapper, below the input row (chip rows, help panels). */
  children?: ReactNode;
  /** Called on focus, after the dropdown has been opened. */
  onFocus?: () => void;
}

/**
 * The one search **input** in the app: caret tokenisation, suggestion splice with
 * caret restore, a single selection state machine (`wrap` / `allowDeselect`),
 * debounce, click-outside, the Escape ladder, and an opt-in `/` shortcut.
 *
 * It owns no results. Fetching and rendering belong to the surface: this draws a
 * flat completion list through `renderSuggestion` and nothing else.
 *
 * It used to carry a `renderDropdown` escape hatch so the workbench overlay
 * could draw grouped entity results inside it. That overlay — and the second
 * search engine behind it — is gone, and `/search` renders its own results, so
 * the hatch went with it.
 *
 * Selection semantics, all expressible through config:
 *   `{ wrap: false, allowDeselect: true }`  — header search (ArrowUp deselects)
 *   `{ wrap: false, allowDeselect: false }` — command palette (clamped, Enter always acts)
 */
export function OmniSearchInput<S extends OmniSuggestion>({
  suggestionSource,
  inputRef: inputRefProp,
  controlRef,
  placeholder,
  "aria-label": ariaLabel,
  autoFocus,
  leading,
  trailing,
  classes,
  renderSuggestion,
  children,
  onFocus,
  ...hookOptions
}: OmniSearchInputProps<S>) {
  const fallbackInputRef = useRef<HTMLInputElement>(null);
  const inputRef = inputRefProp ?? fallbackInputRef;
  const containerRef = useRef<HTMLDivElement>(null);

  const search = useOmniSearchInput<S>({ ...hookOptions, suggestionSource, inputRef, containerRef });
  const { open, setOpen, suggestions, token, activeIndex, setActiveIndex, applySuggestion, registerItem } = search;

  useImperativeHandle(
    controlRef,
    () => ({
      open: () => setOpen(true),
      close: () => setOpen(false),
      focus: () => inputRef.current?.focus(),
      blur: () => inputRef.current?.blur(),
    }),
    [setOpen, inputRef],
  );

  const cls = {
    wrapper: classes?.wrapper ?? styles.wrapper,
    inputRow: classes?.inputRow ?? styles.inputRow,
    input: classes?.input ?? styles.input,
    dropdown: classes?.dropdown ?? styles.dropdown,
  };

  const { onFocus: openOnFocus, ...restInputProps } = search.inputProps;

  const defaultDropdown =
    open && suggestions.length > 0 && token && renderSuggestion ? (
      <div className={cls.dropdown} role="listbox">
        {suggestions.map((item, i) => (
          <Fragment key={`${i}:${item.insert}`}>
            {renderSuggestion(item, {
              index: i,
              active: i === activeIndex,
              ref: registerItem(i),
              select: () => applySuggestion(item),
              activate: () => setActiveIndex(i),
            })}
          </Fragment>
        ))}
      </div>
    ) : null;

  return (
    <div className={cls.wrapper} ref={containerRef}>
      <div className={cls.inputRow}>
        {leading}
        <input
          {...restInputProps}
          type="text"
          className={cls.input}
          placeholder={placeholder}
          aria-label={ariaLabel}
          autoFocus={autoFocus}
          onFocus={() => {
            openOnFocus();
            onFocus?.();
          }}
        />
        {trailing}
      </div>
      {defaultDropdown}
      {children}
    </div>
  );
}
