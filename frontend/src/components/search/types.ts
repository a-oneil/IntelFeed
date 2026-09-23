import type { CursorToken } from "@/utils/queryParser";

/**
 * The token under the caret, as understood by the shared search input.
 *
 * Derived from `getTokenAtCursor` (utils/queryParser) — it walks both directions
 * from the caret and treats `(` / `)` as boundaries, which is the behaviour every
 * search surface wants. `text` is the raw slice a suggestion replaces.
 */
export interface OmniToken {
  /** Raw text of the token, i.e. `value.slice(startPos, endPos)`. Never empty. */
  text: string;
  /** What the tokenizer thinks this is: a bare field name, a `field:value`, or free text. */
  kind: CursorToken["type"];
  /** Field name, for `field_value` tokens only. */
  field?: string;
  /** Text after the `:` for `field_value`, otherwise the whole token. */
  partialValue: string;
  /** Inclusive start offset into the query string. */
  startPos: number;
  /** Exclusive end offset into the query string. */
  endPos: number;
}

/**
 * Minimum shape a suggestion must have to be applicable by the shared input.
 *
 * `insert` replaces `[token.startPos, token.endPos)`. `type === "value"` means the
 * token is now complete, so a trailing space is appended and the dropdown closes;
 * anything else (typically `"field"`) leaves the caret right after the text so the
 * user can keep typing the value.
 */
export interface OmniSuggestion {
  insert: string;
  type?: string;
}

/**
 * A suggestion source is a **React hook**, not a plain function.
 *
 * It is called unconditionally, once per render, from inside `useOmniSearchInput`,
 * so it may call `useQuery` / `useMemo` / anything else. Two consequences:
 *
 *  1. Its identity must be stable across renders — define it at module scope, or
 *     memoise it. Swapping sources between renders breaks the rules of hooks.
 *  2. It must return a **stable array identity** when it has nothing to offer.
 *     Export `NO_SUGGESTIONS` exists for exactly this; see the note on it.
 *
 * `enabled` is false whenever the dropdown is closed or there is no token, so a
 * network-backed source can gate its request on it.
 */
export type SuggestionSource<S extends OmniSuggestion = OmniSuggestion> = (
  token: OmniToken | null,
  enabled: boolean,
) => readonly S[];

/**
 * Stable identity for "no suggestions".
 *
 * `useOmniSearchInput` resets its selection index in a `useEffect` keyed on the
 * suggestions array. Returning a fresh `[]` from a source gives that effect a new
 * dependency on every render, which is an infinite render loop — and it manifests
 * as a frozen browser tab, not as a failing test. Always fall back to this constant.
 */
export const NO_SUGGESTIONS: readonly never[] = [];
