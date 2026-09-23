import {
  cloneElement,
  isValidElement,
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type ReactElement,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { useHoverCards } from "@/hooks/useMediaQuery";
import styles from "./Hint.module.css";

export type HintPlace = "bottom" | "top" | "right" | "left";
export type HintAlign = "start" | "center" | "end";

interface HintProps {
  /** The control's name, in bold. Not a sentence. */
  title: ReactNode;
  /** One plain line about what the thing does. */
  body: ReactNode;
  /** Optional muted third line — the caveat, the shortcut, the thing people get wrong. */
  aside?: ReactNode;
  place?: HintPlace;
  align?: HintAlign;
  /** 240 suits three lines of `--fs-sm`; widen only for genuinely longer copy. */
  width?: number;
  /** Skip the hint entirely — for call sites that only sometimes want one. */
  disabled?: boolean;
  delay?: number;
  /** A single element that takes a ref: the control being explained. */
  children: ReactElement;
}

const GAP = 9;
const EDGE = 8;

type Handler = ((e: unknown) => void) | undefined;

const compose = (theirs: Handler, ours: () => void) => (e: unknown) => {
  theirs?.(e);
  ours();
};

/**
 * A hover card that explains a control.
 *
 * Wraps the control rather than replacing it — `cloneElement` attaches the
 * handlers and `aria-describedby` to the child, so the DOM keeps exactly the
 * shape the surrounding flex/grid layout already expects.
 *
 * Use a card when the control's name doesn't tell you what happens. For
 * one-word actions (Close, Delete, Star) a native `title` is still right.
 */
export function Hint({
  title,
  body,
  aside,
  place = "bottom",
  align = "start",
  width = 240,
  disabled = false,
  delay = 400,
  children,
}: HintProps) {
  const id = useId();
  const hoverCards = useHoverCards();
  const [anchor, setAnchor] = useState<DOMRect | null>(null);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const triggerRef = useRef<HTMLElement | null>(null);
  const cardRef = useRef<HTMLDivElement>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearTimer = () => {
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = null;
  };

  const close = useCallback(() => {
    clearTimer();
    setAnchor(null);
    setPos(null);
  }, []);

  const openAfter = useCallback(
    (wait: number) => {
      if (disabled) return;
      clearTimer();
      timerRef.current = setTimeout(() => {
        const el = triggerRef.current;
        if (el) setAnchor(el.getBoundingClientRect());
      }, wait);
    },
    [disabled],
  );

  // Deliberate delay on hover: instant cards on controls you pass over all day
  // read as nagging. Keyboard focus is an explicit ask, so it skips the wait.
  const onEnter = useCallback(() => openAfter(delay), [openAfter, delay]);
  const onFocus = useCallback(() => openAfter(0), [openAfter]);

  useEffect(() => clearTimer, []);

  // A fixed card can't travel with a scrolling container, so close rather than
  // let it drift away from the control it describes.
  useEffect(() => {
    if (!anchor) return;
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [anchor, close]);

  useLayoutEffect(() => {
    if (!anchor || !cardRef.current) return;
    const card = cardRef.current.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    let top: number;
    let left: number;

    if (place === "right" || place === "left") {
      left = place === "right" ? anchor.right + GAP : anchor.left - GAP - card.width;
      top =
        align === "center"
          ? anchor.top + anchor.height / 2 - card.height / 2
          : align === "end"
            ? anchor.bottom - card.height
            : anchor.top;
      if (place === "right" && left + card.width > vw - EDGE) left = anchor.left - GAP - card.width;
      if (place === "left" && left < EDGE) left = anchor.right + GAP;
    } else {
      top = place === "bottom" ? anchor.bottom + GAP : anchor.top - GAP - card.height;
      left =
        align === "center"
          ? anchor.left + anchor.width / 2 - card.width / 2
          : align === "end"
            ? anchor.right - card.width
            : anchor.left;
      if (place === "bottom" && top + card.height > vh - EDGE) top = anchor.top - GAP - card.height;
      if (place === "top" && top < EDGE) top = anchor.bottom + GAP;
    }

    setPos({
      top: Math.min(Math.max(EDGE, top), Math.max(EDGE, vh - card.height - EDGE)),
      left: Math.min(Math.max(EDGE, left), Math.max(EDGE, vw - card.width - EDGE)),
    });
  }, [anchor, place, align]);

  const attachRef = useCallback(
    (node: HTMLElement | null) => {
      triggerRef.current = node;
      // Don't strand a ref the call site already had on the control.
      const theirs = (children as unknown as { ref?: unknown }).ref;
      if (typeof theirs === "function") (theirs as (n: HTMLElement | null) => void)(node);
      else if (theirs && typeof theirs === "object") {
        (theirs as { current: HTMLElement | null }).current = node;
      }
    },
    [children],
  );

  if (!isValidElement(children)) return children;
  // Touch has no hover: the card would open on the tap that activates the
  // control and then need a second tap on nothing to dismiss it.
  if (disabled || !hoverCards) return children;

  const props = children.props as Record<string, unknown>;
  const trigger = cloneElement(children as ReactElement<Record<string, unknown>>, {
    ref: attachRef,
    "aria-describedby": anchor ? id : props["aria-describedby"],
    onMouseEnter: compose(props.onMouseEnter as Handler, onEnter),
    onMouseLeave: compose(props.onMouseLeave as Handler, close),
    onFocus: compose(props.onFocus as Handler, onFocus),
    onBlur: compose(props.onBlur as Handler, close),
  } as Record<string, unknown>);

  return (
    <>
      {trigger}
      {anchor &&
        createPortal(
          <div
            ref={cardRef}
            id={id}
            role="tooltip"
            className={`${styles.card} ${pos ? styles.visible : ""}`}
            style={{ width, top: pos?.top ?? 0, left: pos?.left ?? 0 }}
          >
            <strong className={styles.title}>{title}</strong>
            <span>{body}</span>
            {aside !== undefined && <span className={styles.aside}>{aside}</span>}
          </div>,
          document.body,
        )}
    </>
  );
}
