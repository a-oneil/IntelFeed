import {
  useState,
  useRef,
  useCallback,
  useEffect,
  useLayoutEffect,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { useHoverCards } from "@/hooks/useMediaQuery";
import styles from "./Tooltip.module.css";

interface Props {
  content: ReactNode;
  children: ReactNode;
  delay?: number;
  position?: "top" | "bottom" | "left" | "right";
  className?: string;
}

const GAP = 8;
const EDGE = 8;

/**
 * A plain hover card for a control that already has a name.
 *
 * Portalled and fixed-positioned rather than absolutely placed inside the
 * trigger: an absolute card centred on a trigger near the window edge (the
 * sidebar's category rows) hangs off the screen with nothing to scroll it
 * back into view. Positions here are clamped to the viewport instead, and the
 * `position` prop is the preferred side rather than a guarantee.
 */
export function Tooltip({ content, children, delay = 400, position = "right", className }: Props) {
  const hoverCards = useHoverCards();
  const [anchor, setAnchor] = useState<DOMRect | null>(null);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const triggerRef = useRef<HTMLDivElement>(null);
  const cardRef = useRef<HTMLDivElement>(null);

  const hide = useCallback(() => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    timeoutRef.current = null;
    setAnchor(null);
    setPos(null);
  }, []);

  const show = useCallback(() => {
    // Touch fires mouseenter on tap; see useHoverCards.
    if (!hoverCards) return;
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    timeoutRef.current = setTimeout(() => {
      const el = triggerRef.current;
      if (el) setAnchor(el.getBoundingClientRect());
    }, delay);
  }, [delay, hoverCards]);

  useEffect(() => () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
  }, []);

  // A fixed card can't travel with a scrolling container, so close rather than
  // let it drift away from the row it describes.
  useEffect(() => {
    if (!anchor) return;
    window.addEventListener("scroll", hide, true);
    window.addEventListener("resize", hide);
    return () => {
      window.removeEventListener("scroll", hide, true);
      window.removeEventListener("resize", hide);
    };
  }, [anchor, hide]);

  useLayoutEffect(() => {
    if (!anchor || !cardRef.current) return;
    const card = cardRef.current.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    let top: number;
    let left: number;

    if (position === "right" || position === "left") {
      left = position === "right" ? anchor.right + GAP : anchor.left - GAP - card.width;
      top = anchor.top + anchor.height / 2 - card.height / 2;
      // Flip to the other side before falling back to a clamp, so the card
      // doesn't end up sitting on top of its own trigger.
      if (position === "right" && left + card.width > vw - EDGE) left = anchor.left - GAP - card.width;
      if (position === "left" && left < EDGE) left = anchor.right + GAP;
    } else {
      top = position === "bottom" ? anchor.bottom + GAP : anchor.top - GAP - card.height;
      left = anchor.left + anchor.width / 2 - card.width / 2;
      if (position === "bottom" && top + card.height > vh - EDGE) top = anchor.top - GAP - card.height;
      if (position === "top" && top < EDGE) top = anchor.bottom + GAP;
    }

    setPos({
      top: Math.min(Math.max(EDGE, top), Math.max(EDGE, vh - card.height - EDGE)),
      left: Math.min(Math.max(EDGE, left), Math.max(EDGE, vw - card.width - EDGE)),
    });
  }, [anchor, position]);

  return (
    <div
      ref={triggerRef}
      className={`${styles.wrapper}${className ? ` ${className}` : ""}`}
      onMouseEnter={show}
      onMouseLeave={hide}
    >
      {children}
      {anchor &&
        createPortal(
          <div
            ref={cardRef}
            role="tooltip"
            className={`${styles.tooltip} ${pos ? styles.visible : ""}`}
            style={{ top: pos?.top ?? 0, left: pos?.left ?? 0 }}
          >
            {content}
          </div>,
          document.body,
        )}
    </div>
  );
}
