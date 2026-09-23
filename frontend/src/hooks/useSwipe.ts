import { useRef, useEffect, useCallback } from "react";

interface SwipeConfig {
  onSwipeLeft?: () => void;
  onSwipeRight?: () => void;
  threshold?: number;
  maxVerticalRatio?: number;
  edgeOnly?: boolean;
  edgeWidth?: number;
  enabled?: boolean;
}

export function useSwipe<T extends HTMLElement>(config: SwipeConfig) {
  const ref = useRef<T>(null);
  const startX = useRef(0);
  const startY = useRef(0);
  const tracking = useRef(false);

  const {
    onSwipeLeft,
    onSwipeRight,
    threshold = 50,
    maxVerticalRatio = 0.75,
    edgeOnly = false,
    edgeWidth = 30,
    enabled = true,
  } = config;

  const onSwipeLeftRef = useRef(onSwipeLeft);
  const onSwipeRightRef = useRef(onSwipeRight);
  onSwipeLeftRef.current = onSwipeLeft;
  onSwipeRightRef.current = onSwipeRight;

  const handleTouchStart = useCallback(
    (e: TouchEvent) => {
      if (!enabled) return;
      const touch = e.touches[0];
      if (edgeOnly) {
        const isLeftEdge = touch.clientX < edgeWidth;
        const isRightEdge = touch.clientX > window.innerWidth - edgeWidth;
        if (!isLeftEdge && !isRightEdge) return;
      }
      startX.current = touch.clientX;
      startY.current = touch.clientY;
      tracking.current = true;
    },
    [enabled, edgeOnly, edgeWidth]
  );

  const handleTouchEnd = useCallback(
    (e: TouchEvent) => {
      if (!tracking.current) return;
      tracking.current = false;

      const touch = e.changedTouches[0];
      const dx = touch.clientX - startX.current;
      const dy = touch.clientY - startY.current;
      const absDx = Math.abs(dx);
      const absDy = Math.abs(dy);

      if (absDx < threshold) return;
      if (absDy / absDx > maxVerticalRatio) return;

      if (dx > 0) {
        onSwipeRightRef.current?.();
      } else {
        onSwipeLeftRef.current?.();
      }
    },
    [threshold, maxVerticalRatio]
  );

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    el.addEventListener("touchstart", handleTouchStart, { passive: true });
    el.addEventListener("touchend", handleTouchEnd, { passive: true });

    return () => {
      el.removeEventListener("touchstart", handleTouchStart);
      el.removeEventListener("touchend", handleTouchEnd);
    };
  }, [handleTouchStart, handleTouchEnd]);

  return ref;
}
