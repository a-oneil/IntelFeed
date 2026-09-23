import { useRef, useEffect, useCallback, useState } from "react";

interface PullToRefreshOptions {
  /** Element that scrolls — pull activates only when scrollTop === 0 */
  scrollRef: React.RefObject<HTMLElement | null>;
  /** Async callback fired on successful pull */
  onRefresh: () => Promise<void>;
  /** Min pull distance (px) to trigger refresh. Default 64 */
  threshold?: number;
  /** Max visual pull distance (px). Default 128 */
  maxPull?: number;
  /** Whether the hook is active. Default true */
  enabled?: boolean;
}

interface PullToRefreshState {
  /** Current pull distance (0 when idle) */
  pullDistance: number;
  /** Whether a refresh is in progress */
  isRefreshing: boolean;
}

export function usePullToRefresh({
  scrollRef,
  onRefresh,
  threshold = 64,
  maxPull = 128,
  enabled = true,
}: PullToRefreshOptions): PullToRefreshState {
  const [pullDistance, setPullDistance] = useState(0);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Refs mirror state so the touch listeners can read current values without
  // being re-attached on every render — re-attaching mid-gesture causes iOS
  // Safari to drop the rest of the gesture.
  const pullDistanceRef = useRef(0);
  const isRefreshingRef = useRef(false);
  const onRefreshRef = useRef(onRefresh);
  onRefreshRef.current = onRefresh;

  const setDistance = useCallback((d: number) => {
    pullDistanceRef.current = d;
    setPullDistance(d);
  }, []);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el || !enabled) return;

    let startY = 0;
    let pulling = false;

    const onTouchStart = (e: TouchEvent) => {
      if (isRefreshingRef.current) return;
      if (el.scrollTop <= 0) {
        startY = e.touches[0].clientY;
        pulling = true;
      }
    };

    const onTouchMove = (e: TouchEvent) => {
      if (!pulling || isRefreshingRef.current) return;
      if (el.scrollTop > 0) {
        pulling = false;
        setDistance(0);
        return;
      }
      const deltaY = e.touches[0].clientY - startY;
      if (deltaY > 0) {
        // Block native rubber-band as soon as we know the user is pulling
        // down — waiting until the indicator is visible is too late on iOS.
        if (e.cancelable) e.preventDefault();
        const distance = Math.min(deltaY * 0.5, maxPull);
        setDistance(distance);
      } else {
        setDistance(0);
      }
    };

    const finishGesture = async () => {
      if (!pulling || isRefreshingRef.current) return;
      pulling = false;
      if (pullDistanceRef.current >= threshold) {
        isRefreshingRef.current = true;
        setIsRefreshing(true);
        setDistance(threshold);
        try {
          await onRefreshRef.current();
        } finally {
          isRefreshingRef.current = false;
          setIsRefreshing(false);
          setDistance(0);
        }
      } else {
        setDistance(0);
      }
    };

    el.addEventListener("touchstart", onTouchStart, { passive: true });
    el.addEventListener("touchmove", onTouchMove, { passive: false });
    el.addEventListener("touchend", finishGesture, { passive: true });
    el.addEventListener("touchcancel", finishGesture, { passive: true });
    return () => {
      el.removeEventListener("touchstart", onTouchStart);
      el.removeEventListener("touchmove", onTouchMove);
      el.removeEventListener("touchend", finishGesture);
      el.removeEventListener("touchcancel", finishGesture);
    };
  }, [scrollRef, enabled, threshold, maxPull, setDistance]);

  return { pullDistance, isRefreshing };
}
