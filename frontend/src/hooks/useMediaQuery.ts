import { useState, useEffect } from "react";

export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() =>
    typeof window !== "undefined" ? window.matchMedia(query).matches : false
  );

  useEffect(() => {
    const mql = window.matchMedia(query);
    const handler = (e: MediaQueryListEvent) => setMatches(e.matches);
    mql.addEventListener("change", handler);
    setMatches(mql.matches);
    return () => mql.removeEventListener("change", handler);
  }, [query]);

  return matches;
}

export function useIsMobile(): boolean {
  return useMediaQuery("(max-width: 767px)");
}

export function useIsTablet(): boolean {
  return useMediaQuery("(max-width: 1199px)");
}

/** True only where the pointer can genuinely hover. */
export function useHasHover(): boolean {
  return useMediaQuery("(hover: hover) and (pointer: fine)");
}

/**
 * Whether floating hover cards (Hint, Tooltip) should render at all.
 *
 * Two reasons they shouldn't. Touch synthesizes a `mouseenter` on tap, so the
 * card opens on the tap that activates the control and then needs a second tap
 * on nothing to dismiss it. And at mobile width the app is already in its
 * mobile layout, where a 240px card over a 390px screen covers the thing it
 * was explaining — including in a desktop browser narrowed to that width.
 */
export function useHoverCards(): boolean {
  const hasHover = useHasHover();
  const isMobile = useIsMobile();
  return hasHover && !isMobile;
}
