import { useLocation } from "react-router-dom";
import { Spinner } from "@/components/primitives";
import { getRouteLabel } from "@/utils/routeLabels";
import styles from "./RouteFallback.module.css";

interface RouteFallbackProps {
  /**
   * What is loading, e.g. "ATT&CK matrix". Omit inside a routed boundary —
   * the pending route's own label is used instead.
   */
  label?: string;
  /** Single-line spinner + text, for a section swapping inside a page. */
  inline?: boolean;
}

/**
 * Fallback for a lazily-loaded routed page or section.
 *
 * The app previously had ONE Suspense boundary, at the top of `App.tsx`, with a
 * `height: 100vh` fallback. Because that boundary sat outside the layouts,
 * every route change unmounted the header, the sidebar and the copilot dock
 * for the duration of the chunk fetch — including for chunks the browser had
 * already cached. On this machine `/workbench` takes ~20s to transform cold in
 * dev, and the entire app was blank for all of it.
 *
 * Rendering this inside the layout instead means only the content pane swaps.
 *
 * Every fallback names what it is fetching when the route is one we can name
 * ("Loading Engine…"), so a slow chunk reads as progress on a known page
 * rather than an anonymous stall.
 */
export function RouteFallback({ label, inline }: RouteFallbackProps) {
  // `useLocation` is safe here: every boundary using this sits inside the
  // router. The pathname is already the *pending* route when Suspense shows
  // the fallback, so it names the page being fetched.
  const { pathname, search } = useLocation();
  const resolved = label ?? getRouteLabel(pathname + search);
  const message = resolved ? `Loading ${resolved}…` : "Loading…";

  return (
    <div
      className={`${styles.wrap} ${inline ? styles.inline : ""}`}
      role="status"
      aria-live="polite"
    >
      <Spinner size={inline ? "md" : "lg"} />
      <span className={styles.label}>{message}</span>
    </div>
  );
}
