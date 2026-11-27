import { useLocation } from "react-router-dom";
import { Spinner } from "@/components/primitives";
import { getRouteLabel } from "@/utils/routeLabels";
import styles from "./RouteFallback.module.css";

interface RouteFallbackProps {
  /** What is loading, e.g. "ATT&CK matrix". Omit inside a routed boundary; the pending route's own label is used instead. */
  label?: string;
  /** Single-line spinner + text, for a section swapping inside a page. */
  inline?: boolean;
}

/**
 * Fallback for a lazily-loaded routed page or section.
 *
 * The layouts carry their own Suspense boundaries that render this, so only the content pane swaps. A single boundary at the top of `App.tsx`, outside the layouts, would unmount the header, the sidebar and the copilot dock on every route change for the duration of the chunk fetch, even for chunks the browser had already cached; `/workbench` can take ~20s to transform cold in dev, which left the whole app blank for that long.
 *
 * When the route has a known label, the fallback names it ("Loading Engine…"), so a slow chunk shows which page is loading.
 */
export function RouteFallback({ label, inline }: RouteFallbackProps) {
  // `useLocation` is safe here: every boundary using this sits inside the router. The pathname is already the *pending* route when Suspense shows the fallback, so it names the page being fetched.
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
