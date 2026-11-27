import { useNavigate } from "react-router-dom";
import { useUIStore } from "@/stores/uiStore";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { IntelFeedLogo } from "./IntelFeedLogo";
import styles from "./BrandButton.module.css";

interface BrandButtonProps {
  /** Extra class from the host surface, for spacing only. */
  className?: string;
}

/**
 * The wordmark, as a button that goes back to all items.
 *
 * One component for both places it appears: the desktop app header, and the mobile sidebar's top row (where the header shows a hamburger instead). Sharing it keeps the sidebar wordmark clickable on a phone instead of being a plain `<span>` that looks like a button but does nothing.
 */
export function BrandButton({ className }: BrandButtonProps) {
  const navigate = useNavigate();
  const isMobile = useIsMobile();
  const setSelectedFeed = useUIStore((s) => s.setSelectedFeed);
  const setSidebarCollapsed = useUIStore((s) => s.setSidebarCollapsed);

  return (
    <button
      className={`${styles.brand} ${className ?? ""}`}
      onClick={() => {
        setSelectedFeed(null);
        // Desktop: expand the sidebar so the nav is showing.
        // Mobile: the sidebar is a full-screen overlay, so collapse it to reveal all items.
        setSidebarCollapsed(isMobile);
        navigate("/");
      }}
      aria-label="Go to all items"
      title="All Items"
    >
      <IntelFeedLogo size={24} className={styles.brandLogo} />
      <span>
        Intel<span className={styles.brandAccent}>Feed</span>
      </span>
    </button>
  );
}
