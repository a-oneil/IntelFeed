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
 * The wordmark, as a button back to all items.
 *
 * One component for both places it appears: the desktop app header, and the
 * mobile sidebar's top row (where the header shows a hamburger instead). It
 * used to be a plain, dead `<span>` in the sidebar — same words, none of the
 * behaviour — so on a phone the wordmark was the one piece of chrome that
 * didn't do what it looks like it does.
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
        // Desktop: make sure the nav you are heading back to is showing.
        // Mobile: the sidebar is a full-screen overlay, so getting to all items
        // means getting out of its way.
        setSidebarCollapsed(isMobile);
        navigate("/");
      }}
      aria-label="Go to all items"
      title="All Items"
    >
      <IntelFeedLogo size={18} className={styles.brandLogo} />
      <span>
        Intel<span className={styles.brandAccent}>Feed</span>
      </span>
    </button>
  );
}
