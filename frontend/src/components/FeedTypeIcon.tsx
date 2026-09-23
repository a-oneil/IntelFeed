import styles from "./FeedTypeIcon.module.css";

export function FeedTypeIcon({ type, size = 12 }: { type: string; size?: number }) {
  const cls = styles.feedTypeIcon;
  switch (type) {
    case "youtube":
      return (
        <svg className={cls} width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
          <path d="M23.5 6.2a3 3 0 0 0-2.1-2.1C19.5 3.5 12 3.5 12 3.5s-7.5 0-9.4.6A3 3 0 0 0 .5 6.2 31.5 31.5 0 0 0 0 12a31.5 31.5 0 0 0 .5 5.8 3 3 0 0 0 2.1 2.1c1.9.6 9.4.6 9.4.6s7.5 0 9.4-.6a3 3 0 0 0 2.1-2.1c.3-1.9.5-3.8.5-5.8s-.2-3.9-.5-5.8zM9.5 15.6V8.4l6.3 3.6-6.3 3.6z" />
        </svg>
      );
    case "podcast":
      return (
        <svg className={cls} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z" />
          <path d="M19 10v2a7 7 0 0 1-14 0v-2" />
          <line x1="12" y1="19" x2="12" y2="23" />
          <line x1="8" y1="23" x2="16" y2="23" />
        </svg>
      );
    case "reddit":
      return (
        <svg className={cls} width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
          <circle cx="9" cy="14" r="1.5" />
          <circle cx="15" cy="14" r="1.5" />
          <path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.6 0 12 0zm6.3 13.3c0 3.3-2.8 5.9-6.3 5.9s-6.3-2.6-6.3-5.9c0-.6.1-1.1.3-1.6-.5-.3-.8-.9-.8-1.5 0-1 .8-1.8 1.8-1.8.5 0 .9.2 1.2.5 1.1-.7 2.5-1.2 4-1.2l.8-3.7 2.6.6c.2-.5.7-.8 1.2-.8.8 0 1.4.6 1.4 1.4s-.6 1.4-1.4 1.4c-.7 0-1.2-.5-1.4-1.1l-2.1-.5-.6 3c1.4.1 2.8.5 3.8 1.2.3-.3.8-.5 1.2-.5 1 0 1.8.8 1.8 1.8 0 .6-.3 1.2-.8 1.5.2.5.3 1 .3 1.6z" />
          <path d="M14.5 17c-.4.4-1.3.7-2.5.7s-2.1-.3-2.5-.7" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" />
        </svg>
      );
    case "github":
    case "github_repo":
      return (
        <svg className={cls} width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 0C5.4 0 0 5.4 0 12c0 5.3 3.4 9.8 8.2 11.4.6.1.8-.3.8-.6v-2c-3.3.7-4-1.6-4-1.6-.5-1.4-1.3-1.8-1.3-1.8-1.1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1.1 1.8 2.8 1.3 3.5 1 .1-.8.4-1.3.7-1.6-2.7-.3-5.5-1.3-5.5-5.9 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.5.1-3.2 0 0 1-.3 3.3 1.2 1-.3 2-.4 3-.4s2 .1 3 .4c2.3-1.6 3.3-1.2 3.3-1.2.7 1.7.3 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.6-2.8 5.6-5.5 5.9.4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6C20.6 21.8 24 17.3 24 12 24 5.4 18.6 0 12 0z" />
        </svg>
      );
    case "manual":
      return (
        <svg className={cls} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <polyline points="14 2 14 8 20 8" />
          <line x1="12" y1="18" x2="12" y2="12" />
          <polyline points="9 15 12 12 15 15" />
        </svg>
      );
    case "atom":
      return (
        <svg className={cls} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="2" fill="currentColor" />
          <ellipse cx="12" cy="12" rx="10" ry="4" />
          <ellipse cx="12" cy="12" rx="10" ry="4" transform="rotate(60 12 12)" />
          <ellipse cx="12" cy="12" rx="10" ry="4" transform="rotate(120 12 12)" />
        </svg>
      );
    case "web_scraper":
      return (
        <svg className={cls} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <line x1="2" y1="12" x2="22" y2="12" />
          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
        </svg>
      );
    case "telegram":
      // Telegram paper-airplane silhouette
      return (
        <svg className={cls} width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
          <path d="M22.5 2.4c-.3-.3-.7-.3-1.1-.2L2 9.5c-.5.2-.8.6-.8 1.1 0 .5.3.9.8 1l4.6 1.6 1.7 5.4c.1.4.5.7.9.7.3 0 .5-.1.7-.3l2.5-2.5 4.5 3.4c.2.2.5.3.7.3.2 0 .3 0 .5-.1.4-.2.7-.5.7-1L23 3.4c.1-.4 0-.8-.5-1zM9.4 14.2l-.5 3.6-1.1-3.4 9.8-7.7-8.2 7.5z" />
        </svg>
      );
    case "bluesky":
      // Stylised butterfly silhouette to match Bluesky's logo
      return (
        <svg className={cls} width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
          <path d="M5.8 3.2c-.6.5-2 1.5-2 4.4 0 1.4.4 2.7 1.1 3.7C5.7 12.5 7 13.5 7.6 14c.3.3.5.5.5.7 0 .3-.4.6-.8.8-.6.4-1.4.8-1.4 2 0 .9.7 1.4 1.4 1.6.7.2 1.3 0 1.7-.2 1.6-.8 2.6-2 2.9-2.5.1-.2.2-.3.4-.3.1 0 .3.1.4.3.3.5 1.3 1.7 2.9 2.5.4.2 1 .4 1.7.2.7-.2 1.4-.7 1.4-1.6 0-1.2-.8-1.6-1.4-2-.4-.2-.8-.5-.8-.8 0-.2.2-.4.5-.7.6-.5 1.9-1.5 2.7-2.7.7-1 1.1-2.3 1.1-3.7 0-2.9-1.4-3.9-2-4.4-.6-.5-1.5-.6-2.2-.2-1.4.7-3.4 3-4.3 4.7-.9-1.7-2.9-4-4.3-4.7-.7-.4-1.6-.3-2.2.2z" />
        </svg>
      );
    default: // rss
      return (
        <svg className={cls} width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
          <circle cx="3.5" cy="20.5" r="2.5" />
          <path d="M1 1c12.7 0 23 10.3 23 23h-4C20 13 13 6 2 6V1h-1z" />
          <path d="M1 8c8.8 0 16 7.2 16 16h-4c0-6.6-5.4-12-12-12V8z" />
        </svg>
      );
  }
}
