import type { ReactNode } from "react";
import { apiErrorInfo } from "@/api/errors";
import { useDebouncedValue } from "@/components/search/useOmniSearchInput";
import { useTitleFilterPreview } from "@/hooks/useFeeds";
import type { FeedForm } from "../useFeedForm";
import styles from "../fields.module.css";

/**
 * The feed's exclude-title list, with a live count of what it would drop.
 *
 * Phrases, not regular expressions: the cases this exists for are literal
 * title prefixes ("ISC Stormcast For", "Chromium CVE-"). The preview runs the
 * server's own matcher over the feed's last 100 titles, so a phrase that
 * catches real articles shows up here before it is saved rather than as a
 * silent gap afterwards.
 */
export function TitleFilterField({ feedId, form }: { feedId: string; form: FeedForm }) {
  const text = form.values.exclude_title_patterns;
  const debounced = useDebouncedValue(text, 400);
  const preview = useTitleFilterPreview(feedId, debounced);

  let status: ReactNode = null;
  if (text.trim() === "") {
    status = null;
  } else if (preview.isError) {
    status = (
      <div className={`${styles.banner} ${styles.bannerError}`} role="alert">
        {apiErrorInfo(preview.error).message}
      </div>
    );
  } else if (preview.data) {
    const { checked, dropped, examples } = preview.data;
    status = (
      <div className={styles.note} aria-live="polite">
        {checked === 0
          ? "No articles yet to test against."
          : `${dropped} of the last ${checked} titles would be dropped.`}
        {examples.length > 0 && (
          <ul className={styles.exampleList}>
            {examples.map((t, i) => (
              <li key={`${i}-${t}`}>{t}</li>
            ))}
          </ul>
        )}
      </div>
    );
  }

  return (
    <div className={styles.field}>
      <label className={styles.label} htmlFor="feed-exclude-titles">
        Skip articles whose title contains
      </label>
      <textarea
        id="feed-exclude-titles"
        className={styles.textarea}
        rows={3}
        value={text}
        placeholder={"ISC Stormcast For\nChromium CVE-"}
        onChange={(e) => form.set("exclude_title_patterns", e.target.value)}
      />
      <span className={styles.hint}>
        One phrase per line, matched anywhere in the title, ignoring case. A
        matching article is dropped before it is saved, so it is never tagged,
        analysed or scored. Articles already here stay.
      </span>
      {status}
    </div>
  );
}
