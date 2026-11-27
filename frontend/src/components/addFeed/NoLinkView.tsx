import { useState } from "react";
import type { Category, Feed } from "@/api/types";
import { useAddFeed, useCategorySuggestion } from "@/hooks/useFeeds";
import { FolderField } from "./FolderField";
import { blueskySearchFeed, mastodonTagFeed, nvdFeed, parseMastodonTag, type FeedCreate } from "./sourcePlan";
import styles from "../AddFeedModal.module.css";

interface Source {
  name: string;
  feedType: string;
  detail: string;
  label: string;
  placeholder: string;
  build: (value: string) => FeedCreate | null;
}

const SOURCES: Source[] = [
  {
    name: "NVD CVEs",
    feedType: "nvd",
    detail: "New CVEs that mention words you choose",
    label: "Words to match",
    placeholder: "Vendors or products, e.g. fortinet, ivanti",
    build: (v) => (v.trim() ? nvdFeed(v) : null),
  },
  {
    name: "Bluesky search",
    feedType: "bluesky",
    detail: "Posts matching a search",
    label: "Search",
    placeholder: 'ransomware OR "zero day"',
    build: (v) => (v.trim() ? blueskySearchFeed(v) : null),
  },
  {
    name: "Mastodon hashtag",
    feedType: "mastodon",
    detail: "Posts with a tag on one server",
    label: "Hashtag and server",
    placeholder: "#threatintel on infosec.exchange",
    build: (v) => {
      const parsed = parseMastodonTag(v);
      return parsed ? mastodonTagFeed(parsed.instanceUrl, parsed.hashtag) : null;
    },
  },
];

/** The sources that have no link to paste: pick one, type one thing. */
export function NoLinkView({
  categories,
  onBack,
  onAdded,
}: {
  categories: Category[] | undefined;
  onBack: () => void;
  onAdded: (feed: Feed) => void;
}) {
  const [picked, setPicked] = useState(0);
  const [value, setValue] = useState("");
  const [chosenFolder, setChosenFolder] = useState("");
  const addFeed = useAddFeed();

  const source = SOURCES[picked];
  const { data: suggested } = useCategorySuggestion(source.feedType);
  const categoryId = chosenFolder || suggested || "";
  const body = source.build(value);
  const needsFolder = (categories?.length ?? 0) > 0 && !categoryId;
  const showHint = value.trim() !== "" && body === null;

  const subscribe = async () => {
    if (!body || needsFolder) return;
    try {
      const feed = await addFeed.mutateAsync({ ...body, ...(categoryId ? { category_id: categoryId } : {}) });
      onAdded(feed);
    } catch {
      // the mutation's toast says why
    }
  };

  return (
    <>
      <div className={styles.body}>
        <div className={styles.sourceList} role="radiogroup" aria-label="Source">
          {SOURCES.map((s, i) => (
            <button
              key={s.name}
              type="button"
              role="radio"
              aria-checked={picked === i}
              className={`${styles.sourceOption} ${picked === i ? styles.sourceOptionOn : ""}`}
              onClick={() => {
                setPicked(i);
                setValue("");
              }}
            >
              <span className={styles.sourceName}>{s.name}</span>
              <span className={styles.sourceDetail}>{s.detail}</span>
            </button>
          ))}
        </div>
        <input
          aria-label={source.label}
          className={styles.textInput}
          placeholder={source.placeholder}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void subscribe();
          }}
        />
        {showHint && <p className={styles.error}>Write it as #tag on server, e.g. #threatintel on infosec.exchange.</p>}
        <FolderField categories={categories} value={categoryId} onChange={setChosenFolder} />
      </div>
      <div className={styles.footer}>
        <button type="button" className={styles.back} onClick={onBack}>
          Back
        </button>
        <button
          type="button"
          className={styles.cta}
          disabled={!body || needsFolder || addFeed.isPending}
          onClick={() => void subscribe()}
        >
          {addFeed.isPending ? "Subscribing…" : "Subscribe"}
        </button>
      </div>
    </>
  );
}
