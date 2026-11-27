import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { useAddFeed, useCategories, useLinkPreview } from "@/hooks/useFeeds";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import { useAuthStore } from "@/stores/authStore";
import { apiErrorInfo } from "@/api/errors";
import type { Feed, LinkPreview } from "@/api/types";
import { FolderField } from "./addFeed/FolderField";
import { NoLinkView } from "./addFeed/NoLinkView";
import { OpmlView } from "./addFeed/OpmlView";
import { PacksView } from "./addFeed/PacksView";
import {
  GITHUB_PARTS,
  INTERVALS,
  defaultChoices,
  describePreview,
  feedOptionLabels,
  feedsToCreate,
  intervalLabel,
  looksLikeLink,
  type SourceChoices,
} from "./addFeed/sourcePlan";
import styles from "./AddFeedModal.module.css";

interface Props {
  onClose: () => void;
  /** Called with the new feed after a single-feed add, in place of onClose. */
  onAdded?: (feed: Feed) => void;
}

type View = "main" | "packs" | "nolink" | "opml";

const HEADINGS: Record<View, string> = {
  main: "Add a source",
  packs: "Starter packs",
  nolink: "Add without a link",
  opml: "Import OPML",
};

/** What the user changed for the link on screen; reset when the link changes. */
interface Edits {
  key: string;
  choices?: SourceChoices;
  folder?: string;
  interval?: number;
  name?: string;
}

/** Add a source. One box takes any link (a site, a feed, a YouTube channel, a GitHub repo, a Bluesky account or search, a Telegram channel, a Mastodon hashtag) and the server says what it is. The dialog then asks only what changes what arrives (at most a couple of choices), the folder, and optionally the interval and name. Everything else is in the feed's own settings, which the caller can open right after a single-feed add through `onAdded`. */
export function AddFeedModal({ onClose, onAdded }: Props) {
  const [view, setView] = useState<View>("main");
  const [link, setLink] = useState("");
  const settled = useDebouncedValue(link.trim(), 450);
  const query = looksLikeLink(settled) ? settled : "";
  const preview = useLinkPreview(query);
  const { data: categories } = useCategories();
  const addFeed = useAddFeed();
  const [busy, setBusy] = useState(false);
  const skipShortsDefault = useAuthStore((s) => s.user?.settings?.youtube_exclude_shorts_default !== false);
  const trapRef = useFocusTrap<HTMLDivElement>();
  const linkRef = useRef<HTMLInputElement>(null);

  // Declared after useFocusTrap so it runs second: the trap focuses the close button, and the paste box is where the user starts.
  useEffect(() => {
    if (view === "main") linkRef.current?.focus();
  }, [view]);

  const found: LinkPreview | null = query && preview.data ? preview.data : null;
  const key = found ? `${query}|${found.url}` : "";
  const [edits, setEdits] = useState<Edits>({ key: "" });
  const current: Edits = edits.key === key ? edits : { key };
  const update = (patch: Omit<Edits, "key">) => setEdits({ ...current, ...patch, key });

  const choices = found ? (current.choices ?? defaultChoices(found, skipShortsDefault)) : null;
  const setChoices = (patch: Partial<SourceChoices>) => choices && update({ choices: { ...choices, ...patch } });
  const folder = current.folder ?? found?.suggested_category_id ?? "";
  const interval = current.interval ?? found?.fetch_interval_minutes ?? 30;

  const typed = link.trim();
  const looking = looksLikeLink(typed) && (typed !== settled || preview.isFetching);
  const notALink = typed !== "" && typed === settled && !looksLikeLink(typed);
  const lookupError = query && preview.isError && !looking ? apiErrorInfo(preview.error).message : null;

  const planned = found && choices ? feedsToCreate(found, choices, {}) : [];
  const needsFolder = (categories?.length ?? 0) > 0 && !folder;
  const canSubscribe = !!found && planned.length > 0 && !needsFolder && !busy;

  const subscribe = async () => {
    if (!found || !choices || !canSubscribe) return;
    const bodies = feedsToCreate(found, choices, {
      categoryId: folder || undefined,
      interval: current.interval,
      name: current.name,
    });
    setBusy(true);
    const created: Feed[] = [];
    try {
      for (const body of bodies) created.push(await addFeed.mutateAsync(body));
    } catch {
      // the mutation's toast says why; keep whatever feeds were already created
    } finally {
      setBusy(false);
    }
    if (created.length === 1 && bodies.length === 1) {
      if (onAdded) onAdded(created[0]);
      else onClose();
    } else if (created.length > 0) {
      toast.success(`Added ${created.length} feeds for ${found.title}.`);
      onClose();
    }
  };

  const back = () => {
    setView("main");
    setLink("");
  };

  return (
    <div
      className={styles.overlay}
      onClick={onClose}
      onKeyDown={(e) => {
        if (e.key === "Escape") onClose();
      }}
    >
      <div
        className={styles.modal}
        onClick={(e) => e.stopPropagation()}
        ref={trapRef}
        role="dialog"
        aria-modal="true"
        aria-label={HEADINGS[view]}
      >
        <div className={styles.header}>
          <h2>{HEADINGS[view]}</h2>
          <button type="button" onClick={onClose} className={styles.closeBtn} aria-label="Close">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
              <path d="M3 3l10 10M13 3L3 13" />
            </svg>
          </button>
        </div>

        {view === "packs" && <PacksView onBack={back} onDone={onClose} />}
        {view === "opml" && <OpmlView onBack={back} onDone={onClose} />}
        {view === "nolink" && (
          <NoLinkView categories={categories} onBack={back} onAdded={(feed) => (onAdded ? onAdded(feed) : onClose())} />
        )}

        {view === "main" && (
          <>
            <div className={styles.body}>
              <input
                ref={linkRef}
                aria-label="Link"
                className={`${styles.linkInput} ${found ? styles.linkInputFound : ""}`}
                value={link}
                onChange={(e) => setLink(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && found) void subscribe();
                }}
                placeholder="Paste a link: a site, feed, YouTube channel, GitHub repo…"
              />

              {typed === "" && (
                <div className={styles.textLinks}>
                  <button type="button" className={styles.textLink} onClick={() => setView("packs")}>
                    Browse starter packs
                  </button>
                  <button type="button" className={styles.textLink} onClick={() => setView("opml")}>
                    Import OPML
                  </button>
                  <button type="button" className={styles.textLink} onClick={() => setView("nolink")}>
                    Add without a link
                  </button>
                </div>
              )}

              {looking && <span className={styles.status}>Looking at this link…</span>}
              {notALink && <p className={styles.error}>That doesn't look like a link.</p>}
              {lookupError && <p className={styles.error}>{lookupError}</p>}

              {found && choices && !looking && (
                <FoundSource
                  found={found}
                  choices={choices}
                  setChoices={setChoices}
                  folder={folder}
                  setFolder={(id) => update({ folder: id })}
                  interval={interval}
                  setInterval={(m) => update({ interval: m })}
                  name={current.name ?? ""}
                  setName={(n) => update({ name: n })}
                  categories={categories}
                />
              )}
            </div>

            {found && !looking && (
              <div className={styles.footer}>
                <button type="button" className={styles.back} onClick={back}>
                  Back
                </button>
                <button type="button" className={styles.cta} disabled={!canSubscribe} onClick={() => void subscribe()}>
                  {busy
                    ? "Subscribing…"
                    : found.kind === "page"
                      ? "Follow this page"
                      : planned.length > 1
                        ? `Subscribe to ${planned.length}`
                        : "Subscribe"}
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function FoundSource({
  found,
  choices,
  setChoices,
  folder,
  setFolder,
  interval,
  setInterval,
  name,
  setName,
  categories,
}: {
  found: LinkPreview;
  choices: SourceChoices;
  setChoices: (patch: Partial<SourceChoices>) => void;
  folder: string;
  setFolder: (id: string) => void;
  interval: number;
  setInterval: (minutes: number) => void;
  name: string;
  setName: (name: string) => void;
  categories: Parameters<typeof FolderField>[0]["categories"];
}) {
  const { mono, kind } = describePreview(found);
  const title = found.kind === "page" ? (found.page?.label ?? found.title) : found.title;
  const isYouTube = found.kind === "feed" && (found.feeds.find((f) => f.url === choices.feedUrl)?.feed_type ?? found.feed_type) === "youtube";
  const intervals = INTERVALS.some((i) => i.minutes === interval)
    ? INTERVALS
    : [...INTERVALS, { minutes: interval, label: intervalLabel(interval) }].sort((a, b) => a.minutes - b.minutes);

  return (
    <>
      <div className={styles.found}>
        <span className={styles.badge} aria-hidden="true">
          {mono}
        </span>
        <span className={styles.foundText}>
          <span className={styles.foundTitle}>{title}</span>
          <span className={styles.foundKind}>{kind}</span>
        </span>
      </div>

      {found.warning && <div className={styles.warning}>{found.warning}</div>}

      {found.kind === "feed" && found.feeds.length > 1 && (
        <div className={styles.choices} role="radiogroup" aria-label="Which feed">
          {feedOptionLabels(found).map((label, i) => (
            <label key={found.feeds[i].url} className={styles.check}>
              <input
                type="radio"
                name="add-feed-which"
                checked={choices.feedUrl === found.feeds[i].url}
                onChange={() => setChoices({ feedUrl: found.feeds[i].url })}
              />
              {label}
            </label>
          ))}
        </div>
      )}

      {isYouTube && (
        <label className={styles.check}>
          <input type="checkbox" checked={choices.skipShorts} onChange={(e) => setChoices({ skipShorts: e.target.checked })} />
          Skip Shorts
        </label>
      )}

      {found.kind === "github" && <GitHubChoices found={found} choices={choices} setChoices={setChoices} />}

      {found.kind === "bluesky" && (
        <label className={styles.check}>
          <input
            type="checkbox"
            checked={choices.includeReposts}
            onChange={(e) => setChoices({ includeReposts: e.target.checked })}
          />
          Include reposts
        </label>
      )}

      {found.kind === "page" && (
        <div className={styles.note}>
          This page has no feed. IntelFeed can read the page itself and pick up new articles.{" "}
          {found.page && found.page.article_links > 0
            ? `It found ${found.page.article_links} article link${found.page.article_links === 1 ? "" : "s"} on it.`
            : "It found no article links on it yet; you can tell it which links to follow in the feed's settings."}
        </div>
      )}

      <FolderField categories={categories} value={folder} onChange={setFolder} />

      <details className={styles.more}>
        <summary>More options</summary>
        <div className={styles.moreBody}>
          <div className={styles.row}>
            <label className={styles.rowLabel} htmlFor="add-feed-interval">
              Check
            </label>
            <select
              id="add-feed-interval"
              className={styles.field}
              value={interval}
              onChange={(e) => setInterval(Number(e.target.value))}
            >
              {intervals.map((i) => (
                <option key={i.minutes} value={i.minutes}>
                  {i.label}
                </option>
              ))}
            </select>
          </div>
          <div className={styles.row}>
            <label className={styles.rowLabel} htmlFor="add-feed-name">
              Name
            </label>
            <input
              id="add-feed-name"
              className={styles.field}
              value={name}
              placeholder={found.kind === "page" ? "Named after the page" : found.title}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <span>Everything else (rating, what runs on each article, filters) is in the feed's settings once it's added.</span>
        </div>
      </details>
    </>
  );
}

function GitHubChoices({
  found,
  choices,
  setChoices,
}: {
  found: LinkPreview;
  choices: SourceChoices;
  setChoices: (patch: Partial<SourceChoices>) => void;
}) {
  const rules = found.github?.rules ?? null;
  const where = rules
    ? rules.folders.filter(Boolean).length
      ? `under ${rules.folders.filter(Boolean).join(", ")}`
      : "in this repo"
    : "";
  return (
    <>
      {rules ? (
        <div className={styles.noteGood}>
          Found {rules.label} {where}. Changed rule files become detection rules automatically.
        </div>
      ) : (
        <div className={styles.noteMuted}>No detection rules in this repo. Pick what to follow.</div>
      )}
      <div className={`${styles.choices} ${styles.choicesWide}`} role="group" aria-label="What to follow">
        {GITHUB_PARTS.map((part) => (
          <div key={part.id} className={styles.choiceBlock}>
            <label className={styles.check}>
              <input
                type="checkbox"
                checked={choices.github[part.id]}
                onChange={(e) => setChoices({ github: { ...choices.github, [part.id]: e.target.checked } })}
              />
              <span>
                {part.label} <span className={styles.checkDetail}>{part.detail}</span>
              </span>
            </label>
            {part.id === "files" && choices.github.files && (
              <input
                aria-label="Paths to watch"
                className={`${styles.field} ${styles.pathsInput}`}
                value={choices.githubPaths}
                placeholder="All files, or paths like docs/** or *.yml"
                onChange={(e) => setChoices({ githubPaths: e.target.value })}
              />
            )}
          </div>
        ))}
      </div>
    </>
  );
}
