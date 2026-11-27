import { useState } from "react";
import { toast } from "sonner";
import { useImportStarterPackFeeds, useStarterPackFeeds, useStarterPacks } from "@/hooks/useFeeds";
import type { StarterPack } from "@/api/types";
import styles from "../AddFeedModal.module.css";

function Chevron({ open }: { open: boolean }) {
  return (
    <svg className={styles.chevron} width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <path d={open ? "M3 7.5l3-3 3 3" : "M3 4.5l3 3 3-3"} />
    </svg>
  );
}

function countLabel(pack: StarterPack): string {
  const followed = pack.followed_count ?? 0;
  return followed > 0 ? `Following ${followed} of ${pack.feed_count}` : `${pack.feed_count} sources`;
}

/**
 * The curated packs as a plain list. One pack opens at a time; its feeds come
 * ticked, the ones already followed greyed out, and "Add N" adds the ticked
 * rest.
 */
export function PacksView({ onBack, onDone }: { onBack: () => void; onDone: () => void }) {
  const { data: packs, isLoading } = useStarterPacks();
  const [openId, setOpenId] = useState<string | null>(null);
  // Feeds the user unticked in the open pack; everything else is ticked.
  const [unticked, setUnticked] = useState<Set<string>>(new Set());
  const { data: feeds, isLoading: feedsLoading } = useStarterPackFeeds(openId);
  const importFeeds = useImportStarterPackFeeds();

  const toAdd = (feeds ?? []).filter((f) => !f.followed && !unticked.has(f.url));

  const toggle = (url: string) => {
    setUnticked((prev) => {
      const next = new Set(prev);
      if (next.has(url)) next.delete(url);
      else next.add(url);
      return next;
    });
  };

  const add = async () => {
    if (!openId || toAdd.length === 0) return;
    try {
      const result = await importFeeds.mutateAsync({ packId: openId, urls: toAdd.map((f) => f.url) });
      toast.success(
        `Added ${result.feeds_added} feed${result.feeds_added === 1 ? "" : "s"}. Their first articles are on the way.`
      );
      onDone();
    } catch {
      // the mutation's toast says why
    }
  };

  return (
    <>
      <div className={styles.body}>
        {isLoading && <span className={styles.status}>Loading packs…</span>}
        <div className={styles.packs}>
          {(packs ?? []).map((pack) => {
            const open = openId === pack.id;
            return (
              <div key={pack.id} className={styles.pack}>
                <button
                  type="button"
                  className={styles.packHead}
                  aria-expanded={open}
                  onClick={() => {
                    setOpenId(open ? null : pack.id);
                    setUnticked(new Set());
                  }}
                >
                  <span className={styles.packTitle}>{pack.title}</span>
                  <span className={`${styles.packCount} ${pack.followed_count ? styles.packCountFollowing : ""}`}>
                    {countLabel(pack)}
                  </span>
                  <Chevron open={open} />
                </button>
                {open && (
                  <div className={styles.packFeeds}>
                    {pack.requires && <span className={styles.packNote}>Needs {pack.requires}.</span>}
                    {feedsLoading && <span className={styles.packNote}>Loading…</span>}
                    {(feeds ?? []).map((feed) => (
                      <label
                        key={feed.url}
                        className={`${styles.packFeed} ${feed.followed ? styles.packFeedFollowed : ""}`}
                        title={feed.followed ? "Already following" : feed.title}
                      >
                        <input
                          type="checkbox"
                          checked={feed.followed || !unticked.has(feed.url)}
                          disabled={feed.followed}
                          onChange={() => toggle(feed.url)}
                        />
                        <span className={styles.packFeedName}>{feed.title}</span>
                      </label>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
      <div className={styles.footer}>
        <button type="button" className={styles.back} onClick={onBack}>
          Back
        </button>
        <button
          type="button"
          className={styles.cta}
          disabled={!openId || toAdd.length === 0 || importFeeds.isPending}
          onClick={() => void add()}
        >
          {importFeeds.isPending ? "Adding…" : openId && toAdd.length ? `Add ${toAdd.length}` : "Pick a pack"}
        </button>
      </div>
    </>
  );
}
