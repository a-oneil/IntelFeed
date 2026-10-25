import { useState } from "react";
import { toast } from "sonner";
import { useFeedAIUsage, useUpdateFeed } from "@/hooks/useFeeds";
import type { Feed } from "@/api/types";
import styles from "../fields.module.css";

/** 804000 → "804k", 8_040_000 → "8.0M". */
export function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${Math.round(n / 1_000)}k`;
  return String(n);
}

/**
 * What a muted feed still costs.
 *
 * Mute only hides a feed from reading views; every article is still tagged,
 * analysed and scored. That is deliberate — once subscriptions are per-user,
 * one reader muting a feed must not switch the AI off for everyone — so this
 * shows the cost instead and leaves turning the AI off as a separate,
 * explicit admin decision.
 */
export function MutedAIUsage({ feed, isAdmin }: { feed: Feed; isAdmin: boolean }) {
  const usage = useFeedAIUsage(feed.id, feed.is_muted);
  const updateFeed = useUpdateFeed();
  const [turnedOff, setTurnedOff] = useState(false);

  if (!feed.is_muted || !usage.data) return null;
  const u = usage.data;
  const aiOn = u.ai_analysis_enabled && !turnedOff;

  const turnOff = () =>
    updateFeed.mutate(
      { feedId: feed.id, data: { ai_analysis_enabled: false } },
      {
        onSuccess: () => {
          setTurnedOff(true);
          toast.success("AI analysis is off for this feed");
        },
      }
    );

  return (
    <div className={`${styles.banner} ${styles.bannerWarn}`}>
      <p className={styles.note}>
        {aiOn
          ? u.runs > 0
            ? `Muted, but still analysed: ${u.runs} AI ${u.runs === 1 ? "run" : "runs"} and ${formatTokens(
                u.tokens_input + u.tokens_output
              )} tokens in the last ${u.days} days.`
            : `Muted, and no AI runs in the last ${u.days} days — but new articles are still analysed.`
          : `Muted, and AI analysis is off for this feed. ${
              u.runs > 0 ? `${u.runs} AI runs in the last ${u.days} days.` : ""
            }`.trim()}{" "}
        Muting only hides a feed from your reading views; it does not stop the pipeline.
      </p>
      {aiOn && isAdmin && (
        <div className={styles.actionRow}>
          <button
            type="button"
            className={styles.actionBtn}
            onClick={turnOff}
            disabled={updateFeed.isPending}
          >
            {updateFeed.isPending ? "Turning off…" : "Turn off AI for this feed"}
          </button>
        </div>
      )}
    </div>
  );
}
