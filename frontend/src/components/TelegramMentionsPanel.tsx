import { useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  useDismissTelegramMention,
  useSubscribeToTelegramMention,
  useTelegramMentionDetail,
  useTelegramMentions,
  useUndismissTelegramMention,
  type TelegramMention,
} from "@/hooks/useTelegram";
import { Chip, PageHeader } from "@/components/primitives";
import { DataTable, type DataTableColumn, type SortDir } from "@/components/table/DataTable";
import { MetaCell, NumCell, DateCell, LinkCell, ActionsCell, RowActionButton } from "@/components/table/cells";
import table from "@/components/table/DataTable.module.css";
import { formatDate } from "@/utils/formatDate";
import styles from "./TelegramMentionsPanel.module.css";

type SortKey = "last_seen" | "first_seen" | "mentions" | "feeds";

/** The four columns the API can order by, keyed by their DataTable column. */
const SERVER_SORT: Record<string, SortKey> = {
  last_seen_at: "last_seen",
  first_seen_at: "first_seen",
  mention_count: "mentions",
  distinct_feed_count: "feeds",
};

export function TelegramMentionsPanel() {
  const [onlyUnsubscribed, setOnlyUnsubscribed] = useState(true);
  const [includeDismissed, setIncludeDismissed] = useState(false);
  const [sort, setSort] = useState<{ key: string; dir: SortDir }>({ key: "last_seen_at", dir: "desc" });
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const qc = useQueryClient();
  const mentions = useTelegramMentions({
    only_unsubscribed: onlyUnsubscribed,
    only_active: !includeDismissed,
    sort: SERVER_SORT[sort.key] ?? "last_seen",
    limit: 200,
  });
  const detail = useTelegramMentionDetail(selectedId);
  const subscribe = useSubscribeToTelegramMention();
  const dismiss = useDismissTelegramMention();
  const undismiss = useUndismissTelegramMention();

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["telegram-mentions"] });
    if (selectedId) {
      qc.invalidateQueries({ queryKey: ["telegram-mention-detail", selectedId] });
    }
  };

  // Rebuilt when a mutation's pending state flips, so an in-flight action
  // can't be fired twice from the row.
  const columns: DataTableColumn<TelegramMention>[] = useMemo(() => [
    {
      key: "handle", label: "Channel", width: 220, minWidth: 130, flex: true,
      textValue: (m) => m.display_handle ?? m.handle,
      sortValue: (m) => (m.display_handle ?? m.handle).toLowerCase(),
      render: (m) => (
        <LinkCell href={m.canonical_url} label={`@${m.display_handle ?? m.handle}`} />
      ),
    },
    {
      key: "mention_count", serverSort: true, label: "Mentions", width: 90, minWidth: 74,
      numValue: (m) => m.mention_count,
      render: (m) => <NumCell value={m.mention_count} />,
    },
    {
      key: "distinct_feed_count", serverSort: true, label: "Feeds", width: 80, minWidth: 68,
      numValue: (m) => m.distinct_feed_count,
      render: (m) => <NumCell value={m.distinct_feed_count} />,
    },
    {
      key: "last_seen_at", serverSort: true, label: "Last seen", width: 110, minWidth: 90,
      sortValue: (m) => m.last_seen_at ?? "",
      render: (m) => <DateCell value={m.last_seen_at} />,
    },
    {
      key: "first_seen_at", serverSort: true, label: "First seen", width: 110, minWidth: 90, hideable: true, defaultHidden: true,
      sortValue: (m) => m.first_seen_at ?? "",
      render: (m) => <DateCell value={m.first_seen_at} />,
    },
    {
      key: "primary_link_type", label: "Type", width: 110, minWidth: 88, hideable: true,
      sortValue: (m) => m.primary_link_type,
      choices: [
        { value: "all", label: "Any type" },
        { value: "channel", label: "Channel" },
        { value: "invite", label: "Invite" },
        { value: "message", label: "Message" },
      ],
      choiceMatch: (m, v) => m.primary_link_type === v,
      render: (m) => <MetaCell value={m.primary_link_type} />,
    },
    {
      key: "status", label: "Status", width: 110, minWidth: 90,
      sortValue: (m) => (m.is_subscribed ? 0 : m.is_dismissed ? 2 : 1),
      choices: [
        { value: "all", label: "Any status" },
        { value: "new", label: "New" },
        { value: "subscribed", label: "Subscribed" },
        { value: "dismissed", label: "Dismissed" },
      ],
      choiceMatch: (m, v) =>
        v === "subscribed" ? m.is_subscribed : v === "dismissed" ? m.is_dismissed : !m.is_subscribed && !m.is_dismissed,
      render: (m) =>
        m.is_subscribed ? (
          <Chip tone="toned" tint="var(--success)">subscribed</Chip>
        ) : m.is_dismissed ? (
          <Chip tone="toned" tint="var(--text-muted)">dismissed</Chip>
        ) : (
          <Chip tone="toned" tint="var(--accent-intel)">new</Chip>
        ),
    },
    {
      key: "actions", label: "", width: 160, minWidth: 160, sticky: "right",
      render: (m) => (
        <ActionsCell>
          {!m.is_subscribed && !m.handle.startsWith("invite:") && (
            <RowActionButton onClick={() => handleSubscribe(m)} disabled={subscribe.isPending}>
              Subscribe
            </RowActionButton>
          )}
          <RowActionButton onClick={() => handleDismiss(m)}>
            {m.is_dismissed ? "Restore" : "Dismiss"}
          </RowActionButton>
        </ActionsCell>
      ),
    },
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [subscribe.isPending, dismiss.isPending, undismiss.isPending]);

  const handleSubscribe = async (m: TelegramMention) => {
    try {
      await subscribe.mutateAsync(m.id);
      refresh();
    } catch (e) {
      console.warn("subscribe failed", e);
    }
  };

  const handleDismiss = async (m: TelegramMention) => {
    if (m.is_dismissed) {
      await undismiss.mutateAsync(m.id);
    } else {
      await dismiss.mutateAsync(m.id);
    }
    refresh();
  };

  return (
    <div className={styles.root}>
      <PageHeader
        title="Telegram Mentions"
        count={mentions.data?.items.length}
        subtitle="Telegram channels auto-extracted from t.me / tg:// links in ingested content."
        controls={
          <>
            <label className={styles.controlLabel}>
              <input
                type="checkbox"
                checked={onlyUnsubscribed}
                onChange={(e) => setOnlyUnsubscribed(e.target.checked)}
              />
              Only unsubscribed
            </label>
            <label className={styles.controlLabel}>
              <input
                type="checkbox"
                checked={includeDismissed}
                onChange={(e) => setIncludeDismissed(e.target.checked)}
              />
              Include dismissed
            </label>
          </>
        }
      />

      <div className={styles.body}>
        <div className={styles.tablePane}>
          <DataTable<TelegramMention>
            tableId="telegram-mentions"
            columns={columns}
            rows={mentions.data?.items ?? []}
            getRowId={(m) => m.id}
            activeRowId={selectedId}
            rowClass={(m) => (m.is_dismissed ? table.rowMuted : undefined)}
            onRowClick={(m) => setSelectedId(m.id)}
            sort={sort}
            onSortChange={setSort}
            totalCount={mentions.data?.total}
            isLoading={mentions.isLoading}
            noun="channel"
            emptyMessage={
              mentions.isError
                ? "Failed to load telegram mentions."
                : `No Telegram channels have been mentioned in your ingested content yet${
                    onlyUnsubscribed ? " (or all of them are already subscribed)." : "."
                  }`
            }
          />
        </div>

        <div className={styles.detail}>
          {!selectedId && (
            <p className={styles.muted}>
              Select a channel on the left to see where it was mentioned.
            </p>
          )}
          {selectedId && detail.isLoading && <p className={styles.muted}>Loading details…</p>}
          {selectedId && detail.data && (
            <div>
              <h3 className={styles.detailHeading}>
                <a
                  href={detail.data.canonical_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={styles.link}
                >
                  @{detail.data.display_handle ?? detail.data.handle}
                </a>
              </h3>
              <div className={styles.detailMeta}>
                {detail.data.mention_count} mentions across{" "}
                {detail.data.distinct_feed_count} feeds. First seen{" "}
                {detail.data.first_seen_at ? formatDate(detail.data.first_seen_at) : "—"}.
              </div>
              {subscribe.isError && (
                <p className={styles.error}>
                  Subscribe failed —{" "}
                  {(subscribe.error as Error & { response?: { data?: { detail?: { message?: string } } } })
                    ?.response?.data?.detail?.message ?? "see console"}
                </p>
              )}

              <div className={styles.sampleHeader}>Recent mentions</div>
              {detail.data.samples.length === 0 && (
                <p className={styles.muted}>No samples available.</p>
              )}
              <ul className={styles.sampleList}>
                {detail.data.samples.map((s) => (
                  <li key={s.link_id} className={styles.sampleItem}>
                    <div>
                      <a
                        href={s.entry.url ?? "#"}
                        target="_blank"
                        rel="noopener noreferrer"
                        className={styles.link}
                      >
                        {s.entry.title ?? "(untitled)"}
                      </a>
                    </div>
                    <div className={styles.sampleMeta}>
                      <span>{s.feed?.title ?? "(no feed)"}</span>
                      <span>·</span>
                      <span>
                        {s.entry.published_at ? formatDate(s.entry.published_at) : "—"}
                      </span>
                      <span>·</span>
                      <Chip size="sm" className={styles.tag}>
                        {s.link_type}
                      </Chip>
                      <a
                        href={s.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className={styles.link}
                      >
                        link
                      </a>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
