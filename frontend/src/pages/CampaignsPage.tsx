import { useState, useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import {
  useCampaigns,
  useCreateCampaign,
  useAutoDetectCampaigns,
} from "@/hooks/useCampaigns";
import type { CampaignCandidate } from "@/hooks/useCampaigns";
import { daysQuiet, isCampaignQuiet } from "@/utils/campaignActivity";
import CreateCampaignModal from "@/components/CreateCampaignModal";
import { getTLPColor } from "@/utils/colorSchemes";
import type { Campaign } from "@/api/types";
import { Chip, PageHeader } from "@/components/primitives";
import { DataTable, type DataTableColumn as ColumnDef, type SortDir } from "@/components/table/DataTable";
import { NameCell, MetaCell, NumCell, DateCell } from "@/components/table/cells";
import { STATUS_OPTIONS, TLP_OPTIONS } from "@/components/CreateCampaignModal";
import styles from "./CampaignsPage.module.css";
import workbench from "./WorkbenchPage.module.css";


const CAMPAIGN_COLUMNS: ColumnDef<Campaign>[] = [
  {
    key: "name", label: "Name", width: 260, minWidth: 140, flex: true,
    serverSort: true, textValue: (c) => c.name,
    render: (c) => <NameCell value={c.name} />,
  },
  {
    key: "status", label: "Status", width: 120, minWidth: 90,
    textValue: (c) => c.status,
    choices: [{ value: "all", label: "Any status" }, ...STATUS_OPTIONS.map((s) => ({ value: s, label: s }))],
    choiceMatch: (c, v) => c.status === v,
    // "active" on a campaign nobody has added to since May is a lie the column
    // was telling. Folded in here rather than given a column of its own.
    render: (c) => {
      const quiet = daysQuiet(c.last_activity_at);
      const stale = isCampaignQuiet(c.status, c.last_activity_at);
      return (
        <span className={styles.statusCell}>
          <Chip className={styles.statusTag}>{c.status}</Chip>
          {stale && <span className={styles.quietTag}>quiet {quiet}d</span>}
        </span>
      );
    },
  },
  {
    key: "tlp_marking", label: "TLP", width: 130, minWidth: 100,
    textValue: (c) => c.tlp_marking,
    choices: [{ value: "all", label: "Any TLP" }, ...TLP_OPTIONS.map((t) => ({ value: t, label: t }))],
    choiceMatch: (c, v) => c.tlp_marking === v,
    render: (c) => <TLPBadge tlp={c.tlp_marking} />,
  },
  {
    key: "entry_count", label: "Entries", width: 90, minWidth: 70,
    numValue: (c) => c.entry_count,
    render: (c) => <NumCell value={c.entry_count} />,
  },
  {
    key: "entity_count", label: "Entities", width: 90, minWidth: 70, hideable: true,
    numValue: (c) => c.entity_count,
    render: (c) => <NumCell value={c.entity_count} />,
  },
  {
    key: "tags", label: "Tags", width: 180, minWidth: 100, hideable: true, defaultHidden: true,
    textValue: (c) => c.tags.join(", "),
    render: (c) => <MetaCell value={c.tags.join(", ")} />,
  },
  {
    // Nothing sets start_date, so this column was empty on every row. A campaign
    // that declared a start shows it; one that didn't shows when its coverage
    // actually begins, which is the honest answer to "started".
    key: "start_date", label: "Started", width: 110, minWidth: 90, hideable: true, defaultHidden: true,
    sortValue: (c) => c.start_date ?? c.first_activity_at ?? "",
    render: (c) => <DateCell value={c.start_date ?? c.first_activity_at ?? null} />,
  },
  {
    key: "updated_at", label: "Updated", width: 110, minWidth: 90, hideable: true,
    serverSort: true,
    render: (c) => <DateCell value={c.updated_at} />,
  },
];

export function CampaignsPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [showCreate, setShowCreate] = useState(false);
  const [showAutoDetect, setShowAutoDetect] = useState(false);
  const [sort, setSort] = useState<{ key: string; dir: SortDir }>({ key: "name", dir: "asc" });
  const { data: campaignsData, isLoading } = useCampaigns({
    limit: 200,
    sort_by: sort.key,
    sort_order: sort.dir,
  });

  useEffect(() => {
    if (searchParams.get("create") === "true") {
      setShowCreate(true);
      setSearchParams({}, { replace: true });
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const campaigns = campaignsData?.items || [];

  return (
    <div className={styles.page}>
      <div className={styles.listPanel}>
        {/* Same treatment as every other entity table: no count in the header
            (DataTable's own bar reports "N loaded · M total" just below), and
            the shared workbench button classes rather than bespoke ones. */}
        <PageHeader
          title="Campaigns"
          actions={
            <>
              <button
                className={`${workbench.btn} ${workbench.btnAI}`}
                onClick={() => setShowAutoDetect(true)}
                title="Let the AI propose campaigns from recent coverage"
              >
                ✦ Discover
              </button>
              <button className={`${workbench.btn} ${workbench.btnPrimary}`} onClick={() => setShowCreate(true)}>
                + New
              </button>
            </>
          }
        />
        <DataTable<Campaign>
          tableId="campaigns"
          columns={CAMPAIGN_COLUMNS}
          rows={campaigns}
          getRowId={(c) => c.id}
          onRowClick={(c) => navigate(`/workbench/campaign/${c.id}`)}
          sort={sort}
          onSortChange={setSort}
          isLoading={isLoading}
          totalCount={campaignsData?.total}
          noun="campaign"
          emptyMessage="No campaigns yet. Create one to start tracking threat campaigns."
        />
      </div>

      {showCreate && (
        <CreateCampaignModal
          onClose={() => setShowCreate(false)}
          onCreated={(id) => navigate(`/workbench/campaign/${id}`)}
        />
      )}

      {showAutoDetect && (
        <AutoDetectModal
          onClose={() => setShowAutoDetect(false)}
          onCreated={(id) => { setShowAutoDetect(false); navigate(`/workbench/campaign/${id}`); }}
        />
      )}
    </div>
  );
}

function TLPBadge({ tlp }: { tlp: string }) {
  // `outline` paints the tint on both the text and the border over the page
  // ground — the same two properties this set inline before, so the rendered
  // foreground (and its contrast) is unchanged.
  return (
    <Chip tone="outline" tint={getTLPColor(tlp, "#888")}>
      {tlp}
    </Chip>
  );
}

function AutoDetectModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (id: string) => void;
}) {
  const autoDetect = useAutoDetectCampaigns();
  const createCampaign = useCreateCampaign();
  const [hasRun, setHasRun] = useState(false);

  const handleDiscover = () => {
    autoDetect.mutate({ limit: 30, days: 90 }, { onSuccess: () => setHasRun(true) });
  };

  const handleCreate = (suggestion: CampaignCandidate) => {
    createCampaign.mutate(
      {
        name: suggestion.suggested_name,
        entry_ids: suggestion.entry_ids,
        pivot_entity: { type: suggestion.pivot_entity.type, id: suggestion.pivot_entity.id },
      },
      {
        onSuccess: (campaign) => {
          toast.success(`Campaign "${suggestion.suggested_name}" created with ${suggestion.entry_ids.length} entries`);
          onCreated(campaign.id);
        },
        onError: () => toast.error("Failed to create campaign"),
      }
    );
  };

  return (
    <div className={styles.modalOverlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div className={styles.modalHeader}>
          <h3>Discover Campaigns</h3>
          <button className={styles.modalClose} onClick={onClose}>&times;</button>
        </div>
        <div className={styles.modalBody}>
          {!hasRun && (
            <div className={styles.modalCenter}>
              <p className={styles.modalDesc}>
                Look for actors and malware carrying more than one story, or one that kept moving.
              </p>
              <button
                className={styles.createBtn}
                onClick={handleDiscover}
                disabled={autoDetect.isPending}
              >
                {autoDetect.isPending ? "Analyzing..." : "Run Discovery"}
              </button>
            </div>
          )}

          {hasRun && autoDetect.data && autoDetect.data.length === 0 && (
            <div className={styles.placeholder}>
              No campaign candidates found. Try again after more entries have been processed.
            </div>
          )}

          {hasRun && autoDetect.data && autoDetect.data.length > 0 && (
            <div className={styles.suggestionList}>
              {autoDetect.data.map((s, i) => (
                <div key={i} className={styles.autoDetectRow}>
                  <div className={styles.autoDetectInfo}>
                    <div className={styles.suggestionTitle}>{s.suggested_name}</div>
                    <div className={styles.suggestionMeta}>
                      <span className={styles.overlapBadge}>{s.pivot_entity.type}: {s.pivot_entity.name}</span>
                      {s.evidence === "story_threads" ? (
                        <span>
                          {s.thread_count} {s.thread_count === 1 ? "story" : "stories"}
                          {(s.span_days ?? 0) > 0 && ` over ${s.span_days} days`}
                          {" \u00b7 "}{s.entry_count} entries
                        </span>
                      ) : (
                        <span>{s.entry_count} entries</span>
                      )}
                    </div>
                    {/* Threads are the evidence, so they replace the sample
                        headlines: three article titles from one story say less
                        than "this ran three separate times". */}
                    {s.threads && s.threads.length > 0 ? (
                      <div className={styles.sampleEntries}>
                        {s.threads.slice(0, 3).map((t) => (
                          <div key={t.slug} className={styles.sampleEntry}>
                            {t.entry_count} · {t.title}
                          </div>
                        ))}
                        {s.threads.length > 3 && (
                          <div className={styles.sampleEntry}>+{s.threads.length - 3} more</div>
                        )}
                      </div>
                    ) : (
                      s.sample_entries.length > 0 && (
                        <div className={styles.sampleEntries}>
                          {s.sample_entries.slice(0, 3).map((e) => (
                            <div key={e.id} className={styles.sampleEntry}>{e.title}</div>
                          ))}
                        </div>
                      )
                    )}
                    {(s.wider_entry_count ?? 0) > s.entry_count && (
                      <div className={styles.widerHint}>
                        {s.wider_entry_count} entries mention {s.pivot_entity.name} — the rest wait in Suggestions
                      </div>
                    )}
                  </div>
                  <button
                    className={styles.createBtn}
                    onClick={() => handleCreate(s)}
                    disabled={createCampaign.isPending}
                  >
                    Create
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
