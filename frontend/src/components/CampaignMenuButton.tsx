import { useState, useRef, useEffect } from "react";
import { useCampaigns, useCampaignsForEntry, useAddCampaignEntry, useCreateCampaign } from "@/hooks/useCampaigns";
import styles from "./WorkbenchPanel.module.css";

interface CampaignMenuButtonProps {
  entryId: string;
  /** Trigger button class — defaults to the intel action-bar accent button. */
  buttonClassName?: string;
  /** Trigger button content — defaults to "+ Campaign". */
  children?: React.ReactNode;
  title?: string;
}

/**
 * "+ Campaign" button with its add-to-campaign dropdown (existing campaigns,
 * inline create). Shared between the Intel panel action bar and the AI panel's
 * suggested actions.
 */
export function CampaignMenuButton({ entryId, buttonClassName, children, title }: CampaignMenuButtonProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const [flash, setFlash] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const dropdownRef = useRef<HTMLDivElement>(null);
  const { data: campaignsData } = useCampaigns({ limit: 100 });
  const { data: entryCampaignIds } = useCampaignsForEntry(entryId);
  const addToCampaign = useAddCampaignEntry();
  const createCampaign = useCreateCampaign();

  useEffect(() => {
    if (!menuOpen) return;
    const handleClick = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
        setCreating(false);
      }
    };
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [menuOpen]);

  const handleAdd = (campaignId: string, campaignName: string) => {
    addToCampaign.mutate(
      { campaignId, entryId },
      {
        onSuccess: () => {
          setFlash(`Added to ${campaignName}`);
          setTimeout(() => setFlash(null), 2000);
          setMenuOpen(false);
        },
        onError: () => {
          setFlash("Failed to add");
          setTimeout(() => setFlash(null), 2000);
        },
      }
    );
  };

  const handleCreateAndAdd = () => {
    if (!newName.trim()) return;
    createCampaign.mutate(
      { name: newName.trim() },
      {
        onSuccess: (campaign) => {
          setNewName("");
          setCreating(false);
          handleAdd(campaign.id, campaign.name);
        },
      }
    );
  };

  return (
    <div style={{ position: "relative" }} ref={dropdownRef}>
      <button
        className={buttonClassName ?? `${styles.actionBtn} ${styles.actionBtnAccent}`}
        onClick={() => setMenuOpen((o) => !o)}
        title={title ?? "Add this article to a campaign"}
      >
        {children ?? "+ Campaign"}
      </button>
      {flash && <div className={styles.campaignFlash}>{flash}</div>}
      {menuOpen && (
        <div className={styles.campaignDropdown}>
          {campaignsData?.items?.length ? (
            campaignsData.items.map((c) => {
              const alreadyAdded = entryCampaignIds?.includes(c.id);
              return (
                <button
                  key={c.id}
                  className={`${styles.campaignOption} ${alreadyAdded ? styles.campaignOptionAdded : ""}`}
                  onClick={() => {
                    if (!alreadyAdded) handleAdd(c.id, c.name);
                  }}
                  disabled={alreadyAdded}
                >
                  {alreadyAdded && <span className={styles.campaignCheck}>&#10003;</span>}
                  {c.name}
                </button>
              );
            })
          ) : (
            <span className={styles.campaignOption} style={{ opacity: 0.5 }}>No campaigns yet</span>
          )}
          <div className={styles.campaignDivider} />
          {creating ? (
            <div className={styles.campaignCreateRow}>
              <input
                className={styles.campaignCreateInput}
                placeholder="Campaign name..."
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleCreateAndAdd();
                  if (e.key === "Escape") setCreating(false);
                }}
                autoFocus
              />
              <button
                className={styles.campaignCreateBtn}
                onClick={handleCreateAndAdd}
                disabled={!newName.trim() || createCampaign.isPending}
              >
                {createCampaign.isPending ? "..." : "Add"}
              </button>
            </div>
          ) : (
            <button className={styles.campaignOption} onClick={() => setCreating(true)}>
              + New Campaign
            </button>
          )}
        </div>
      )}
    </div>
  );
}
