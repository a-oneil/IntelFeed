import { useState, useRef, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useCampaigns, useAddCampaignEntity } from "@/hooks/useCampaigns";
import { useUnlinkEntity } from "@/hooks/useIntelligence";
import { useUIStore } from "@/stores/uiStore";
import { getEntityColor, getEntityLabel } from "@/utils/entityTheme";
import styles from "./EntityActionMenu.module.css";

export interface EntityActionTarget {
  id: string;
  type:
    | "cve"
    | "ttp"
    | "threat_actor"
    | "malware"
    | "country"
    | "mitigation"
    | "tool"
    | "vendor"
    | "product";
  value: string;
  /** Optional sub-type qualifier */
  subType?: string;
  /** Entry ID this entity was extracted from */
  entryId?: string;
}

// Backend CampaignEntityAdd schema only accepts these four — see backend/app/schemas/campaign.py
const CAMPAIGN_SUPPORTED_TYPES = new Set(["ttp", "cve", "threat_actor", "malware"]);

interface EntityActionMenuProps {
  entity: EntityActionTarget;
  onCreateRule?: (entity: EntityActionTarget) => void;
}

const PROFILE_ROUTES: Record<string, string> = {
  cve: "/workbench/cve",
  ttp: "/workbench/ttp",
  threat_actor: "/workbench/threat_actor",
  malware: "/workbench/malware",
  country: "/workbench/country",
  mitigation: "/workbench/mitigation",
  tool: "/workbench/tool",
  vendor: "/workbench/vendor",
  product: "/workbench/product",
};

export default function EntityActionMenu({
  entity,
  onCreateRule,
}: EntityActionMenuProps) {
  const [open, setOpen] = useState(false);
  const [showCampaigns, setShowCampaigns] = useState(false);
  const [copied, setCopied] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const [menuPos, setMenuPos] = useState<{ top: number; left: number } | null>(null);
  const navigate = useNavigate();
  const setHeaderSearchQuery = useUIStore((s) => s.setHeaderSearchQuery);

  const { data: campaignsData } = useCampaigns(
    showCampaigns ? { limit: 20 } : undefined
  );
  const addEntity = useAddCampaignEntity();
  const unlinkEntity = useUnlinkEntity();

  const close = useCallback(() => {
    setOpen(false);
    setShowCampaigns(false);
  }, []);

  useEffect(() => {
    if (!open) return;
    const handleClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        close();
      }
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
    };
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
    };
  }, [open, close]);

  const handleViewProfile = () => {
    const base = PROFILE_ROUTES[entity.type];
    if (base) navigate(`${base}/${entity.id}`);
    close();
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(entity.value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const handleCreateRule = () => {
    if (onCreateRule) {
      onCreateRule(entity);
    } else {
      // Navigate to rule builder in create mode
      const params = new URLSearchParams({
        entity_type: entity.type,
        entity_value: entity.value,
        ...(entity.entryId ? { entry_id: entity.entryId } : {}),
        ...(entity.subType ? { sub_type: entity.subType } : {}),
      });
      navigate(`/workbench/rule/new?${params.toString()}`);
    }
    close();
  };

  const handleAddToCampaign = (campaignId: string) => {
    addEntity.mutate({
      campaignId,
      entityType: entity.type,
      entityId: entity.id,
    });
    close();
  };

  const campaigns = campaignsData?.items || [];
  const accentColor = getEntityColor(entity.type);

  return (
    <div className={styles.wrapper} ref={menuRef}>
      <button
        ref={triggerRef}
        className={styles.trigger}
        onClick={(e) => {
          e.stopPropagation();
          if (!open && triggerRef.current) {
            const rect = triggerRef.current.getBoundingClientRect();
            setMenuPos({ top: rect.bottom + 2, left: rect.right });
          }
          setOpen(!open);
        }}
        title={`Actions for ${getEntityLabel(entity.type)}`}
        style={{ color: accentColor }}
      >
        &#x22EF;
      </button>

      {open && menuPos && (
        <div className={styles.menu} style={{ position: 'fixed', top: menuPos.top, left: 'auto', right: `calc(100vw - ${menuPos.left}px)` }}>
          <button className={styles.menuItem} onClick={handleViewProfile}>
            <span className={styles.menuIcon}>&#x2197;</span>
            View Profile
          </button>

          <button
            className={styles.menuItem}
            onClick={() => {
              setHeaderSearchQuery(entity.value);
              navigate("/search");
              close();
            }}
          >
            <span className={styles.menuIcon}>&#x1F50D;</span>
            Find in IntelFeed
          </button>

          {(entity.type === "ttp" ||
            entity.type === "cve") && (
            <button className={styles.menuItem} onClick={handleCreateRule}>
              <span
                className={styles.menuIcon}
                style={{ color: "var(--entity-rule)" }}
              >
                &#x2318;
              </span>
              Create Rule
            </button>
          )}

          {CAMPAIGN_SUPPORTED_TYPES.has(entity.type) && (
            <>
              <button
                className={styles.menuItem}
                onClick={() => setShowCampaigns(!showCampaigns)}
              >
                <span
                  className={styles.menuIcon}
                  style={{ color: "var(--entity-campaign)" }}
                >
                  &#x2B;
                </span>
                Add to Campaign
              </button>

              {showCampaigns && (
                <div className={styles.campaignList}>
                  {campaigns.length === 0 && (
                    <div className={styles.noCampaigns}>No campaigns yet</div>
                  )}
                  {campaigns.map((c) => (
                    <button
                      key={c.id}
                      className={styles.campaignItem}
                      onClick={() => handleAddToCampaign(c.id)}
                      disabled={addEntity.isPending}
                    >
                      {c.name}
                    </button>
                  ))}
                </div>
              )}
            </>
          )}

          <button className={styles.menuItem} onClick={handleCopy}>
            <span className={styles.menuIcon}>&#x2398;</span>
            {copied ? "Copied!" : "Copy"}
          </button>

          {entity.entryId && (
            <button
              className={`${styles.menuItem} ${styles.menuItemDanger}`}
              onClick={() => {
                if (confirm(`Unlink this ${getEntityLabel(entity.type)} from the article?`)) {
                  unlinkEntity.mutate({
                    entryId: entity.entryId!,
                    entityId: entity.id,
                    entityType: entity.type,
                  });
                  close();
                }
              }}
              disabled={unlinkEntity.isPending}
            >
              <span className={styles.menuIcon}>&#x2717;</span>
              {unlinkEntity.isPending ? "Unlinking..." : "Unlink"}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
