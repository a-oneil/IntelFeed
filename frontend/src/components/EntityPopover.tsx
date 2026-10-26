import { useEffect, useRef, useState, useLayoutEffect } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import type { HighlightEntity } from "./InlineEntityHighlighter";
import { getPivotLinks } from "@/utils/pivotLinks";
import { getEntityColor, getEntityLabel } from "@/utils/entityTheme";
import { getSeverityColor } from "@/utils/colorSchemes";
import { Chip } from "./primitives";
import { useEnrichEntity, useEnrichmentSources } from "@/hooks/useEnrichment";
import { useReportFalsePositive, type FalsePositiveScope } from "@/hooks/useFalsePositives";
import {
  useConvertEntity,
  useUnlinkAllEntries,
  MERGEABLE_ENTITY_TYPES,
} from "@/hooks/useEntityProfile";
import { EntityMergeIntoModal } from "./EntityMergeIntoModal";
import { useDenyObservable, useUnlinkEntity } from "@/hooks/useIntelligence";
import { convertTargetsFor, runEntityConvert } from "@/utils/entityConvert";
import { useAuthStore, useIsVisitor } from "@/stores/authStore";
import { useUIStore } from "@/stores/uiStore";
import { formatDate } from "@/utils/formatDate";
import styles from "./EntityPopover.module.css";
import { confirmDialog } from "@/utils/dialog";

function truncate(text: string, max: number): string {
  return text.length > max ? text.slice(0, max).trimEnd() + "…" : text;
}

interface EntityPopoverProps {
  entity: HighlightEntity;
  x: number;
  y: number;
  onClose: () => void;
  onNavigate: () => void;
  readOnly?: boolean;
  entryId?: string;
}

/** Clamp popover position so it stays within the viewport */
function useClampPosition(
  ref: React.RefObject<HTMLDivElement | null>,
  x: number,
  y: number,
) {
  const [pos, setPos] = useState({ left: x, top: y });

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) {
      setPos({ left: x, top: y });
      return;
    }

    const clamp = () => {
      const rect = el.getBoundingClientRect();
      const pad = 8;
      let left = x;
      let top = y;

      // Horizontal: popover is centered via translateX(-50%), so check half-widths
      const halfW = rect.width / 2;
      if (left - halfW < pad) left = halfW + pad;
      if (left + halfW > window.innerWidth - pad) left = window.innerWidth - halfW - pad;

      // Vertical: if it overflows bottom, flip above the target
      if (top + rect.height > window.innerHeight - pad) {
        // Place above: y was bottom+4 of target, so target bottom ≈ y-4
        top = y - 4 - rect.height - 4;
        if (top < pad) top = pad;
      }

      setPos({ left, top });
    };

    // Re-clamp whenever the popover's size changes — its content loads async
    // (entity metadata: aliases, article counts) and can push the card off-screen
    // after the initial measure. The Enrich / Wrong? dropdowns deliberately don't
    // count here: they're absolutely positioned, so opening one leaves the card's
    // box (and therefore its position) alone instead of flipping it up the page.
    // Repositioning only changes top/left, not size, so this can't feed back into
    // the observer.
    clamp();
    const ro = new ResizeObserver(clamp);
    ro.observe(el);
    return () => ro.disconnect();
  }, [ref, x, y]);

  return pos;
}

export function EntityPopover({
  entity,
  x,
  y,
  onClose,
  onNavigate,
  readOnly,
  entryId,
}: EntityPopoverProps) {
  // Public read-only mode: Profile and Copy only — Search is hidden for
  // visitors, and Enrich / Wrong? write.
  const isVisitor = useIsVisitor();
  const ref = useRef<HTMLDivElement>(null);
  const pos = useClampPosition(ref, x, y);
  const navigate = useNavigate();
  const setHeaderSearchQuery = useUIStore((s) => s.setHeaderSearchQuery);
  const [showEnrichMenu, setShowEnrichMenu] = useState(false);
  const [showFpMenu, setShowFpMenu] = useState(false);
  // Which way the dropdowns open. Decided when one is opened, from the room left
  // under the card — the card itself no longer moves to make space.
  const [menuUp, setMenuUp] = useState(false);
  const [showConvertMenu, setShowConvertMenu] = useState(false);
  const [mergeOpen, setMergeOpen] = useState(false);
  const [enrichStatus, setEnrichStatus] = useState<string | null>(null);
  const enrichEntity = useEnrichEntity();
  // Skip the authenticated sources fetch on public shared pages (no JWT → 401).
  const { data: enrichSources } = useEnrichmentSources(!readOnly && !isVisitor);
  const reportFalsePositive = useReportFalsePositive();
  const convertEntity = useConvertEntity();
  const unlinkAll = useUnlinkAllEntries();

  // Convert, merge, and unlink-all are admin-only endpoints; the false-positive
  // scopes stay open to every analyst.
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");

  // The entity's real name — `entity.value` is whatever surface form matched in
  // this article, which is often an alias.
  const canonicalName = entity.name ?? entity.value;
  const isAliasable = (MERGEABLE_ENTITY_TYPES as readonly string[]).includes(entity.type);
  const isAliasMatch = canonicalName.trim().toLowerCase() !== entity.value.trim().toLowerCase();

  /** Roughly how tall the taller of the two menus gets. Only the choice of
   *  direction depends on it, and the menu scrolls past this height anyway. */
  const MENU_HEIGHT = 250;

  const toggleMenu = (which: "fp" | "enrich") => {
    const rect = ref.current?.getBoundingClientRect();
    if (rect) {
      const below = window.innerHeight - rect.bottom;
      setMenuUp(below < MENU_HEIGHT && rect.top > below);
    }
    if (which === "fp") {
      setShowEnrichMenu(false);
      setShowFpMenu((o) => !o);
    } else {
      setShowFpMenu(false);
      setShowEnrichMenu((o) => !o);
    }
    setShowConvertMenu(false);
  };

  const handleReportFalsePositive = async (scope: FalsePositiveScope) => {
    setShowFpMenu(false);
    if (scope === "global") {
      const ok = await confirmDialog({
        title: "Stop matching this name",
        message:
          `Stop matching "${entity.value}" for every entity, everywhere?\n\n` +
          "Existing links stay — use \u201cUnlink from every article\u201d to clear those.",
        confirmLabel: "Stop matching",
        destructive: true,
      });
      if (!ok) return;
    }
    reportFalsePositive.mutate(
      {
        entity_type: entity.type,
        entity_id: entity.id,
        entity_value: entity.value,
        source_entry_id: entryId,
        scope,
      },
      {
        onSuccess: (result) => {
          if (scope === "global") {
            toast.success(`Won't match "${entity.value}" again — autolinker vocabulary updated`);
          } else if (scope === "alias") {
            const also = result.links_removed
              ? ` — unlinked ${result.links_removed} article${result.links_removed === 1 ? "" : "s"} that matched only that name`
              : "";
            toast.success(`"${entity.value}" is no longer a name for ${canonicalName}${also}`);
          } else {
            toast.success(`Unlinked "${entity.value}" from this article`);
          }
          if (scope !== "global" && !result.unlinked_from_entry && entryId) {
            toast.message("Note: no link existed for this article — recorded for review only.");
          }
        },
        onError: (err: unknown) => {
          const data = (err as { response?: { data?: { error?: { message?: string }; detail?: string } } })?.response
            ?.data;
          toast.error(data?.error?.message || data?.detail || "Failed to report false positive");
        },
      },
    );
    onClose();
  };

  // Observables live in the ledger, not the autolinker: their wrong-match
  // rungs are the sighting unlink (entry-local) and the deny tombstone
  // (global) — the false-positive vocabulary path can't touch them.
  const unlinkObservableSighting = useUnlinkEntity();
  const denyObservable = useDenyObservable();

  const handleObservableWrongHere = () => {
    setShowFpMenu(false);
    if (!entryId) return;
    unlinkObservableSighting.mutate(
      { entryId, entityId: entity.id, entityType: "observable" },
      {
        onSuccess: () => toast.success(`Removed this article's sighting of ${entity.value}`),
        onError: () => toast.error("Failed to remove the sighting"),
      },
    );
    onClose();
  };

  const handleObservableNeverCapture = async () => {
    setShowFpMenu(false);
    const ok = await confirmDialog({
      title: "Never capture this value",
      message:
        `Never capture "${entity.value}" again?\n\n` +
        "Tombstones the ledger row everywhere: every capture door refuses the value and it leaves the outbound feeds. Sightings are kept as history.",
      confirmLabel: "Never capture",
      destructive: true,
    });
    if (!ok) return;
    denyObservable.mutate(entity.id, {
      onSuccess: () => toast.success(`"${entity.value}" is tombstoned — no door will capture it again`),
      onError: () => toast.error("Failed to tombstone"),
    });
    onClose();
  };

  const handleUnlinkAll = async () => {
    setShowFpMenu(false);
    if (
      !(await confirmDialog({
        title: "Unlink from every article",
        message:
          `Unlink ${canonicalName} from every article it's linked to?\n\n` +
          "The entity and its relationships stay; only the article links go. This cannot be undone.",
        confirmLabel: "Unlink all",
        destructive: true,
      }))
    )
      return;
    unlinkAll.mutate(
      { entityType: entity.type, entityId: entity.id },
      {
        onSuccess: (result) => toast.success(`Unlinked ${canonicalName} from ${result.unlinked} articles`),
        onError: () => toast.error("Failed to unlink"),
      },
    );
    onClose();
  };

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      // The merge modal is portaled to <body>, so clicks inside it read as
      // "outside the popover" — closing here would unmount the modal mid-task.
      if (mergeOpen) return;
      if (ref.current && !ref.current.contains(e.target as Node)) {
        onClose();
      }
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        if (mergeOpen) {
          setMergeOpen(false);
          return;
        }
        onClose();
      }
    };
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
    };
  }, [onClose, mergeOpen]);

  const handleCopy = () => {
    navigator.clipboard.writeText(entity.value);
    onClose();
  };

  // Pivot the global search field to this entity and open the results page.
  const handleSearch = () => {
    setHeaderSearchQuery(`"${entity.value}"`);
    navigate("/search");
    onClose();
  };

  const cveMeta = entity.cveMeta;
  const ttpMeta = entity.ttpMeta;
  const meta = entity.meta;
  const isCVE = entity.type === "cve" && cveMeta;
  const isTTP = entity.type === "ttp" && ttpMeta;
  const facts = meta?.facts ?? [];
  const aliases = (meta?.aliases ?? []).filter(
    (a) => a.toLowerCase() !== entity.value.toLowerCase(),
  );

  // Portal to <body>: the popover is `position: fixed`, but when rendered inside
  // the AI-summary day divider it lives within the virtualized entry list, whose
  // rows carry `transform: translateY(...)`. A transformed ancestor makes `fixed`
  // resolve against that ancestor instead of the viewport, so the viewport-based
  // coordinates and clamp are wrong and the popover ends up clipped/off-screen.
  // Escaping to <body> restores true viewport positioning. (Works everywhere the
  // popover is used, including the non-transformed reader body.)
  return createPortal(
    <div
      ref={ref}
      className={styles.popover}
      style={pos}
    >
      <div className={styles.header}>
        <Chip
          tone="solid"
          tint={getEntityColor(entity.type)}
          className={styles.badge}
        >
          {getEntityLabel(entity.type)}
        </Chip>
        {isCVE && cveMeta.is_kev && (
          <Chip
            tone="solid"
            tint="#dc2626"
            className={styles.kevBadge}
            title="CISA Known Exploited Vulnerability"
          >
            KEV
          </Chip>
        )}
        {isCVE && cveMeta.severity && (
          <Chip
            tone="toned"
            tint={getSeverityColor(cveMeta.severity)}
            className={styles.severityBadge}
          >
            {cveMeta.severity}
          </Chip>
        )}
      </div>
      <div className={styles.valueRow}>
        {meta?.image_url && (
          <img
            className={styles.thumb}
            src={meta.image_url}
            alt=""
            loading="lazy"
            onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = "none"; }}
          />
        )}
        <span className={styles.value}>{entity.value}</span>
      </div>

      {/* CVE metadata */}
      {isCVE && (
        <div className={styles.metaGrid}>
          {cveMeta.cvss_score != null && (
            <div className={styles.metaItem}>
              <span className={styles.metaLabel}>CVSS</span>
              <span className={styles.metaValue}>{cveMeta.cvss_score}</span>
            </div>
          )}
          {cveMeta.epss_score != null && (
            <div className={styles.metaItem}>
              <span className={styles.metaLabel}>EPSS</span>
              <span className={styles.metaValue}>{(Number(cveMeta.epss_score) * 100).toFixed(cveMeta.epss_score < 0.1 ? 1 : 0)}%</span>
            </div>
          )}
          {(cveMeta.github_poc_count || cveMeta.metasploit_module) && (
            <div className={styles.metaItem}>
              <span className={styles.metaLabel}>PoC</span>
              <span className={styles.metaValue}>
                {[
                  cveMeta.github_poc_count ? `${cveMeta.github_poc_count} GitHub` : null,
                  cveMeta.metasploit_module ? "Metasploit" : null,
                ].filter(Boolean).join(" · ")}
              </span>
            </div>
          )}
          {cveMeta.exploit_status && (
            <div className={styles.metaItem}>
              <span className={styles.metaLabel}>Exploit</span>
              <span className={`${styles.metaValue} ${styles.exploitValue}`}>{cveMeta.exploit_status}</span>
            </div>
          )}
          <div className={styles.metaItem}>
            <span className={styles.metaLabel}>First seen</span>
            <span className={styles.metaValue}>{formatDate(cveMeta.first_seen_at)}</span>
          </div>
          {cveMeta.article_count != null && (
            <div className={styles.metaItem}>
              <span className={styles.metaLabel}>Articles</span>
              <span className={styles.metaValue}>{cveMeta.article_count}</span>
            </div>
          )}
          {cveMeta.description && (
            <div className={`${styles.metaItem} ${styles.metaFull}`}>
              <span className={styles.metaLabel}>Description</span>
              <span className={styles.metaDesc}>
                {cveMeta.description.length > 120
                  ? cveMeta.description.slice(0, 120) + "..."
                  : cveMeta.description}
              </span>
            </div>
          )}
        </div>
      )}

      {/* TTP metadata */}
      {isTTP && (
        <div className={styles.metaGrid}>
          <div className={styles.metaItem}>
            <span className={styles.metaLabel}>Technique</span>
            <span className={styles.metaValue}>{ttpMeta.technique_id}</span>
          </div>
          {ttpMeta.tactic && (
            <div className={styles.metaItem}>
              <span className={styles.metaLabel}>Tactic</span>
              <span className={styles.metaValue}>{ttpMeta.tactic}</span>
            </div>
          )}
          <div className={styles.metaItem}>
            <span className={styles.metaLabel}>First seen</span>
            <span className={styles.metaValue}>{formatDate(ttpMeta.first_seen_at)}</span>
          </div>
          <div className={styles.metaItem}>
            <span className={styles.metaLabel}>Articles</span>
            <span className={styles.metaValue}>{ttpMeta.article_count}</span>
          </div>
          {ttpMeta.description && (
            <div className={`${styles.metaItem} ${styles.metaFull}`}>
              <span className={styles.metaLabel}>Description</span>
              <span className={styles.metaDesc}>{truncate(ttpMeta.description, 220)}</span>
            </div>
          )}
        </div>
      )}

      {/* Generic metadata (threat actors, malware, vendors, products, tools, etc.) */}
      {!isCVE && !isTTP && meta && (facts.length > 0 || meta.description || (meta.aliases && meta.aliases.length > 0) || meta.article_count != null) && (
        <div className={styles.metaGrid}>
          {facts.map((f) => (
            <div key={f.label} className={styles.metaItem}>
              <span className={styles.metaLabel}>{f.label}</span>
              <span className={styles.metaValue}>{f.value}</span>
            </div>
          ))}
          {meta.article_count != null && (
            <div className={styles.metaItem}>
              <span className={styles.metaLabel}>Articles</span>
              <span className={styles.metaValue}>{meta.article_count}</span>
            </div>
          )}
          {meta.first_seen_at && (
            <div className={styles.metaItem}>
              <span className={styles.metaLabel}>First seen</span>
              <span className={styles.metaValue}>{formatDate(meta.first_seen_at)}</span>
            </div>
          )}
          {aliases.length > 0 && (
            <div className={`${styles.metaItem} ${styles.metaFull}`}>
              <span className={styles.metaLabel}>Also known as</span>
              <span className={styles.metaValue}>{aliases.slice(0, 6).join(", ")}</span>
            </div>
          )}
          {meta.description && (
            <div className={`${styles.metaItem} ${styles.metaFull}`}>
              <span className={styles.metaLabel}>Description</span>
              <span className={styles.metaDesc}>{truncate(meta.description, 220)}</span>
            </div>
          )}
        </div>
      )}

      {/* Detection artifacts (offensive tools) */}
      {meta?.artifacts && meta.artifacts.length > 0 && (
        <div className={styles.artifacts}>
          <div className={styles.artifactsLabel}>Detection artifacts</div>
          {meta.artifacts.slice(0, 4).map((a) => (
            <div key={a.label} className={styles.artifactItem}>
              <span className={styles.artifactKey}>{a.label}</span>
              <span className={styles.artifactVal}>{truncate(a.value, 90)}</span>
            </div>
          ))}
        </div>
      )}

      {/* Pivot / reference links (CVE databases, MITRE, Malpedia, vendor sites) */}
      {(() => {
        const pivotType = entity.type === "cve" ? "cve" : "";
        const pivotLinks = (pivotType ? getPivotLinks(pivotType, entity.value) : []).map(
          (l) => ({ label: l.platform, url: l.url }),
        );
        const links = [...pivotLinks, ...(meta?.links ?? [])];
        return links.length > 0 ? (
          <div className={styles.pivotLinks}>
            {links.slice(0, 4).map((link) => (
              <a
                key={link.label}
                href={link.url}
                target="_blank"
                rel="noopener noreferrer"
                className={styles.pivotLink}
              >
                {link.label}
              </a>
            ))}
          </div>
        ) : null;
      })()}

      {/* Primary actions — hidden entirely on public shared pages. The wrapper
          is the positioning context for the two dropdowns below it. */}
      <div className={styles.actionsWrap}>
      {!readOnly && (
        <div className={styles.actions}>
          <button className={styles.actionBtn} onClick={onNavigate}>
            Profile
          </button>
          {!isVisitor && (
          <button className={styles.actionBtn} onClick={handleSearch} title="Search the feed for this entity">
            Search
          </button>
          )}
          <button className={styles.actionBtn} onClick={handleCopy}>
            Copy
          </button>
          {!isVisitor && (<>
          <button
            className={styles.actionBtn}
            onClick={() => toggleMenu("enrich")}
            disabled={enrichEntity.isPending}
          >
            {enrichEntity.isPending ? "..." : "Enrich"}
          </button>
          <button
            className={styles.actionBtn}
            onClick={() => toggleMenu("fp")}
            disabled={reportFalsePositive.isPending}
            title="Report this as a wrong entity match"
          >
            {reportFalsePositive.isPending ? "..." : "Wrong?"}
          </button>
          </>)}
        </div>
      )}

      {/* Observables get their own two-rung ladder: unlink the sighting here,
          or tombstone the value globally (admin). The autolinker FP path below
          can't touch ledger rows. */}
      {!readOnly && !isVisitor && showFpMenu && entity.type === "observable" && (
        <div className={`${styles.enrichMenu} ${menuUp ? styles.menuUp : ""}`}>
          {entryId && (
            <button
              className={styles.enrichMenuItem}
              onClick={handleObservableWrongHere}
              disabled={unlinkObservableSighting.isPending}
            >
              Wrong for this article — remove sighting
            </button>
          )}
          {isAdmin ? (
            <button
              className={styles.enrichMenuItem}
              onClick={handleObservableNeverCapture}
              disabled={denyObservable.isPending}
            >
              Never capture "{truncate(entity.value, 40)}" — tombstone
            </button>
          ) : (
            <div className={styles.enrichMenuItem} style={{ opacity: 0.6, cursor: "default" }}>
              Global tombstone needs an admin
            </div>
          )}
        </div>
      )}

      {/* Wrong-match menu, narrowest fix first: this article → this name →
          this entity (type/duplicate) → this word everywhere. */}
      {!readOnly && !isVisitor && showFpMenu && entity.type !== "observable" && (
        <div className={`${styles.enrichMenu} ${menuUp ? styles.menuUp : ""}`}>
          {entryId && (
            <button className={styles.enrichMenuItem} onClick={() => handleReportFalsePositive("entry")}>
              Wrong for this article
            </button>
          )}
          {isAliasable && isAliasMatch && (
            <button
              className={styles.enrichMenuItem}
              onClick={() => handleReportFalsePositive("alias")}
              title={`Drop "${entity.value}" as a name for ${canonicalName} and unlink articles that matched only via it`}
            >
              Not a name for {canonicalName}
            </button>
          )}
          {isAdmin && (
            <button className={styles.enrichMenuItem} onClick={() => setShowConvertMenu((o) => !o)}>
              Wrong type — convert <span className="caret-glyph">{showConvertMenu ? "▾" : "▸"}</span>
            </button>
          )}
          {isAdmin && showConvertMenu && (
            <div className={styles.submenu}>
              {convertTargetsFor(entity.type).map((target) => (
                <button
                  key={target.key}
                  className={styles.enrichMenuItem}
                  onClick={async () => {
                    setShowConvertMenu(false);
                    setShowFpMenu(false);
                    await runEntityConvert({
                      entityType: entity.type,
                      entityId: entity.id,
                      target,
                      convert: convertEntity,
                    });
                    onClose();
                  }}
                >
                  {target.label}
                </button>
              ))}
            </div>
          )}
          {isAdmin && isAliasable && (
            <button className={styles.enrichMenuItem} onClick={() => setMergeOpen(true)}>
              Duplicate — merge into…
            </button>
          )}
          <div className={styles.menuDivider} />
          {isAdmin && (
            <button className={styles.enrichMenuItem} onClick={handleUnlinkAll} disabled={unlinkAll.isPending}>
              Unlink from every article
            </button>
          )}
          <button className={styles.enrichMenuItem} onClick={() => handleReportFalsePositive("global")}>
            Never match "{entity.value}" anywhere
          </button>
        </div>
      )}

      {mergeOpen &&
        createPortal(
          <EntityMergeIntoModal
            entityType={entity.type}
            keeperId={entity.id}
            keeperName={canonicalName}
            onClose={() => setMergeOpen(false)}
            onMerged={onClose}
          />,
          document.body,
        )}

      {/* Quick Enrich dropdown */}
      {!readOnly && !isVisitor && showEnrichMenu && (() => {
        // Map entity type to adapter type for matching
        const adapterType = entity.type;

        const applicable = enrichSources?.filter(
          (s) =>
            s.is_enabled &&
            s.supported_entity_types.some(
              (t) => t === adapterType || t === entity.type
            )
        ) ?? [];

        const handleQuickEnrich = (sourceType: string) => {
          enrichEntity.mutate(
            {
              entityType: entity.type,
              entityId: entity.id,
              sourceTypes: [sourceType],
            },
            {
              onSuccess: (data) => {
                const result = data.results[0];
                setEnrichStatus(result?.status === "success" ? "Done" : result?.status ?? "error");
                setTimeout(() => setEnrichStatus(null), 3000);
              },
              onError: () => {
                setEnrichStatus("error");
                setTimeout(() => setEnrichStatus(null), 3000);
              },
            }
          );
          setShowEnrichMenu(false);
        };

        return (
          <div className={`${styles.enrichMenu} ${menuUp ? styles.menuUp : ""}`}>
            {applicable.length === 0 && (
              <div className={styles.enrichMenuEmpty}>No sources available</div>
            )}
            {applicable.slice(0, 5).map((s) => (
              <button
                key={s.id}
                className={styles.enrichMenuItem}
                onClick={() => handleQuickEnrich(s.source_type)}
              >
                {s.display_name}
              </button>
            ))}
            {applicable.length > 5 && (
              <button className={styles.enrichMenuItem} onClick={onNavigate}>
                More...
              </button>
            )}
          </div>
        );
      })()}
      </div>

      {/* Enrich status flash */}
      {!readOnly && !isVisitor && enrichStatus && (
        <div className={styles.enrichFlash}>
          {enrichStatus === "Done" ? "Enriched" : enrichStatus}
        </div>
      )}

    </div>,
    document.body,
  );
}
