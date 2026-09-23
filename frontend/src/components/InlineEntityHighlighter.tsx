import { useEffect, useState, useCallback, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { EntityPopover } from "./EntityPopover";
import { ENTITY_COLOR_MAP } from "@/utils/entityTheme";
import { useIntelStore, type EntityType } from "@/stores/intelStore";
import styles from "./InlineEntityHighlighter.module.css";

/**
 * Generic metadata attached to a highlighted entity so the popover can show a
 * description plus a few key facts while reading, without a follow-up fetch.
 * Populated for all non-CVE entity types (CVE uses the richer `cveMeta`).
 */
export interface HighlightEntityMeta {
  description?: string | null;
  /** Short key/value facts shown in the popover grid (e.g. Motivation, Type). */
  facts?: Array<{ label: string; value: string }>;
  /** Alternative names ("also known as"). */
  aliases?: string[];
  /** External reference links (MITRE, Malpedia, vendor site, GitHub, Wikipedia). */
  links?: Array<{ label: string; url: string }>;
  /** Wikipedia thumbnail (country flag, vendor/product logo, actor group image). */
  image_url?: string | null;
  /** Detection artifacts for offensive tools (hashes, registry keys, signatures). */
  artifacts?: Array<{ label: string; value: string }>;
  article_count?: number;
  first_seen_at?: string;
}

export interface HighlightEntity {
  id: string;
  type:
    | "cve"
    | "cwe"
    | "ttp"
    | "threat_actor"
    | "malware"
    | "country"
    | "vendor"
    | "product"
    | "tool"
    | "mitigation"
    | "observable";
  value: string;
  /** The entity's canonical name, when the matched `value` is an alias or other
   *  surface form. Lets the popover tell "wrong alias" from "wrong entity". */
  name?: string;
  /** Optional CVE metadata for enriched popovers */
  cveMeta?: {
    cvss_score: number | null;
    severity: string | null;
    description: string | null;
    exploit_status: string | null;
    first_seen_at: string;
    article_count?: number;
    epss_score?: number | null;
    is_kev?: boolean;
    github_poc_count?: number | null;
    metasploit_module?: string | null;
    risk_tier?: string | null;
  };
  /** Optional TTP metadata for enriched popovers */
  ttpMeta?: {
    technique_id: string;
    technique_name: string;
    tactic: string | null;
    description?: string | null;
    article_count: number;
    first_seen_at: string;
  };
  /** Generic metadata for threat actors, malware, vendors, products, etc. */
  meta?: HighlightEntityMeta;
}

interface InlineEntityHighlighterProps {
  containerRef: React.RefObject<HTMLDivElement | null>;
  entities: HighlightEntity[];
  enabled: boolean;
  disableNavigation?: boolean;
  /** Entry this content belongs to — lets the popover offer "report false positive". */
  entryId?: string;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Build a regex fragment for an entity value.
 */
function buildEntityPattern(entity: HighlightEntity): string {
  // Lookbehind/lookahead instead of \b so values ending in punctuation
  // (e.g. "U.S.") still match — \b requires a \w↔\W transition.
  return `(?<!\\w)${escapeRegExp(entity.value)}(?!\\w)`;
}

export function InlineEntityHighlighter({
  containerRef,
  entities,
  enabled,
  disableNavigation,
  entryId,
}: InlineEntityHighlighterProps) {
  const navigate = useNavigate();
  const [popover, setPopover] = useState<{
    entity: HighlightEntity;
    x: number;
    y: number;
  } | null>(null);
  // Bumped whenever the container's DOM content is replaced (e.g. SafeHTML re-render)
  const [domVersion, setDomVersion] = useState(0);
  // Track which entity set was last applied so we re-highlight when entities change
  const lastAppliedKey = useRef<string>("");
  // Suppress MutationObserver during our own highlight clearing
  const isSelfMutating = useRef(false);

  const showPopoverFor = useCallback(
    (target: HTMLElement) => {
      const entityId = target.dataset.entityId;
      const entityType = target.dataset.entityType;
      if (!entityId || !entityType) return;

      const entity = entities.find((en) => en.id === entityId);
      if (!entity) return;

      const rect = target.getBoundingClientRect();
      setPopover({
        entity,
        x: rect.left + rect.width / 2,
        y: rect.bottom + 4,
      });
    },
    [entities],
  );

  const handleEntityClick = useCallback(
    (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.classList.contains(styles.entityHighlight)) return;
      // The highlight span may sit inside an <a> from the article HTML
      // (publishers often hyperlink CVE IDs) — keep the click on the popover
      // instead of letting the anchor navigate away.
      e.preventDefault();
      showPopoverFor(target);
    },
    [showPopoverFor],
  );

  const hoverTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleEntityMouseOver = useCallback(
    (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.classList.contains(styles.entityHighlight)) return;
      if (hoverTimerRef.current) clearTimeout(hoverTimerRef.current);
      hoverTimerRef.current = setTimeout(() => {
        showPopoverFor(target);
      }, 300);
    },
    [showPopoverFor],
  );

  const handleEntityMouseOut = useCallback(
    (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.classList.contains(styles.entityHighlight)) return;
      if (hoverTimerRef.current) {
        clearTimeout(hoverTimerRef.current);
        hoverTimerRef.current = null;
      }
    },
    [],
  );

  // Watch for container content being replaced (e.g. SafeHTML re-render from
  // glossary terms or keywords loading after entity highlights were applied).
  // When that happens, bump domVersion so the highlight effect re-runs.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const observer = new MutationObserver(() => {
      // Skip mutations caused by our own highlight clearing/re-application
      if (isSelfMutating.current) return;
      // If entity highlights are gone, the content was replaced — re-process
      if (!el.querySelector(`.${styles.entityHighlight}`)) {
        lastAppliedKey.current = "";
        setDomVersion((v) => v + 1);
      }
    });
    observer.observe(el, { childList: true, subtree: true });
    return () => observer.disconnect();
  }, [containerRef]);

  // When the "Highlight entities" preference is turned off, unwrap any
  // highlights already applied so the article returns to plain text.
  useEffect(() => {
    if (enabled) return;
    const el = containerRef.current;
    if (!el) return;
    isSelfMutating.current = true;
    el.querySelectorAll(`.${styles.entityHighlight}`).forEach((span) => {
      const text = document.createTextNode(span.textContent || "");
      span.parentNode?.replaceChild(text, span);
    });
    el.normalize();
    lastAppliedKey.current = "";
    isSelfMutating.current = false;
  }, [containerRef, enabled]);

  // Highlight entities in the container's text nodes
  useEffect(() => {
    const el = containerRef.current;
    if (!el || !enabled || entities.length === 0) return;

    // Build a fingerprint of the current entity set
    const entityKey = entities.map((e) => e.id + e.value).join("|");

    // If highlights already exist for this exact entity set, skip
    if (el.querySelector(`.${styles.entityHighlight}`) && entityKey === lastAppliedKey.current) return;

    // Clear existing highlights if entities changed (e.g. CVEs loaded after IOCs)
    isSelfMutating.current = true;
    if (entityKey !== lastAppliedKey.current) {
      el.querySelectorAll(`.${styles.entityHighlight}`).forEach((span) => {
        const text = document.createTextNode(span.textContent || "");
        span.parentNode?.replaceChild(text, span);
      });
      // Normalize adjacent text nodes after unwrapping
      el.normalize();
    }

    lastAppliedKey.current = entityKey;

    // Sort by value length descending so longer matches take priority
    const sorted = [...entities].sort((a, b) => b.value.length - a.value.length);

    // Build a combined regex
    const pattern = sorted.map((e) => buildEntityPattern(e)).join("|");
    if (!pattern) {
      isSelfMutating.current = false;
      return;
    }
    const regex = new RegExp(`(${pattern})`, "gi");

    // Build lookup map
    const entityMap = new Map<string, HighlightEntity>();
    for (const e of sorted) {
      entityMap.set(e.value.toLowerCase(), e);
    }

    // Walk text nodes
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    const textNodes: Text[] = [];
    let node: Text | null;
    while ((node = walker.nextNode() as Text | null)) {
      textNodes.push(node);
    }

    for (const textNode of textNodes) {
      const parent = textNode.parentElement;
      if (
        !parent ||
        parent.classList.contains("glossary-term") ||
        parent.classList.contains(styles.entityHighlight)
      ) {
        continue;
      }

      const text = textNode.textContent || "";
      if (!regex.test(text)) continue;
      regex.lastIndex = 0;

      const fragment = document.createDocumentFragment();
      let lastIndex = 0;
      let match: RegExpExecArray | null;
      let matched = false;

      while ((match = regex.exec(text)) !== null) {
        matched = true;
        if (match.index > lastIndex) {
          fragment.appendChild(
            document.createTextNode(text.slice(lastIndex, match.index)),
          );
        }

        const entity = entityMap.get(match[0].toLowerCase());
        const span = document.createElement("span");
        span.className = styles.entityHighlight;
        // Observables are machine strings — mono marks them as such inline.
        if (entity?.type === "observable") span.classList.add(styles.entityMono);
        span.dataset.entityId = entity?.id || "";
        span.dataset.entityType = entity?.type || "";
        span.style.borderBottomColor = ENTITY_COLOR_MAP[entity?.type || "cve"];
        span.textContent = match[0];
        fragment.appendChild(span);

        lastIndex = regex.lastIndex;
      }

      if (matched) {
        if (lastIndex < text.length) {
          fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
        }
        textNode.parentNode?.replaceChild(fragment, textNode);
      }
    }

    isSelfMutating.current = false;

  }, [containerRef, entities, enabled, domVersion]);

  // Attach click + hover handlers separately so they survive re-renders
  // even when the highlight effect returns early (highlights already present).
  useEffect(() => {
    const el = containerRef.current;
    if (!el || !enabled) return;
    el.addEventListener("click", handleEntityClick);
    el.addEventListener("mouseover", handleEntityMouseOver);
    el.addEventListener("mouseout", handleEntityMouseOut);
    return () => {
      el.removeEventListener("click", handleEntityClick);
      el.removeEventListener("mouseover", handleEntityMouseOver);
      el.removeEventListener("mouseout", handleEntityMouseOut);
      if (hoverTimerRef.current) clearTimeout(hoverTimerRef.current);
    };
  }, [containerRef, enabled, handleEntityClick, handleEntityMouseOver, handleEntityMouseOut]);

  const selectEntity = useIntelStore((s) => s.selectEntity);

  const handleNavigate = useCallback(
    (entity: HighlightEntity) => {
      setPopover(null);
      if (disableNavigation) return;
      const entityTypes = ["cve", "cwe", "ttp", "threat_actor", "malware", "country", "vendor", "product", "tool", "mitigation", "observable"];
      if (entityTypes.includes(entity.type)) {
        selectEntity(entity.type as EntityType, entity.id, entity.value);
        navigate("/workbench/explore");
      }
    },
    [navigate, selectEntity, disableNavigation],
  );

  return (
    <>
      {popover && (
        <EntityPopover
          entity={popover.entity}
          x={popover.x}
          y={popover.y}
          onClose={() => setPopover(null)}
          onNavigate={() => handleNavigate(popover.entity)}
          readOnly={disableNavigation}
          entryId={entryId}
        />
      )}
    </>
  );
}
