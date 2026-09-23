/**
 * EntityLinkedMarkdown — render markdown text with known intelligence entities
 * highlighted and linked to their profiles, exactly like the daily AI summary.
 *
 * It scans `text` via the auto-linker (`useEntityScan`), builds surface-form →
 * profile-href links, and feeds them to the shared `remarkEntityLinks` plugin.
 * While the scan is in flight (or fails) it degrades gracefully to plain
 * markdown — no entity links, but the text always renders.
 */
import { useCallback, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { Components } from "react-markdown";
import type { PluggableList } from "unified";
import { useEntityScan, type EntityScanMatch } from "@/hooks/useEntityScan";
import {
  remarkEntityLinks,
  type RemarkEntityLink,
} from "@/utils/remarkEntityLinks";
import { remarkSoftBreaks } from "@/utils/remarkSoftBreaks";
import { ENTITY_COLOR_MAP } from "@/utils/entityTheme";
import { EntityPopover } from "@/components/EntityPopover";
import type { HighlightEntity } from "@/components/InlineEntityHighlighter";
import { useIntelStore, type EntityType } from "@/stores/intelStore";
import {
  actorMeta,
  malwareMeta,
  vendorMeta,
  productMeta,
  toolMeta,
  countryMeta,
  mitigationMeta,
  cweMeta,
} from "@/utils/entityPopoverMeta";
import type {
  ThreatActor,
  MalwareFamily,
  Vendor,
  Product,
  OffensiveTool,
  Country,
  Mitigation,
  CWEResponse,
  CVE,
  TTP,
} from "@/api/types";
import styles from "./EntityLinkedMarkdown.module.css";

interface Props {
  text: string;
  /** Entity whose profile is currently shown — never links to itself. */
  excludeEntityId?: string;
  /** Skip scanning (e.g. while editing). */
  enabled?: boolean;
}


const ENTITY_HREF_RE =
  /^\/workbench\/(threat_actor|malware|cve|cwe|ttp|vendor|product|country|tool|mitigation)\//;

function entityTypeFromHref(href: string | undefined): string | null {
  if (!href) return null;
  const m = ENTITY_HREF_RE.exec(href);
  if (!m) return null;
  return m[1];
}

/** Fold the scan match's full entity payload into the HighlightEntity so the
 *  popover renders with the same descriptions, facts, aliases and links as the
 *  reader and the daily-summary divider. */
function scanMatchToHighlightEntity(m: EntityScanMatch): HighlightEntity {
  const base: HighlightEntity = {
    id: m.entity_id,
    type: m.entity_type as HighlightEntity["type"],
    value: m.canonical_name,
    name: m.canonical_name,
  };
  const payload = m.entity;
  if (!payload) return base;
  switch (base.type) {
    case "cve": {
      const c = payload as unknown as CVE;
      return {
        ...base,
        cveMeta: {
          cvss_score: c.cvss_score,
          severity: c.severity,
          description: c.description,
          exploit_status: c.exploit_status,
          first_seen_at: c.first_seen_at,
          article_count: c.article_count,
          epss_score: c.epss_score,
          is_kev: c.is_kev,
          github_poc_count: c.github_poc_count,
          metasploit_module: c.metasploit_module,
          risk_tier: c.risk_tier,
        },
      };
    }
    case "ttp": {
      const t = payload as unknown as TTP;
      return {
        ...base,
        ttpMeta: {
          technique_id: t.technique_id,
          technique_name: t.technique_name,
          tactic: t.tactic,
          description: t.description,
          article_count: t.article_count,
          first_seen_at: t.first_seen_at,
        },
      };
    }
    case "threat_actor":
      return { ...base, meta: actorMeta(payload as unknown as ThreatActor) };
    case "malware":
      return { ...base, meta: malwareMeta(payload as unknown as MalwareFamily) };
    case "vendor":
      return { ...base, meta: vendorMeta(payload as unknown as Vendor) };
    case "product":
      return { ...base, meta: productMeta(payload as unknown as Product) };
    case "tool":
      return { ...base, meta: toolMeta(payload as unknown as OffensiveTool) };
    case "country":
      return { ...base, meta: countryMeta(payload as unknown as Country) };
    case "mitigation":
      return { ...base, meta: mitigationMeta(payload as unknown as Mitigation) };
    case "cwe":
      return { ...base, meta: cweMeta(payload as unknown as CWEResponse) };
    default:
      return base;
  }
}

export function EntityLinkedMarkdown({ text, excludeEntityId, enabled = true }: Props) {
  const navigate = useNavigate();
  const selectEntity = useIntelStore((s) => s.selectEntity);
  const { data: matches } = useEntityScan(text, enabled);

  // Build the remark links and, in the same pass, an href → entity map so
  // hovering a link shows the shared EntityPopover with the full metadata the
  // scan response carries (description, facts, aliases, links) — the same card
  // the reader and the daily-summary divider show.
  const { linkEntities, entityByHref } = useMemo(() => {
    const out: RemarkEntityLink[] = [];
    const byHref = new Map<string, HighlightEntity>();
    if (!matches) return { linkEntities: out, entityByHref: byHref };
    const seen = new Set<string>();
    for (const m of matches) {
      if (excludeEntityId && m.entity_id === excludeEntityId) continue;
      const slug = m.entity_type;
      if (!slug) continue;
      const href = `/workbench/${slug}/${m.entity_id}`;
      byHref.set(href, scanMatchToHighlightEntity(m));
      for (const sf of m.surface_forms) {
        if (!sf) continue;
        const key = `${href}::${sf.toLowerCase()}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ type: m.entity_type, value: sf, href });
      }
    }
    return { linkEntities: out, entityByHref: byHref };
  }, [matches, excludeEntityId]);

  // Hover popover — opens on a 300ms hover-in delay (matching the reader / AI
  // summary), closes on outside-click / Escape (handled inside EntityPopover).
  const [popover, setPopover] = useState<{ entity: HighlightEntity; x: number; y: number } | null>(null);
  const hoverTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const openPopoverFor = useCallback(
    (href: string | undefined, el: HTMLElement) => {
      if (!href) return;
      const entity = entityByHref.get(href);
      if (!entity) return;
      // Show the surface form actually hovered (often an alias) as the value —
      // `name` keeps the canonical name — so the popover's wrong-match options
      // act on the matched name, exactly like the reader's highlights.
      const hovered = el.textContent?.trim();
      const shown =
        hovered && hovered.toLowerCase() !== entity.value.toLowerCase()
          ? { ...entity, value: hovered }
          : entity;
      const rect = el.getBoundingClientRect();
      setPopover({ entity: shown, x: rect.left + rect.width / 2, y: rect.bottom + 4 });
    },
    [entityByHref],
  );

  // IMPORTANT: pass as [plugin, options] tuple — see remarkEntityLinks usage in
  // DayDividerSummary for why a direct call breaks the transformer.
  const remarkPlugins = useMemo<PluggableList>(
    () => [remarkGfm, remarkSoftBreaks, [remarkEntityLinks, linkEntities]],
    [linkEntities],
  );

  const components = useMemo<Components>(
    () => ({
      a: ({ href, children, ...rest }) => {
        const entityType = entityTypeFromHref(href);
        if (entityType) {
          return (
            <a
              {...rest}
              href={href}
              className={styles.entityLink}
              style={{ borderBottomColor: ENTITY_COLOR_MAP[entityType] || "currentColor" }}
              onMouseEnter={(e) => {
                const el = e.currentTarget;
                if (hoverTimer.current) clearTimeout(hoverTimer.current);
                hoverTimer.current = setTimeout(() => openPopoverFor(href, el), 300);
              }}
              onMouseLeave={() => {
                if (hoverTimer.current) {
                  clearTimeout(hoverTimer.current);
                  hoverTimer.current = null;
                }
              }}
              onClick={(e) => {
                e.stopPropagation();
                if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) {
                  return;
                }
                if (href) {
                  e.preventDefault();
                  navigate(href);
                }
              }}
            >
              {children}
            </a>
          );
        }
        const isInternal = !!href && href.startsWith("/");
        return (
          <a
            {...rest}
            href={href}
            target={isInternal ? undefined : "_blank"}
            rel={isInternal ? undefined : "noopener noreferrer"}
            className={styles.articleLink}
            onClick={(e) => {
              e.stopPropagation();
              if (isInternal && href) {
                e.preventDefault();
                navigate(href);
              }
            }}
          >
            {children}
          </a>
        );
      },
    }),
    [navigate, openPopoverFor],
  );

  return (
    <>
      <Markdown remarkPlugins={remarkPlugins} components={components}>
        {text}
      </Markdown>
      {popover && (
        <EntityPopover
          entity={popover.entity}
          x={popover.x}
          y={popover.y}
          onClose={() => setPopover(null)}
          onNavigate={() => {
            const { entity } = popover;
            setPopover(null);
            selectEntity(entity.type as EntityType, entity.id, entity.value);
            navigate("/workbench/explore");
          }}
        />
      )}
    </>
  );
}
