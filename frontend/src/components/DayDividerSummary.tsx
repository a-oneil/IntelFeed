import { useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  useDailySummary,
  useGenerateDailySummary,
  type DailySummaryFilters,
} from "@/hooks/useDailySummary";
import {
  useDayEntities,
  type DayActor,
  type DayMalware,
  type DayVendor,
  type DayProduct,
  type DayCountry,
  type DayTool,
} from "@/hooks/useDayEntities";
import { usePlayerStore } from "@/stores/playerStore";
import { useUIStore } from "@/stores/uiStore";
import { useIntelStore, type EntityType } from "@/stores/intelStore";
import { useTts } from "@/hooks/useTts";
import { extractSpeechParagraphs } from "@/utils/speechPreprocess";
import type { PluggableList } from "unified";
import {
  remarkEntityLinks,
  type RemarkEntityLink,
} from "@/utils/remarkEntityLinks";
import { ENTITY_COLOR_MAP } from "@/utils/entityTheme";
import { EntityPopover } from "@/components/EntityPopover";
import type {
  HighlightEntity,
  HighlightEntityMeta,
} from "@/components/InlineEntityHighlighter";
import { SummarySelectionMenu } from "@/components/SummarySelectionMenu";
import { Hint } from "@/components/primitives";
import styles from "./DayDividerSummary.module.css";

interface Props {
  dayKey: string;          // "YYYY-MM-DD"
  dayCount: number;        // how many entries fall in this day
  filters: DailySummaryFilters;
  label?: string;          // "Today" / "Yesterday" / "Mon, Jul 8" — for read-aloud
}

type MetaFact = { label: string; value: string };
type MetaLink = { label: string; url: string };

/** Match the entity profile routes the remark plugin emits. The popover lookup
 *  and per-type styling both key off these. group 2 = entity slug. */
const ENTITY_HREF_RE =
  /^\/(intelligence|workbench)\/(actor|malware|cve|ttp|vendor|product|country|sector|tool|mitigation)\//;

function entityTypeFromHref(href: string | undefined): string | null {
  if (!href) return null;
  const m = ENTITY_HREF_RE.exec(href);
  if (!m) return null;
  return m[2];
}

function withWiki(links: MetaLink[], url: string | null): MetaLink[] {
  if (url) links.push({ label: "Wikipedia", url });
  return links;
}

// Build the popover metadata for each named-entity type from the day-entities
// payload — mirrors the entry reader's builders so the tooltip is identical.
function actorMeta(a: DayActor): HighlightEntityMeta {
  const facts: MetaFact[] = [];
  if (a.motivation) facts.push({ label: "Motivation", value: a.motivation });
  if (a.country) facts.push({ label: "Origin", value: a.country });
  if (a.targeted_sectors?.length)
    facts.push({ label: "Targets", value: a.targeted_sectors.slice(0, 3).join(", ") });
  const links: MetaLink[] = [];
  if (a.mitre_id) links.push({ label: "MITRE ATT&CK", url: `https://attack.mitre.org/groups/${a.mitre_id}/` });
  return metaBase(a, facts, withWiki(links, a.wikipedia_url));
}

function malwareMeta(m: DayMalware): HighlightEntityMeta {
  const facts: MetaFact[] = [];
  if (m.malware_type) facts.push({ label: "Type", value: m.malware_type });
  const links: MetaLink[] = [];
  if (m.malpedia_url) links.push({ label: "Malpedia", url: m.malpedia_url });
  return metaBase(m, facts, withWiki(links, m.wikipedia_url));
}

function vendorMeta(v: DayVendor): HighlightEntityMeta {
  const facts: MetaFact[] = [];
  if (v.vendor_type) facts.push({ label: "Type", value: v.vendor_type });
  const links: MetaLink[] = [];
  if (v.website) links.push({ label: "Website", url: v.website });
  return metaBase(v, facts, withWiki(links, v.wikipedia_url));
}

function productMeta(p: DayProduct): HighlightEntityMeta {
  const facts: MetaFact[] = [];
  if (p.product_type) facts.push({ label: "Type", value: p.product_type });
  const links: MetaLink[] = [];
  if (p.website) links.push({ label: "Website", url: p.website });
  return metaBase(p, facts, withWiki(links, p.wikipedia_url));
}

function countryMeta(c: DayCountry): HighlightEntityMeta {
  const facts: MetaFact[] = [];
  if (c.region) facts.push({ label: "Region", value: c.region });
  return metaBase(c, facts, withWiki([], c.wikipedia_url));
}

function toolMeta(t: DayTool): HighlightEntityMeta {
  const facts: MetaFact[] = [];
  if (t.tool_type) facts.push({ label: "Type", value: t.tool_type });
  if (t.platforms?.length) facts.push({ label: "Platforms", value: t.platforms.slice(0, 3).join(", ") });
  const links: MetaLink[] = [];
  if (t.github_url) links.push({ label: "GitHub", url: t.github_url });
  if (t.malpedia_url) links.push({ label: "Malpedia", url: t.malpedia_url });
  const artifacts: MetaFact[] = [];
  for (const [key, raw] of Object.entries(t.detection_artifacts ?? {})) {
    const value = Array.isArray(raw) ? raw.join(", ") : String(raw ?? "");
    if (value && value !== "null" && value !== "{}")
      artifacts.push({ label: key.replace(/_/g, " "), value });
  }
  return { ...metaBase(t, facts, withWiki(links, t.wikipedia_url)), artifacts };
}

function metaBase(
  o: {
    description: string | null;
    aliases: string[];
    wikipedia_image_url: string | null;
    article_count: number;
    first_seen_at: string | null;
  },
  facts: MetaFact[],
  links: MetaLink[],
): HighlightEntityMeta {
  return {
    description: o.description,
    facts,
    aliases: o.aliases,
    links,
    image_url: o.wikipedia_image_url,
    article_count: o.article_count,
    first_seen_at: o.first_seen_at ?? undefined,
  };
}

function dayWindowIso(dayKey: string): { since: string; before: string } | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dayKey);
  if (!m) return null;
  const [, y, mo, d] = m;
  const start = new Date(Number(y), Number(mo) - 1, Number(d), 0, 0, 0, 0);
  const end = new Date(Number(y), Number(mo) - 1, Number(d), 23, 59, 59, 999);
  return { since: start.toISOString(), before: end.toISOString() };
}

/** Slice the summary down to its TL;DR section (everything before the second
 * top-level `## ` heading). If the model didn't structure with sections, the
 * whole summary is returned — graceful fallback. */
function tldrOnly(summary: string): string {
  const lines = summary.split("\n");
  let seenH2 = 0;
  for (let i = 0; i < lines.length; i++) {
    if (/^##\s+/.test(lines[i])) {
      seenH2 += 1;
      if (seenH2 === 2) {
        return lines.slice(0, i).join("\n").trim();
      }
    }
  }
  return summary;
}

export function DayDividerSummary({ dayKey, dayCount, filters, label }: Props) {
  const navigate = useNavigate();
  const { data: cached, isLoading: cacheLoading } = useDailySummary(dayKey, filters);
  const generate = useGenerateDailySummary();

  // Read-aloud reuses the global speech player. A hidden full-summary render
  // (below) is the extraction source so we speak the whole thing even when the
  // visible body is collapsed to the TL;DR.
  const speechEntryId = `daily-summary:${dayKey}`;
  const playSpeech = usePlayerStore((s) => s.playSpeech);
  const stopSpeech = usePlayerStore((s) => s.stopSpeech);
  const stopAudio = usePlayerStore((s) => s.stop);
  const isSpeechForThis = usePlayerStore((s) => s.speechTrack?.entryId === speechEntryId);
  const isTtsForThis = usePlayerStore(
    (s) => s.mode === "audio" && s.currentTrack?.kind === "tts" && s.currentTrack?.entryId === speechEntryId,
  );
  const isSpeaking = isSpeechForThis || isTtsForThis;
  const readAloudEngine = useUIStore((s) => s.readAloudEngine);
  const tts = useTts();
  const speechSupported =
    typeof window !== "undefined" && "speechSynthesis" in window;
  const readAloudAvailable = readAloudEngine === "piper" || speechSupported;
  const fullBodyRef = useRef<HTMLDivElement>(null);
  // Visible, entity-highlighted body — the selection-menu scopes to this element
  // so highlighting text raises the same create-note/entity menu as the reader.
  const bodyRef = useRef<HTMLDivElement>(null);

  const handleListen = async () => {
    if (isSpeaking) {
      if (isTtsForThis) stopAudio();
      else stopSpeech();
      return;
    }
    const scope = label ? ` for ${label}` : "";
    const paragraphs = extractSpeechParagraphs(
      fullBodyRef.current,
      `Daily summary${scope}`,
    );
    if (paragraphs.length === 0) return;
    const title = `Daily summary${label ? ` — ${label}` : ""}`;
    const speakViaBrowser = () =>
      playSpeech({
        entryId: speechEntryId,
        title,
        feedTitle: "IntelFeed — Daily Summary",
        paragraphs,
      });
    if (readAloudEngine === "piper") {
      // Text is resolved server-side from the cached summary (matches the morning
      // pre-generation); pass the same filters used to fetch it. Falls back to the
      // browser voice (reading the rendered paragraphs) if Piper is unavailable.
      const ok = await tts.start({
        source: "summary",
        id: dayKey,
        filters: filters as unknown as Record<string, unknown>,
        track: { entryId: speechEntryId, title, feedTitle: "IntelFeed — Daily Summary" },
      });
      if (ok) return;
      if (speechSupported) speakViaBrowser();
      return;
    }
    speakViaBrowser();
  };
  const dayWin = useMemo(() => dayWindowIso(dayKey), [dayKey]);
  // Only fetch entities once we actually have a summary to highlight against.
  const hasSummary = !!cached?.summary;
  const { data: dayEntities } = useDayEntities(
    dayKey,
    dayWin?.since ?? null,
    dayWin?.before ?? null,
    { feed_id: filters.feed_id, category_id: filters.category_id },
    hasSummary,
  );
  // The remark plugin highlights entity mentions as anchors at the markdown-AST
  // level (safe — react-markdown owns the DOM), and `entityByHref` maps each
  // anchor's href back to a rich HighlightEntity so hovering it shows the same
  // popover the entry reader uses. Both are built in one pass: each entity emits
  // one link per surface form (matched_names first — the exact wording the model
  // saw — then name/aliases), all pointing at the same href + metadata.
  const { linkEntities, entityByHref } = useMemo(() => {
    const links: RemarkEntityLink[] = [];
    const byHref = new Map<string, HighlightEntity>();
    if (!dayEntities) return { linkEntities: links, entityByHref: byHref };

    const register = (
      remarkType: string,
      href: string,
      entity: HighlightEntity,
      values: string[],
    ) => {
      byHref.set(href, entity);
      const seen = new Set<string>();
      for (const v of values) {
        if (!v) continue;
        const key = v.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        links.push({ type: remarkType, value: v, href });
      }
    };

    for (const c of dayEntities.cves) {
      register("cve", `/workbench/cve/${c.id}`, {
        id: c.id,
        type: "cve",
        value: c.cve_id,
        cveMeta: {
          cvss_score: c.cvss_score,
          severity: c.severity,
          description: c.description,
          exploit_status: c.exploit_status,
          first_seen_at: c.first_seen_at ?? "",
          epss_score: c.epss_score,
          is_kev: c.is_kev,
          github_poc_count: c.github_poc_count,
          metasploit_module: c.metasploit_module,
        },
      }, [c.cve_id]);
    }
    for (const t of dayEntities.ttps) {
      register("ttp", `/workbench/ttp/${t.id}`, {
        id: t.id,
        type: "ttp",
        value: t.technique_id,
        ttpMeta: {
          technique_id: t.technique_id,
          technique_name: t.technique_name,
          tactic: t.tactic,
          description: t.description,
          article_count: t.article_count,
          first_seen_at: t.first_seen_at ?? "",
        },
      }, [t.technique_id, t.technique_name]);
    }

    function registerNamed<
      T extends { id: string; name: string; aliases: string[]; matched_names: string[] },
    >(
      type: HighlightEntity["type"],
      remarkType: string,
      hrefBase: string,
      items: T[],
      metaFor: (item: T) => HighlightEntityMeta,
    ) {
      for (const it of items) {
        register(
          remarkType,
          `${hrefBase}/${it.id}`,
          { id: it.id, type, value: it.name, meta: metaFor(it) },
          [...(it.matched_names ?? []), it.name, ...it.aliases],
        );
      }
    }
    registerNamed("threat_actor", "threat_actor", "/workbench/threat_actor", dayEntities.actors, actorMeta);
    registerNamed("malware", "malware", "/workbench/malware", dayEntities.malware, malwareMeta);
    registerNamed("vendor", "vendor", "/workbench/vendor", dayEntities.vendors, vendorMeta);
    registerNamed("product", "product", "/workbench/product", dayEntities.products, productMeta);
    registerNamed("country", "country", "/workbench/country", dayEntities.countries, countryMeta);
    registerNamed("tool", "tool", "/workbench/tool", dayEntities.tools, toolMeta);

    for (const m of dayEntities.mitigations) {
      register("mitigation", `/workbench/mitigation/${m.id}`, {
        id: m.id,
        type: "mitigation",
        value: m.name,
        meta: {
          description: m.description,
          aliases: [],
          facts: m.mitre_id ? [{ label: "MITRE ID", value: m.mitre_id }] : [],
          links: withWiki(
            m.mitre_url ? [{ label: "MITRE ATT&CK", url: m.mitre_url }] : [],
            m.wikipedia_url,
          ),
          image_url: m.wikipedia_image_url,
          article_count: m.article_count,
          first_seen_at: m.first_seen_at ?? undefined,
        },
      }, [m.name, m.mitre_id ?? ""]);
    }
    return { linkEntities: links, entityByHref: byHref };
  }, [dayEntities]);

  // IMPORTANT: pass as [plugin, options] tuple — not remarkEntityLinks(linkEntities).
  // The latter returns the transformer, and unified then treats the transformer
  // itself as the plugin, calls it with undefined as args, and never registers a
  // real transformer — so `tree` ends up undefined inside our walker.
  const remarkPlugins = useMemo<PluggableList>(
    () => [remarkGfm, [remarkEntityLinks, linkEntities]],
    [linkEntities],
  );

  // Hover popover state — driven by the entity anchors the remark plugin emits.
  // Opening on a 300ms hover-in delay (matching the reader) and closing on
  // outside-click / Escape (handled inside EntityPopover) means we never touch
  // react-markdown's DOM, so React reconciliation stays intact.
  const [popover, setPopover] = useState<{ entity: HighlightEntity; x: number; y: number } | null>(null);
  const hoverTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const selectEntity = useIntelStore((s) => s.selectEntity);

  const openPopoverFor = (href: string | undefined, el: HTMLElement) => {
    if (!href) return;
    const entity = entityByHref.get(href);
    if (!entity) return;
    const rect = el.getBoundingClientRect();
    setPopover({ entity, x: rect.left + rect.width / 2, y: rect.bottom + 4 });
  };
  // Collapsed by default. The divider component remounts whenever the view
  // mode changes (magazine ↔ list ↔ compact) or the page reloads, so an
  // "expanded by default" default would re-expand on every remount and force
  // the user to re-collapse it. Showing it collapsed keeps the list scannable;
  // the user clicks Expand when they want to read.
  const [showFull, setShowFull] = useState(false);

  // While the initial cache lookup is in flight, show nothing — avoids a flash
  // of the "Summarize" button only to be replaced by an existing summary.
  if (cacheLoading) return null;

  const summary = cached?.summary ?? null;
  const isGenerating = generate.isPending;
  const errorMessage = (() => {
    const err = generate.error as { response?: { data?: { message?: string } } } | null;
    if (!err) return null;
    return err.response?.data?.message ?? (generate.error as Error)?.message ?? "Generation failed";
  })();

  const handleGenerate = (force: boolean) => {
    const win = dayWindowIso(dayKey);
    if (!win) return;
    generate.mutate({
      day_key: dayKey,
      since: win.since,
      before: win.before,
      filters,
      force,
    });
  };

  if (!summary) {
    if (dayCount < 2) return null; // a single article doesn't need a day summary
    return (
      <div className={styles.row}>
        <button
          type="button"
          className={styles.generateBtn}
          disabled={isGenerating}
          onClick={(e) => {
            e.stopPropagation();
            handleGenerate(false);
          }}
          title={isGenerating ? "Summarizing…" : `AI-summarize ${label === "Today" ? "today's" : "this day's"} coverage`}
          aria-label={isGenerating ? "Summarizing…" : "Summarize day"}
        >
          {isGenerating ? (
            <span className={styles.spinner} aria-hidden />
          ) : (
            <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden>
              <path d="M8 1.5l1.2 3.3L12.5 6l-3.3 1.2L8 10.5l-1.2-3.3L3.5 6l3.3-1.2L8 1.5z" />
              <path d="M13 9l.6 1.7L15.3 11l-1.7.6L13 13.3l-.6-1.7L10.7 11l1.7-.6L13 9z" />
            </svg>
          )}
          {/* The label is the feature's advertisement — an icon alone reads as
              decoration, and this is one of the most guest-impressive features. */}
          <span className={styles.generateLabel}>
            {isGenerating ? "Summarizing…" : label === "Today" ? "Catch me up" : "Summarize day"}
          </span>
        </button>
        {errorMessage && <span className={styles.error}>{errorMessage}</span>}
      </div>
    );
  }

  return (
    <div className={styles.panel}>
      <div className={styles.panelHeader}>
        <Hint
          title="Day summary"
          body="What the day's articles were actually about, written from the articles themselves."
          aside="Hover any name in it for that entity's dossier."
        >
          <span className={styles.panelLabel}>AI summary</span>
        </Hint>
        <button
          type="button"
          className={styles.linkBtn}
          onClick={(e) => {
            e.stopPropagation();
            setShowFull((v) => !v);
          }}
        >
          {showFull ? "Collapse" : "Expand"}
        </button>
        {readAloudAvailable && (
          <button
            type="button"
            className={styles.linkBtn}
            aria-pressed={isSpeaking}
            onClick={(e) => {
              e.stopPropagation();
              void handleListen();
            }}
            title={isSpeaking ? "Stop reading" : "Read this summary aloud"}
          >
            {isSpeaking ? "Stop" : tts.isPreparing ? "Generating…" : "Listen"}
          </button>
        )}
        <button
          type="button"
          className={styles.linkBtn}
          disabled={isGenerating}
          onClick={(e) => {
            e.stopPropagation();
            handleGenerate(true);
          }}
          title="Regenerate (uses tokens)"
        >
          {isGenerating ? "Regenerating…" : "Regenerate"}
        </button>
      </div>
      {/* Offscreen full-summary render — extraction source for read-aloud so we
          speak the whole summary even when the visible body shows only the TL;DR. */}
      <div ref={fullBodyRef} aria-hidden style={{ display: "none" }}>
        <Markdown remarkPlugins={remarkPlugins}>{summary}</Markdown>
      </div>
      <div ref={bodyRef} className={`${styles.body} ${showFull ? styles.bodyExpanded : ""}`} data-untrusted-content="">
        <Markdown
          remarkPlugins={remarkPlugins}
          components={{
            a: ({ href, children, ...rest }) => {
              const entityType = entityTypeFromHref(href);
              if (entityType) {
                // Entity mention — styled underline + hover popover (the same
                // popover the entry reader shows), and click still navigates.
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
                      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
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
          }}
        >
          {showFull ? summary : tldrOnly(summary)}
        </Markdown>
      </div>
      {errorMessage && <div className={styles.error}>{errorMessage}</div>}
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
      <SummarySelectionMenu containerRef={bodyRef} />
    </div>
  );
}
