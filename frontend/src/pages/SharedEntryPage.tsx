import { useState, useMemo, useRef, useCallback } from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import axios from "axios";
import { SafeHTML } from "@/components/SafeHTML";
import { FindInArticle } from "@/components/FindInArticle";
import { ReaderTypography } from "@/components/ReaderTypography";
import { SpeechHighlighter } from "@/components/SpeechHighlighter";
import { ToolbarDropdown, DropdownItem } from "@/components/ToolbarDropdown";
import { InlineEntityHighlighter, type HighlightEntity, type HighlightEntityMeta } from "@/components/InlineEntityHighlighter";
import { actorMeta, malwareMeta, vendorMeta, productMeta, toolMeta, countryMeta, mitigationMeta } from "@/utils/entityPopoverMeta";
import type { TTP, CVE, ThreatActor, MalwareFamily, EntryCountry, Mitigation, OffensiveTool, Vendor, Product } from "@/api/types";
import { GlossaryTooltip } from "@/components/GlossaryTooltip";
import { IntelFeedLogo } from "@/components/IntelFeedLogo";
import { RouteFallback } from "@/components/RouteFallback";
import WorkbenchPanel from "@/components/WorkbenchPanel";
import EntryAIPanel from "@/components/EntryAIPanel";
import type { RunTaskResult } from "@/components/AIAnalysisSection";
import { useUIStore } from "@/stores/uiStore";
import { usePlayerStore } from "@/stores/playerStore";
import { useTts } from "@/hooks/useTts";
import { formatDateTime } from "@/utils/formatDate";
import { extractSpeechParagraphs } from "@/utils/speechPreprocess";
import { toast } from "sonner";
import readerStyles from "@/components/EntryReader.module.css";
import { Chip } from "@/components/primitives/Chip";
import styles from "./SharedEntryPage.module.css";

// --- Client-side export helpers (no auth needed, data already loaded) ---

function downloadFile(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function stripHtml(html: string): string {
  const div = document.createElement("div");
  div.innerHTML = html;
  return div.textContent || "";
}

function entryToMarkdown(entry: SharedEntryData): string {
  const lines: string[] = [];
  lines.push(`# ${entry.title}\n`);
  const meta: string[] = [];
  if (entry.feed_title) meta.push(`**Source:** ${entry.feed_title}`);
  if (entry.author) meta.push(`**Author:** ${entry.author}`);
  if (entry.published_at) meta.push(`**Published:** ${new Date(entry.published_at).toLocaleDateString()}`);
  if (entry.url) meta.push(`**URL:** ${entry.url}`);
  if (meta.length) lines.push(meta.join(" | ") + "\n");
  lines.push("---\n");
  if (entry.content_text) {
    lines.push(entry.content_text + "\n");
  } else if (entry.content_html) {
    lines.push(stripHtml(entry.content_html) + "\n");
  } else if (entry.summary) {
    lines.push(entry.summary + "\n");
  }
  if (entry.notes.length > 0) {
    lines.push("\n---\n\n## Analyst Notes\n");
    for (const note of entry.notes) {
      lines.push(`### ${note.is_pinned ? "📌 " : ""}${note.title}\n`);
      lines.push((note.content_markdown || stripHtml(note.content_html || "")) + "\n");
    }
  }
  return lines.join("\n");
}

function intelToMarkdown(entry: SharedEntryData): string {
  const lines: string[] = [];
  lines.push(`# Intelligence: ${entry.title}\n`);
  if (entry.ttps.length) {
    lines.push("## MITRE ATT&CK TTPs\n");
    lines.push("| Technique | Name | Tactic |");
    lines.push("|-----------|------|--------|");
    for (const t of entry.ttps) lines.push(`| ${t.technique_id} | ${t.technique_name} | ${t.tactic || ""} |`);
    lines.push("");
  }
  if (entry.cves.length) {
    lines.push("## CVEs\n");
    lines.push("| CVE | CVSS | Severity | Priority |");
    lines.push("|-----|------|----------|----------|");
    for (const c of entry.cves) lines.push(`| ${c.cve_id} | ${c.cvss_score ?? ""} | ${c.severity || ""} | ${c.priority || ""} |`);
    lines.push("");
  }
  if (entry.threat_actors.length) {
    lines.push("## Threat Actors\n");
    for (const a of entry.threat_actors) {
      lines.push(`- **${a.name}**${a.country ? ` (${a.country})` : ""}${a.motivation ? ` — ${a.motivation}` : ""}${a.aliases.length ? ` aka ${a.aliases.join(", ")}` : ""}`);
    }
    lines.push("");
  }
  if (entry.malware.length) {
    lines.push("## Malware\n");
    for (const m of entry.malware) {
      lines.push(`- **${m.name}**${m.malware_type ? ` (${m.malware_type})` : ""}${m.aliases.length ? ` aka ${m.aliases.join(", ")}` : ""}`);
    }
    lines.push("");
  }
  if (entry.countries.length) {
    lines.push("## Countries\n");
    for (const c of entry.countries) lines.push(`- ${c.iso_code || ""} ${c.name}${c.role ? ` — ${c.role}` : ""}`);
    lines.push("");
  }
  if (entry.mitigations.length) {
    lines.push("## Mitigations\n");
    for (const m of entry.mitigations) lines.push(`- ${m.mitre_id || ""} ${m.name}`);
    lines.push("");
  }
  if (entry.tools.length) {
    lines.push("## Tools\n");
    for (const t of entry.tools) lines.push(`- **${t.name}**${t.tool_type ? ` (${t.tool_type})` : ""}`);
    lines.push("");
  }
  if (entry.vendors?.length) {
    lines.push("## Vendors\n");
    for (const v of entry.vendors) lines.push(`- **${v.name}**${v.vendor_type ? ` (${v.vendor_type})` : ""}`);
    lines.push("");
  }
  if (entry.products?.length) {
    lines.push("## Products\n");
    for (const p of entry.products) lines.push(`- **${p.name}**${p.product_type ? ` (${p.product_type})` : ""}${p.vendor_name ? ` by ${p.vendor_name}` : ""}`);
    lines.push("");
  }
  if (entry.detection_rules.length) {
    lines.push("## Detection Rules\n");
    for (const r of entry.detection_rules) {
      lines.push(`### ${r.title} (${r.rule_type.replace(/_/g, " ").toUpperCase()})\n`);
      lines.push("```");
      lines.push(r.rule_content);
      lines.push("```\n");
    }
  }
  return lines.join("\n");
}

function intelToCsv(entry: SharedEntryData): string {
  const rows: string[][] = [["Type", "ID", "Name", "Details"]];
  for (const t of entry.ttps) rows.push(["TTP", t.technique_id, t.technique_name, t.tactic || ""]);
  for (const c of entry.cves) rows.push(["CVE", c.cve_id, c.severity || "", `CVSS ${c.cvss_score ?? ""}`]);
  for (const a of entry.threat_actors) rows.push(["Threat Actor", "", a.name, a.country || ""]);
  for (const m of entry.malware) rows.push(["Malware", "", m.name, m.malware_type || ""]);
  for (const c of entry.countries) rows.push(["Country", c.iso_code || "", c.name, c.role || ""]);
  for (const m of entry.mitigations) rows.push(["Mitigation", m.mitre_id || "", m.name, ""]);
  for (const t of entry.tools) rows.push(["Tool", "", t.name, t.tool_type || ""]);
  for (const v of (entry.vendors || [])) rows.push(["Vendor", "", v.name, v.vendor_type || ""]);
  for (const p of (entry.products || [])) rows.push(["Product", "", p.name, p.product_type || ""]);
  for (const r of entry.detection_rules) rows.push(["Detection Rule", r.rule_type, r.title, r.severity || ""]);
  return rows.map((r) => r.map((c) => `"${c.replace(/"/g, '""')}"`).join(",")).join("\n");
}

function SharedQuickExportBar({ entry }: { entry: SharedEntryData }) {
  const [flash, setFlash] = useState<string | null>(null);
  const showFlash = (msg: string) => { setFlash(msg); setTimeout(() => setFlash(null), 2000); };

  const handleExport = (format: "csv" | "markdown" | "clipboard") => {
    const safeTitle = entry.title.slice(0, 50).replace(/[/\\]/g, "-");
    if (format === "csv") {
      downloadFile(intelToCsv(entry), `${safeTitle}-intel.csv`, "text/csv");
      showFlash("Downloaded");
    } else if (format === "markdown") {
      downloadFile(intelToMarkdown(entry), `${safeTitle}-intel.md`, "text/markdown");
      showFlash("Downloaded");
    } else {
      navigator.clipboard.writeText(intelToMarkdown(entry));
      showFlash("Copied!");
    }
  };

  return (
    <div className={styles.quickExportBar}>
      <span className={styles.quickExportLabel}>Export:</span>
      {(["csv", "markdown", "clipboard"] as const).map((fmt) => (
        <button key={fmt} className={styles.quickExportBtn} onClick={() => handleExport(fmt)}>
          {fmt === "clipboard" ? "Clipboard" : fmt.toUpperCase()}
        </button>
      ))}
      {flash && <span className={styles.quickExportFlash}>{flash}</span>}
    </div>
  );
}

interface SharedNote {
  id: string;
  title: string;
  content_markdown: string;
  content_html: string | null;
  tags: string[];
  is_pinned: boolean;
  created_at: string;
  updated_at: string;
}

interface SharedEntryData {
  id: string;
  title: string;
  author: string | null;
  url: string | null;
  content_html: string | null;
  content_text: string | null;
  summary: string | null;
  published_at: string | null;
  fetched_at: string;
  word_count: number | null;
  image_url: string | null;
  feed_title: string | null;
  feed_type: string | null;
  metadata: Record<string, unknown> | null;
  media: Array<{ id: string; media_type: string; url: string; thumbnail_url: string | null; duration_seconds: number | null }>;
  // Entity arrays use the full API types — the public endpoint returns the same
  // response schemas as the authenticated intelligence endpoints, so the rich
  // popover fields (description, wikipedia thumbnail, platforms, …) are present.
  ttps: TTP[];
  cves: CVE[];
  threat_actors: ThreatActor[];
  malware: MalwareFamily[];
  countries: EntryCountry[];
  mitigations: Mitigation[];
  tools: OffensiveTool[];
  vendors: Vendor[];
  products: Product[];
  detection_rules: Array<{
    id: string; rule_type: string; title: string; description: string | null;
    rule_content: string; severity: string | null;
  }>;
  glossary_matches: Array<{
    term: {
      id: string; name: string; category: string; description: string;
      search_terms: string[];
    };
    match_count: number;
  }>;
  referenced_urls: Array<{ url: string; context: string }>;
  ai_results: Array<{
    id: string; target_type: string | null; target_id: string | null;
    is_current: boolean; task_id: string; task_name: string | null;
    model_name: string | null; parsed_result: Record<string, unknown> | null;
    cost_estimate: string | null; created_at: string | null;
  }>;
  ai_tasks: Array<{
    id: string; name: string; display_name: string; description: string | null;
    category: string | null; variables: string[]; is_system: boolean;
    created_at: string | null;
  }>;
  notes: SharedNote[];
  shared_at: string;
}

const publicApi = axios.create({ baseURL: "/api", timeout: 15000 });

function useSharedEntry(token: string | undefined) {
  return useQuery({
    queryKey: ["shared-entry", token],
    queryFn: async () => {
      const { data } = await publicApi.get<SharedEntryData>(`/shared/${token}`);
      return data;
    },
    enabled: !!token,
    retry: false,
    staleTime: 60_000,
  });
}

export function SharedEntryPage() {
  const { token } = useParams<{ token: string }>();
  const { data: entry, isLoading, error } = useSharedEntry(token);
  const [showFind, setShowFind] = useState(false);
  const [showSidePanel, setShowSidePanel] = useState(false);
  const [sharedPanelTab, setSharedPanelTab] = useState<"intel" | "ai" | "notes">("intel");
  const articleContentRef = useRef<HTMLDivElement>(null);
  const articleHeaderRef = useRef<HTMLElement>(null);
  const readerFontSize = useUIStore((s) => s.readerFontSize);
  const readerLineHeight = useUIStore((s) => s.readerLineHeight);
  const readerMaxWidth = useUIStore((s) => s.readerMaxWidth);
  const sidePanelWidth = useUIStore((s) => s.sidePanelWidth);
  const playSpeech = usePlayerStore((s) => s.playSpeech);
  const stopSpeech = usePlayerStore((s) => s.stopSpeech);
  const stopAudio = usePlayerStore((s) => s.stop);
  const speechTrack = usePlayerStore((s) => s.speechTrack);
  const currentTrack = usePlayerStore((s) => s.currentTrack);
  const playerMode = usePlayerStore((s) => s.mode);
  const playerIsPlaying = usePlayerStore((s) => s.isPlaying);
  const readAloudEngine = useUIStore((s) => s.readAloudEngine);
  const tts = useTts({ shareToken: token });

  const articleBodyStyle = useMemo<React.CSSProperties>(() => ({
    fontSize: `${readerFontSize}px`,
    lineHeight: readerLineHeight,
    maxWidth: readerMaxWidth === 0 ? "none" : `${readerMaxWidth}px`,
  }), [readerFontSize, readerLineHeight, readerMaxWidth]);

  const articlePaneStyle = useMemo<React.CSSProperties>(() => ({
    ["--reader-col-width" as string]: readerMaxWidth === 0 ? "none" : `${readerMaxWidth + 64}px`,
    ["--reader-col-inner" as string]: readerMaxWidth === 0 ? "none" : `${readerMaxWidth}px`,
  }), [readerMaxWidth]);

  const highlightEntities = useMemo<HighlightEntity[]>(() => {
    if (!entry) return [];
    const entities: HighlightEntity[] = [];
    for (const cve of entry.cves) {
      entities.push({
        id: cve.id, type: "cve", value: cve.cve_id,
        cveMeta: {
          cvss_score: cve.cvss_score, severity: cve.severity,
          description: cve.description, exploit_status: cve.exploit_status,
          first_seen_at: cve.first_seen_at, article_count: cve.article_count,
          epss_score: cve.epss_score, is_kev: cve.is_kev,
          github_poc_count: cve.github_poc_count,
          metasploit_module: cve.metasploit_module, risk_tier: cve.risk_tier,
        },
      });
    }
    for (const ttp of entry.ttps) {
      const ttpMeta = {
        technique_id: ttp.technique_id, technique_name: ttp.technique_name,
        tactic: ttp.tactic, description: ttp.description,
        article_count: ttp.article_count, first_seen_at: ttp.first_seen_at,
      };
      if (ttp.technique_id) entities.push({ id: ttp.id, type: "ttp", value: ttp.technique_id, ttpMeta });
      if (ttp.technique_name) entities.push({ id: ttp.id, type: "ttp", value: ttp.technique_name, ttpMeta });
    }
    // Prefer matched_names (the exact surface forms the backend detected with
    // word-boundary checks). Fall back to name + aliases when none are recorded.
    const pushFor = <T extends { id: string; name: string; aliases?: string[] | null; matched_names?: string[] | null }>(
      type: HighlightEntity["type"],
      item: T,
      meta?: HighlightEntityMeta,
    ) => {
      if (item.matched_names && item.matched_names.length > 0) {
        for (const value of item.matched_names) {
          entities.push({ id: item.id, type, value, meta });
        }
        return;
      }
      entities.push({ id: item.id, type, value: item.name, meta });
      for (const alias of item.aliases ?? []) {
        entities.push({ id: item.id, type, value: alias, meta });
      }
    };
    for (const actor of entry.threat_actors) pushFor("threat_actor", actor, actorMeta(actor));
    for (const m of entry.malware) pushFor("malware", m, malwareMeta(m));
    for (const c of entry.countries) pushFor("country", c, countryMeta(c));
    for (const v of entry.vendors ?? []) pushFor("vendor", v, vendorMeta(v));
    for (const p of entry.products ?? []) pushFor("product", p, productMeta(p));
    for (const t of entry.tools ?? []) pushFor("tool", t, toolMeta(t));
    for (const m of entry.mitigations ?? []) {
      const meta = mitigationMeta(m);
      if (m.name) entities.push({ id: m.id, type: "mitigation", value: m.name, meta });
      if (m.mitre_id) entities.push({ id: m.id, type: "mitigation", value: m.mitre_id, meta });
    }
    return entities;
  }, [entry]);

  const glossaryTermsForHighlight = useMemo(
    () => entry?.glossary_matches?.map((m) => ({
      id: m.term.id,
      name: m.term.name,
      category: m.term.category,
      search_terms: m.term.search_terms,
    })) ?? [],
    [entry],
  );

  const glossaryMatches = useMemo(
    () => entry?.glossary_matches?.map((m) => ({
      term: {
        ...m.term,
        maturity: null, long_description: null, technologies: [],
        is_system: false, created_by: null, created_at: "", updated_at: "",
      },
      match_count: m.match_count,
    })) ?? [],
    [entry],
  );

  // WorkbenchPanel preloaded data (entity arrays already use the API types;
  // detection_rules keeps a narrow shared shape, so it still needs a cast)
  const preloadedData = useMemo(() => {
    if (!entry) return undefined;
    return {
      ttps: entry.ttps,
      cves: entry.cves,
      actors: entry.threat_actors,
      malware: entry.malware,
      countries: entry.countries,
      mitigations: entry.mitigations,
      tools: entry.tools,
      vendors: entry.vendors,
      products: entry.products,
      rules: entry.detection_rules as unknown as import("@/api/types").DetectionRule[],
      urls: entry.referenced_urls || [],
    };
  }, [entry]);

  // AI tasks from shared response
  const aiTasks = useMemo(
    () => (entry?.ai_tasks || []) as unknown as import("@/api/types").AITask[],
    [entry],
  );

  // AI results already run — build set of completed task names + static results array
  const aiCompletedTasks = useMemo(
    () => new Set((entry?.ai_results || []).map((r) => r.task_name).filter(Boolean) as string[]),
    [entry],
  );

  const aiStaticResults = useMemo(
    () => (entry?.ai_results || []) as unknown as import("@/api/types").AIResult[],
    [entry],
  );

  // AI run function for shared pages — calls public endpoint with one-time enforcement
  const aiRunTaskFn = useCallback(async (taskName: string): Promise<RunTaskResult> => {
    const { data } = await publicApi.post<RunTaskResult>(`/shared/${token}/run-ai-task`, { task_name: taskName }, { timeout: 120000 });
    return data;
  }, [token]);

  if (isLoading) {
    return <RouteFallback />;
  }

  if (error || !entry) {
    const is404 = axios.isAxiosError(error) && error.response?.status === 404;
    const is410 = axios.isAxiosError(error) && error.response?.status === 410;
    return (
      <div className={styles.errorContainer}>
        <div className={styles.errorTitle}>{is410 ? "Link Expired" : is404 ? "Not Found" : "Error"}</div>
        <div className={styles.errorMessage}>
          {is410 ? "This share link has expired." : is404 ? "This share link doesn't exist or has been revoked." : "Something went wrong loading this article."}
        </div>
      </div>
    );
  }

  const readTime = entry.word_count ? Math.max(1, Math.round(entry.word_count / 238)) : null;
  const hasNotes = !!entry.notes && entry.notes.length > 0;
  const activeTab = sharedPanelTab === "notes" && !hasNotes ? "intel" : sharedPanelTab;
  const openPanelTab = (tab: "intel" | "ai" | "notes") => {
    if (showSidePanel && activeTab === tab) setShowSidePanel(false);
    else { setSharedPanelTab(tab); setShowSidePanel(true); }
  };
  const isSpeechActive = playerMode === "speech" && !!speechTrack && playerIsPlaying;
  const isSpeechForThisEntry = isSpeechActive && speechTrack?.entryId === entry.id;
  const isTtsForThisEntry =
    playerMode === "audio" && currentTrack?.kind === "tts" && currentTrack?.entryId === entry.id;
  const isReadingThisEntry = isSpeechForThisEntry || isTtsForThisEntry;

  const getArticleParagraphs = () => {
    return extractSpeechParagraphs(articleContentRef.current, entry.title);
  };

  return (
    <div className={styles.page}>
      <div className={readerStyles.readerContainer}>
        <article className={readerStyles.articlePane} style={articlePaneStyle}>
          {/* Top bar — matches EntryReader toolbar */}
          <div className={`${readerStyles.topBar} ${styles.topBar}`}>
            <a className={styles.brand} href="/" title="Go to IntelFeed" aria-label="Go to IntelFeed">
              <IntelFeedLogo size={18} className={styles.brandLogo} />
              <span>
                Intel<span className={styles.brandAccent}>Feed</span>
              </span>
            </a>
            <Chip className={styles.sharedBadge}>Shared Article</Chip>
            <div className={readerStyles.topBarActions}>
              <button
                className={`${readerStyles.labelBtn} ${showSidePanel && activeTab === "intel" ? readerStyles.labelBtnActive : ""}`}
                onClick={() => openPanelTab("intel")}
                title="Toggle intel panel"
              >
                Intel
              </button>
              <button
                className={`${readerStyles.labelBtn} ${showSidePanel && activeTab === "ai" ? readerStyles.labelBtnActive : ""}`}
                onClick={() => openPanelTab("ai")}
                title="Toggle AI panel"
              >
                AI
              </button>
              {hasNotes && (
                <button
                  className={`${readerStyles.labelBtn} ${showSidePanel && activeTab === "notes" ? readerStyles.labelBtnActive : ""}`}
                  onClick={() => openPanelTab("notes")}
                  title="Toggle notes panel"
                >
                  Notes
                </button>
              )}
              <div className={readerStyles.topBarDivider} />
              <ReaderTypography />
              <ToolbarDropdown
                label="More"
                icon={
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                    <circle cx="12" cy="5" r="1" />
                    <circle cx="12" cy="12" r="1" />
                    <circle cx="12" cy="19" r="1" />
                  </svg>
                }
              >
                <DropdownItem
                  icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>}
                  label="Export article"
                  onClick={() => {
                    if (!entry) return;
                    const safeTitle = entry.title.slice(0, 50).replace(/[/\\]/g, "-");
                    downloadFile(entryToMarkdown(entry), `${safeTitle}.md`, "text/markdown");
                    toast.success("Article exported");
                  }}
                />
                <DropdownItem
                  icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></svg>}
                  label="Find in article"
                  shortcut="⌘F"
                  active={showFind}
                  onClick={() => setShowFind((v) => !v)}
                />
                {(readAloudEngine === "piper" || "speechSynthesis" in window) && (
                  <DropdownItem
                    icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" /><path d="M19.07 4.93a10 10 0 0 1 0 14.14" /><path d="M15.54 8.46a5 5 0 0 1 0 7.07" /></svg>}
                    label={isReadingThisEntry ? "Stop reading" : tts.isPreparing ? "Generating audio…" : "Read aloud"}
                    active={isReadingThisEntry}
                    onClick={async () => {
                      if (isReadingThisEntry) {
                        if (isTtsForThisEntry) stopAudio();
                        else stopSpeech();
                        return;
                      }
                      const speakViaBrowser = () =>
                        playSpeech({
                          entryId: entry.id,
                          title: entry.title,
                          feedTitle: entry.feed_title || "",
                          paragraphs: getArticleParagraphs(),
                        });
                      if (readAloudEngine === "piper") {
                        const ok = await tts.start({
                          source: "entry",
                          id: entry.id,
                          track: {
                            entryId: entry.id,
                            title: entry.title,
                            feedTitle: entry.feed_title || "",
                            thumbnailUrl: entry.image_url ?? null,
                          },
                        });
                        if (ok) return;
                        if ("speechSynthesis" in window) speakViaBrowser();
                        else toast.error("Read-aloud audio is unavailable right now.");
                        return;
                      }
                      speakViaBrowser();
                    }}
                  />
                )}
                {entry.url && (
                  <DropdownItem
                    icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" /><polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" /></svg>}
                    label="Open original"
                    href={entry.url}
                  />
                )}
                <DropdownItem
                  icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" /><polyline points="10 17 15 12 10 7" /><line x1="15" y1="12" x2="3" y2="12" /></svg>}
                  label="Open in IntelFeed"
                  href={`/?entry=${entry.id}`}
                />
              </ToolbarDropdown>
            </div>
          </div>

          {showFind && (
            <FindInArticle containerRef={articleContentRef} onClose={() => setShowFind(false)} />
          )}

          {/* Article header — matches EntryReader */}
          <header className={readerStyles.header} ref={articleHeaderRef}>
            <div className={readerStyles.meta}>
              {entry.feed_title && <span className={readerStyles.feedName}>{entry.feed_title}</span>}
              {entry.published_at && <span className={readerStyles.date}>{formatDateTime(entry.published_at)}</span>}
            </div>
            <h1 className={readerStyles.title}>{entry.title}</h1>
            <div className={readerStyles.byline}>
              {entry.author && <span>By {entry.author}</span>}
              {readTime && <span>{readTime} min read</span>}
            </div>
          </header>

          {/* Article content */}
          <div className={`${readerStyles.content} ${isSpeechForThisEntry ? readerStyles.speechActive : ""}`} ref={articleContentRef}>
            {entry.content_html ? (
              <SafeHTML html={entry.content_html} className={readerStyles.articleBody} style={articleBodyStyle} glossaryTerms={glossaryTermsForHighlight} />
            ) : entry.summary ? (
              <SafeHTML html={`<p>${entry.summary}</p>`} className={readerStyles.articleBody} style={articleBodyStyle} glossaryTerms={glossaryTermsForHighlight} />
            ) : (
              <p className={readerStyles.noContent}>
                No content available.{" "}
                {entry.url && <a href={entry.url} target="_blank" rel="noopener noreferrer">Open original article</a>}
              </p>
            )}
            {glossaryMatches.length > 0 && (
              <GlossaryTooltip containerRef={articleContentRef} matches={glossaryMatches} />
            )}
            <InlineEntityHighlighter
              containerRef={articleContentRef}
              entities={highlightEntities}
              enabled={true}
              disableNavigation={true}
            />
            <SpeechHighlighter
              entryId={entry.id}
              hasTitle={!!entry.title}
              headerRef={articleHeaderRef}
              contentRef={articleContentRef}
            />
          </div>
        </article>

        {/* Side panel — content driven by the Intel / AI / Notes header buttons */}
        {showSidePanel && (
          <div className={readerStyles.sidePanel} style={{ width: sidePanelWidth }}>
            <div className={readerStyles.sidePanelHeader}>
              <span className={readerStyles.sidePanelTitle}>
                {activeTab === "intel" ? "Intel" : activeTab === "ai" ? "AI" : "Notes"}
              </span>
              <div className={readerStyles.sidePanelHeaderActions}>
                <button className={readerStyles.sidePanelClose} onClick={() => setShowSidePanel(false)}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <line x1="18" y1="6" x2="6" y2="18" />
                    <line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                </button>
              </div>
            </div>
            <div className={readerStyles.sidePanelContent}>
              {activeTab === "intel" && (
                <>
                  <SharedQuickExportBar entry={entry} />
                  <WorkbenchPanel
                    entryId={entry.id}
                    entryTitle={entry.title}
                    readOnly={true}
                    preloadedData={preloadedData}
                  />
                </>
              )}
              {activeTab === "ai" && (
                <EntryAIPanel
                  entryId={entry.id}
                  entryTitle={entry.title}
                  readOnly={true}
                  aiTasks={aiTasks}
                  aiRunTaskFn={aiRunTaskFn}
                  aiCompletedTasks={aiCompletedTasks}
                  aiStaticResults={aiStaticResults}
                  aiAskAgentFn={async (question, history) => {
                    const { data } = await publicApi.post(`/shared/${token}/ask-agent`, { question, history }, { timeout: 120000 });
                    return data;
                  }}
                />
              )}
              {activeTab === "notes" && hasNotes && (
                <div className={styles.sharedNotes}>
                  <div className={styles.sharedNotesTitle}>Analyst Notes</div>
                  {entry.notes.map((note) => (
                    <div key={note.id} className={styles.sharedNoteCard}>
                      <div className={styles.sharedNoteName}>
                        {note.is_pinned && <span style={{ marginRight: "0.25rem" }}>&#128204;</span>}
                        {note.title}
                      </div>
                      {note.content_html ? (
                        <div className={styles.sharedNoteBody} dangerouslySetInnerHTML={{ __html: note.content_html }} />
                      ) : note.content_markdown ? (
                        <div className={styles.sharedNoteBody}>{note.content_markdown}</div>
                      ) : null}
                      {note.tags.length > 0 && (
                        <div className={styles.sharedNoteTags}>
                          {note.tags.map((t) => (
                            <Chip key={t} pill truncate>
                              {t}
                            </Chip>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
