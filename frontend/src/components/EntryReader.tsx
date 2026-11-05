import { useState, useMemo, useRef, useEffect, useCallback } from "react";
import { toast } from "sonner";
import api from "@/api/client";
import { useEntry, useToggleStar, useToggleBookmark, useMarkRead, useMarkUnread, useSimilarEntries, useTranslateEntry } from "@/hooks/useEntries";
import { useFeeds } from "@/hooks/useFeeds";
import { exportEntry } from "@/hooks/useExport";
import { useUIStore } from "@/stores/uiStore";
import { adjacentEntryId } from "@/utils/entryNavigation";
import { useOpenSavedSearch } from "@/hooks/useOpenSavedSearch";
import { usePlayerStore } from "@/stores/playerStore";
import { useExistingTts, useTts } from "@/hooks/useTts";
import { useAuthStore, useIsVisitor } from "@/stores/authStore";
import { useReadingPrefs } from "@/hooks/useReadingPrefs";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { useSwipe } from "@/hooks/useSwipe";
import { SafeHTML } from "@/components/SafeHTML";
import { useDetectGlossaryTerms } from "@/hooks/useGlossary";
import { formatDateTime } from "@/utils/formatDate";
import { extractSpeechParagraphs } from "@/utils/speechPreprocess";
import { YouTubePlayer } from "@/components/YouTubePlayer";
import { EntryNotePanel } from "@/components/EntryNotePanel";
import { TagInput } from "@/components/TagInput";
import { ToolbarDropdown, DropdownItem } from "@/components/ToolbarDropdown";
import { ResizeHandle } from "@/components/ResizeHandle";
import { RailToggle } from "@/components/primitives";
import { FeedNameMenuButton } from "@/components/FeedNameMenuButton";
import { EntryPipelineStatus } from "@/components/EntryPipelineStatus";
import { SignalChip } from "@/components/SignalChip";
import WorkbenchPanel from "@/components/WorkbenchPanel";
import EntryAIPanel from "@/components/EntryAIPanel";
import { GlossaryTooltip } from "@/components/GlossaryTooltip";
import { ReaderTOC } from "@/components/ReaderTOC";
import { ArticleSummaryCard } from "@/components/ArticleSummaryCard";
import { WhyRankedCard } from "@/components/WhyRankedCard";
import { InlineEntityHighlighter, type HighlightEntity, type HighlightEntityMeta } from "@/components/InlineEntityHighlighter";
import { actorMeta, malwareMeta, vendorMeta, productMeta, toolMeta, countryMeta, mitigationMeta, cweMeta, observableMeta } from "@/utils/entityPopoverMeta";
import { RuleEntryCard } from "@/components/RuleEntryCard";
import { IntelLevelBadge } from "@/components/IntelLevelBadge";
import { InfoGradeChip } from "@/components/InfoGradeChip";
import { EntryIntelBadges } from "@/components/EntryIntelBadges";
import { SelectionContextMenu } from "@/components/SelectionContextMenu";
import { CreateEntityPanel } from "@/components/CreateEntityPanel";
import { AddAliasPanel } from "@/components/AddAliasPanel";
import { LinkEntityPanel } from "@/components/LinkEntityPanel";
import { FindInArticle } from "@/components/FindInArticle";
import { ReaderTypography } from "@/components/ReaderTypography";
import { SpeechHighlighter } from "@/components/SpeechHighlighter";
import { useEntryCVEs, useEntryTTPs, useEntryThreatActors, useEntryMalware, useEntryCountries, useEntryVendors, useEntryProducts, useEntryTools, useEntryMitigations, useEntryCWEs, useEntryObservables } from "@/hooks/useIntelligence";
import { useEntryIntelBadges } from "@/hooks/useEntryIntelBadges";
import { useIntelStore } from "@/stores/intelStore";
import { useOpenEntry, useOpenThread } from "@/utils/openEntry";
import styles from "./EntryReader.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";
import { Hint } from "@/components/primitives";
import { UploadByline, UploadDownloadItem } from "@/components/EntryUploadInfo";

interface EntryReaderProps {
  entryId: string;
}

function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) return `${h}:${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

function formatYouTubeDescription(html: string): string {
  if (/<br\s*\/?>/i.test(html)) return html;
  const text = html.replace(/<[^>]+>/g, "").trim();
  if (!text) return "";
  // No target here: SafeHTML applies the reader's open-in-new-tab preference.
  const linked = text.replace(
    /(https?:\/\/[^\s<>"')\]]+)/g,
    '<a href="$1" rel="noopener noreferrer">$1</a>',
  );
  const formatted = linked.replace(/\n/g, "<br>\n");
  return `<div>${formatted}</div>`;
}

function formatViewCount(count: number): string {
  if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(1)}M views`;
  if (count >= 1_000) return `${(count / 1_000).toFixed(1)}K views`;
  return `${count} views`;
}

export function EntryReader({ entryId }: EntryReaderProps) {
  const { data: entry, isLoading, error: entryError } = useEntry(entryId);
  const toggleStar = useToggleStar();
  const toggleBookmark = useToggleBookmark();
  const markRead = useMarkRead();
  const markUnread = useMarkUnread();
  const translateEntry = useTranslateEntry();
  const [showTranslated, setShowTranslated] = useState(false);
  const setSelectedEntry = useUIStore((s) => s.setSelectedEntry);
  // Every "open that other article" link in the reader routes through this:
  // docked in the workbench it swaps the dock, in the feed it moves the
  // list selection. Writing the feed selection while docked was a dead click.
  const openEntry = useOpenEntry();
  const openThread = useOpenThread();
  const openCopilotWith = useUIStore((s) => s.openCopilotWith);
  const playTrack = usePlayerStore((s) => s.play);
  // Settings → Reading → "Open links in new tab" (article-body links are
  // handled inside SafeHTML).
  const openLinksNewTab = useReadingPrefs().open_links_new_tab;
  const currentTrack = usePlayerStore((s) => s.currentTrack);
  const activeReaderPanel = useUIStore((s) => s.activeReaderPanel);
  const setActiveReaderPanel = useUIStore((s) => s.setActiveReaderPanel);
  const sidePanelWidth = useUIStore((s) => s.sidePanelWidth);
  const setSidePanelWidth = useUIStore((s) => s.setSidePanelWidth);
  const readerFontSize = useUIStore((s) => s.readerFontSize);
  const readerLineHeight = useUIStore((s) => s.readerLineHeight);
  const readerMaxWidth = useUIStore((s) => s.readerMaxWidth);
  const readerHighlightEntities = useUIStore((s) => s.readerHighlightEntities);
  const openSavedSearch = useOpenSavedSearch();
  const navIds = useUIStore((s) => s.entryNavigationIds);
  const navigateEntry = useUIStore((s) => s.navigateEntry);
  const navTrail = useUIStore((s) => s.entryNavTrail);
  const navTrailIndex = useUIStore((s) => s.entryNavTrailIndex);
  const currentNavIndex = navIds.indexOf(entryId);
  // Prev/Next follow the same list-then-trail rule as j/k, so they stay live on
  // an article auto-read out of the list rather than greying out under you.
  const hasPrev = !!adjacentEntryId("prev", entryId, navIds, navTrail, navTrailIndex);
  const hasNext = !!adjacentEntryId("next", entryId, navIds, navTrail, navTrailIndex);
  const { data: feedsData } = useFeeds();
  const { data: glossaryMatches } = useDetectGlossaryTerms(entryId);
  const articleContentRef = useRef<HTMLDivElement>(null);
  const articleHeaderRef = useRef<HTMLElement>(null);
  const autoOpenIntelPanel = useIntelStore((s) => s.autoOpenIntelPanel);
  const isMobile = useIsMobile();
  const [sidePanelMaximized, setSidePanelMaximized] = useState(false);
  const [noteInitialContent, setNoteInitialContent] = useState<string | undefined>(undefined);
  const [noteKey, setNoteKey] = useState(0);
  const [entityInitialText, setEntityInitialText] = useState<string | undefined>(undefined);
  const [entityKey, setEntityKey] = useState(0);
  const [aliasText, setAliasText] = useState<string | undefined>(undefined);
  const [aliasKey, setAliasKey] = useState(0);
  const [linkEntitySearch, setLinkEntitySearch] = useState<string | undefined>(undefined);
  const [linkEntityKey, setLinkEntityKey] = useState(0);
  const [showFind, setShowFind] = useState(false);
  // Bumped when an in-article glossary tooltip asks the Intel tab to open its Glossary section.
  const [glossaryExpandSignal, setGlossaryExpandSignal] = useState(0);
  const playSpeech = usePlayerStore((s) => s.playSpeech);
  const stopSpeech = usePlayerStore((s) => s.stopSpeech);
  const speechTrack = usePlayerStore((s) => s.speechTrack);
  const playerMode = usePlayerStore((s) => s.mode);
  const playerIsPlaying = usePlayerStore((s) => s.isPlaying);
  const requestSpeechSkip = usePlayerStore((s) => s.requestSpeechSkip);
  const isSpeechActive = playerMode === "speech" && !!speechTrack && playerIsPlaying;
  const isSpeechForThisEntry = isSpeechActive && speechTrack?.entryId === entryId;
  const stopAudio = usePlayerStore((s) => s.stop);
  const readAloudEngine = useUIStore((s) => s.readAloudEngine);
  const tts = useTts();
  // Public read-only mode: a visitor reads, nothing more. No personal state,
  // no AI, nothing that writes or makes the server do work.
  const isVisitor = useIsVisitor();
  const existingAudio = useExistingTts(entryId, isVisitor);
  // The Intel panel is the only one a visitor gets (AI, notes, tags and the
  // entity tools all write or show private work); a shortcut or a persisted
  // choice from a signed-in session must not open another.
  useEffect(() => {
    if (isVisitor && activeReaderPanel && activeReaderPanel !== "intel") setActiveReaderPanel(null);
  }, [isVisitor, activeReaderPanel, setActiveReaderPanel]);
  const isTtsForThisEntry =
    playerMode === "audio" && currentTrack?.kind === "tts" && currentTrack?.entryId === entryId;
  const isReadingThisEntry = isSpeechForThisEntry || isTtsForThisEntry;

  const handleShare = useCallback(async () => {
    try {
      const { data } = await api.post<{ token: string; url: string }>(`/entries/${entryId}/share`);
      const shareUrl = `${window.location.origin}${data.url}`;
      await navigator.clipboard.writeText(shareUrl);
      toast.success("Share link copied to clipboard");
    } catch {
      toast.error("Failed to create share link");
    }
  }, [entryId]);

  // Reset find and similar when entry changes (speech keeps playing in the bottom bar)
  useEffect(() => {
    setShowFind(false);
    setShowSimilar(false);
    setShowTranslated(!!entry?.translated_html);
  }, [entryId, entry?.translated_html]);

  const handleTranslate = useCallback(() => {
    if (!entry) return;
    if (entry.translated_html) {
      setShowTranslated((v) => !v);
      return;
    }
    translateEntry.mutate(
      { entryId },
      {
        onSuccess: () => {
          setShowTranslated(true);
          toast.success("Translated");
        },
        onError: (err: unknown) => {
          const detail = (err as { response?: { data?: { detail?: { message?: string }; message?: string } } })?.response?.data;
          const message = detail?.detail?.message || detail?.message || "Translation failed";
          toast.error(message);
        },
      },
    );
  }, [entry, entryId, translateEntry]);

  // Ctrl+F to open find in article
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "f") {
        // Only intercept if the reader is visible
        if (swipeRef.current) {
          e.preventDefault();
          setShowFind(true);
        }
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Intel badges (used in header + auto-open logic)
  const { data: intelBadges } = useEntryIntelBadges([entryId]);

  // Auto-open workbench panel when setting is enabled
  const lastAutoOpenedRef = useRef<string | null>(null);
  useEffect(() => {
    if (
      autoOpenIntelPanel &&
      !activeReaderPanel &&
      lastAutoOpenedRef.current !== entryId
    ) {
      lastAutoOpenedRef.current = entryId;
      setActiveReaderPanel("intel");
    }
  }, [entryId, autoOpenIntelPanel, activeReaderPanel, setActiveReaderPanel]);

  // Entity highlighting data — always enabled
  const { data: entryCVEs } = useEntryCVEs(entryId);
  const { data: entryTTPs } = useEntryTTPs(entryId);
  const { data: entryCWEs } = useEntryCWEs(entryId);
  const { data: entryObservables } = useEntryObservables(entryId);
  const { data: entryActors } = useEntryThreatActors(entryId);
  const { data: entryMalware } = useEntryMalware(entryId);
  const { data: entryCountries } = useEntryCountries(entryId);
  const { data: entryVendors } = useEntryVendors(entryId);
  const { data: entryProducts } = useEntryProducts(entryId);
  const { data: entryTools } = useEntryTools(entryId);
  const { data: entryMitigations } = useEntryMitigations(entryId);
  const [showSimilar, setShowSimilar] = useState(false);
  const { data: similarData, isLoading: similarLoading } = useSimilarEntries(
    entryId,
    showSimilar,
  );

  const highlightEntities = useMemo<HighlightEntity[]>(() => {
    const entities: HighlightEntity[] = [];
    if (entryCVEs) {
      for (const cve of entryCVEs) {
        entities.push({
          id: cve.id,
          type: "cve",
          value: cve.cve_id,
          cveMeta: {
            cvss_score: cve.cvss_score,
            severity: cve.severity,
            description: cve.description,
            exploit_status: cve.exploit_status,
            first_seen_at: cve.first_seen_at,
            article_count: cve.article_count,
            epss_score: cve.epss_score,
            is_kev: cve.is_kev,
            github_poc_count: cve.github_poc_count,
            metasploit_module: cve.metasploit_module,
            risk_tier: cve.risk_tier,
          },
        });
      }
    }
    if (entryTTPs) {
      for (const ttp of entryTTPs) {
        const ttpMeta = {
          technique_id: ttp.technique_id,
          technique_name: ttp.technique_name,
          tactic: ttp.tactic,
          description: ttp.description,
          article_count: ttp.article_count,
          first_seen_at: ttp.first_seen_at,
        };
        if (ttp.technique_id) {
          entities.push({ id: ttp.id, type: "ttp", value: ttp.technique_id, ttpMeta });
        }
        if (ttp.technique_name) {
          entities.push({ id: ttp.id, type: "ttp", value: ttp.technique_name, ttpMeta });
        }
      }
    }
    // Prefer matched_names (the exact surface forms the backend detected with
    // word-boundary checks). Fall back to name + aliases only when no matched_names
    // are recorded — e.g. AI-extracted entities or pre-migration rows.
    const pushFor = <T extends { id: string; name: string; aliases?: string[] | null; matched_names?: string[] | null }>(
      type: HighlightEntity["type"],
      item: T,
      meta?: HighlightEntityMeta,
    ) => {
      if (item.matched_names && item.matched_names.length > 0) {
        for (const value of item.matched_names) {
          entities.push({ id: item.id, type, value, name: item.name, meta });
        }
        return;
      }
      entities.push({ id: item.id, type, value: item.name, name: item.name, meta });
      for (const alias of item.aliases ?? []) {
        entities.push({ id: item.id, type, value: alias, name: item.name, meta });
      }
    };
    if (entryActors) for (const actor of entryActors) pushFor("threat_actor", actor, actorMeta(actor));
    if (entryMalware) for (const malware of entryMalware) pushFor("malware", malware, malwareMeta(malware));
    if (entryCountries) for (const country of entryCountries) pushFor("country", country, countryMeta(country));
    if (entryVendors) for (const vendor of entryVendors) pushFor("vendor", vendor, vendorMeta(vendor));
    if (entryProducts) for (const product of entryProducts) pushFor("product", product, productMeta(product));
    if (entryTools) for (const tool of entryTools) pushFor("tool", tool, toolMeta(tool));
    if (entryCWEs) {
      for (const c of entryCWEs) {
        // Id only. Highlighting the catalog's alternate terms ("Use After Free",
        // "SQL Injection") in article prose is the same dictionary-word problem
        // the autolinker refuses for the same reason.
        entities.push({ id: c.id, type: "cwe", value: c.cwe_id, meta: cweMeta(c) });
      }
    }
    if (entryMitigations) {
      for (const m of entryMitigations) {
        const meta = mitigationMeta(m);
        if (m.name) entities.push({ id: m.id, type: "mitigation", value: m.name, meta });
        if (m.mitre_id) entities.push({ id: m.id, type: "mitigation", value: m.mitre_id, meta });
      }
    }
    // Confirmed observables only — candidates never highlight. The article
    // usually prints the defanged surface form, so match on that AND the
    // canonical value; both map to the same ledger row.
    // An ioc_list entry carries hundreds of sightings; a 10,000-branch
    // alternation regex freezes the tab. The panel still lists them all.
    const observableItems = (entryObservables?.items?.length ?? 0) <= 200 ? (entryObservables?.items ?? []) : [];
    for (const o of observableItems) {
      const meta = observableMeta(o);
      entities.push({ id: o.id, type: "observable", value: o.value, name: o.value, meta });
      if (o.surface_form && o.surface_form.toLowerCase() !== o.value.toLowerCase()) {
        entities.push({ id: o.id, type: "observable", value: o.surface_form, name: o.value, meta });
      }
    }
    return entities;
  }, [entryCVEs, entryTTPs, entryActors, entryMalware, entryCountries, entryVendors, entryProducts, entryTools, entryMitigations, entryCWEs, entryObservables]);

  const articleBodyStyle = useMemo<React.CSSProperties>(() => ({
    fontSize: `${readerFontSize}px`,
    lineHeight: readerLineHeight,
    maxWidth: readerMaxWidth === 0 ? "none" : `${readerMaxWidth}px`,
  }), [readerFontSize, readerLineHeight, readerMaxWidth]);

  const articlePaneStyle = useMemo<React.CSSProperties>(() => ({
    ["--reader-col-width" as string]: readerMaxWidth === 0 ? "none" : `${readerMaxWidth + 64}px`,
    ["--reader-col-inner" as string]: readerMaxWidth === 0 ? "none" : `${readerMaxWidth}px`,
  }), [readerMaxWidth]);

  const glossaryTermsForHighlight = useMemo(
    () =>
      glossaryMatches?.map((m) => ({
        id: m.term.id,
        name: m.term.name,
        category: m.term.category,
        search_terms: m.term.search_terms,
      })) ?? [],
    [glossaryMatches],
  );

  const handleGlossarySearch = useCallback(
    (term: { name: string; search_terms?: string[] }) => {
      const allNames = [term.name, ...(term.search_terms || [])];
      const query = allNames.map((n) => `"${n}"`).join(" OR ");
      openSavedSearch({
        id: "glossary-search",
        name: "glossary-search",
        display_name: null,
        query,
        filters: {},
        unread_count: 0,
        total_count: 0,
        created_at: new Date().toISOString(),
      });
    },
    [openSavedSearch],
  );

  const swipeRef = useSwipe<HTMLDivElement>({
    onSwipeRight: () => setSelectedEntry(null),
    edgeOnly: true,
    edgeWidth: 30,
    threshold: 60,
    enabled: isMobile,
  });

  const getArticleParagraphs = useCallback((): string[] => {
    return extractSpeechParagraphs(articleContentRef.current, entry?.title);
  }, [entry?.title]);

  const handleContentClick = useCallback((e: React.MouseEvent) => {
    if (!isSpeechForThisEntry) return;
    // Don't hijack link clicks
    if ((e.target as HTMLElement).closest("a")) return;

    const container = articleContentRef.current;
    if (!container) return;

    const blockSelector = "p, h1, h2, h3, h4, h5, h6, li, blockquote, td, pre";
    const clickedBlock = (e.target as HTMLElement).closest(blockSelector);
    if (!clickedBlock || !container.contains(clickedBlock)) return;

    const blocks = container.querySelectorAll(blockSelector);
    let nonEmptyIndex = 0;
    for (let i = 0; i < blocks.length; i++) {
      const text = (blocks[i].textContent || "").trim();
      if (!text) continue;
      if (blocks[i] === clickedBlock || clickedBlock.contains(blocks[i]) || blocks[i].contains(clickedBlock)) {
        // +1 offset if title is paragraph 0
        const paragraphIndex = entry?.title ? nonEmptyIndex + 1 : nonEmptyIndex;
        requestSpeechSkip(paragraphIndex);
        return;
      }
      nonEmptyIndex++;
    }
  }, [isSpeechForThisEntry, entry?.title, requestSpeechSkip]);

  if (isLoading) {
    return <AsyncStateLoading label="Loading article…" />;
  }

  if (!entry) {
    const rateLimited = (entryError as { response?: { status?: number } } | null)?.response?.status === 429;
    return (
      <div className={styles.loading}>
        {rateLimited ? "Too many articles opened in a short time. Wait a minute and try again." : "Entry not found"}
      </div>
    );
  }

  const readTime = entry.word_count ? Math.ceil(entry.word_count / 200) : null;
  const isYouTube = entry.feed_type === "youtube";
  const isPodcast = entry.feed_type === "podcast";
  const videoId = (entry.metadata?.video_id as string | undefined)
    || (isYouTube && entry.url ? new URL(entry.url).searchParams.get("v") ?? undefined : undefined);
  const audioMedia = entry.media?.find((m) => m.media_type === "audio");

  const handlePlayEpisode = () => {
    if (!audioMedia) return;
    playTrack({
      mediaId: audioMedia.id,
      entryId: entry.id,
      title: entry.title,
      feedTitle: entry.feed_title || "",
      audioUrl: audioMedia.url,
      thumbnailUrl: audioMedia.thumbnail_url,
      durationSeconds: audioMedia.duration_seconds,
    });
  };

  const isCurrentlyPlaying = currentTrack?.mediaId === audioMedia?.id;

  const togglePanel = (panel: "intel" | "ai" | "notes" | "tag") => {
    setActiveReaderPanel(activeReaderPanel === panel ? null : panel);
  };

  return (
    <div className={styles.readerContainer} ref={swipeRef}>
      <article className={styles.articlePane} style={articlePaneStyle}>
        <div className={styles.topBar}>
          <button
            className={styles.closeBtn}
            onClick={() => {
              // The reader also lives docked in the workbench, where Close must
              // clear that dock's entry rather than the main list selection.
              setSelectedEntry(null);
              useIntelStore.getState().closeWorkbenchReader();
            }}
          >
            {isMobile ? (
              <>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="15 18 9 12 15 6" />
                </svg>
                Back
              </>
            ) : (
              "Close"
            )}
          </button>
          <div className={styles.entryNav}>
            <button
              className={styles.navBtn}
              onClick={() => navigateEntry("prev")}
              disabled={!hasPrev}
              title="Previous entry (k)"
              aria-label="Previous entry"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="15 18 9 12 15 6" />
              </svg>
            </button>
            <span className={styles.navPosition}>{currentNavIndex >= 0 ? currentNavIndex + 1 : "–"}/{navIds.length}</span>
            <button
              className={styles.navBtn}
              onClick={() => navigateEntry("next")}
              disabled={!hasNext}
              title="Next entry (j)"
              aria-label="Next entry"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="9 18 15 12 9 6" />
              </svg>
            </button>
          </div>
          <div className={styles.topBarActions}>
            {!isVisitor && (<>
            <button
              className={`${styles.labelBtn} ${entry.is_starred ? styles.labelBtnActive : ""}`}
              onClick={() => toggleStar.mutate(entryId)}
              title={`${entry.is_starred ? "Unstar" : "Star"} this article (s)`}
            >
              {entry.is_starred ? "Unstar" : "Star"}
            </button>
            <button
              className={styles.labelBtn}
              onClick={() => entry.is_read ? markUnread.mutate(entryId) : markRead.mutate(entryId)}
              title={`Mark ${entry.is_read ? "unread" : "read"} (m)`}
            >
              {entry.is_read ? "Unread" : "Read"}
            </button>
            <button
              className={`${styles.labelBtn} ${entry.is_bookmarked ? styles.labelBtnActive : ""}`}
              onClick={() => toggleBookmark.mutate(entryId)}
              title={`${entry.is_bookmarked ? "Remove bookmark" : "Bookmark for later"} (b)`}
            >
              {entry.is_bookmarked ? "Unbookmark" : "Bookmark"}
            </button>
            <div className={styles.topBarDivider} />
            </>)}
            <Hint
              title="Extracted intel"
              body="Every entity, technique, CVE and indicator this article mentions. Click one to open its dossier."
              aside={<><kbd>w</kbd></>}
            >
              <button
                className={`${styles.labelBtn} ${activeReaderPanel === "intel" ? styles.labelBtnActive : ""}`}
                onClick={() => togglePanel("intel")}
              >
                Intel
              </button>
            </Hint>
            {!isVisitor && (<>
            <button
              className={`${styles.labelBtn} ${activeReaderPanel === "ai" ? styles.labelBtnActive : ""}`}
              onClick={() => togglePanel("ai")}
              title="AI summary and analysis of this article (a)"
            >
              AI
            </button>
            <button
              className={`${styles.labelBtn} ${activeReaderPanel === "notes" ? styles.labelBtnActive : ""}`}
              onClick={() => togglePanel("notes")}
              title="Your notes on this article (n)"
            >
              Notes
            </button>
            <button
              className={`${styles.labelBtn} ${activeReaderPanel === "tag" ? styles.labelBtnActive : ""}`}
              onClick={() => togglePanel("tag")}
              title="Tag this article (t)"
            >
              Tags
            </button>
            <button
              className={styles.labelBtn}
              title="Ask the copilot about this article"
              onClick={() =>
                openCopilotWith({
                  // Context-only seed: pin the article and let the analyst ask
                  // their own question — no auto-submitted canned prompt.
                  context: { entry_id: entryId, label: entry?.title },
                  lockContext: true,
                })
              }
            >
              Ask Copilot
            </button>
            </>)}
            <div className={styles.topBarDivider} />
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
              {!isVisitor && (<>
              <DropdownItem
                icon={
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="7 10 12 15 17 10" />
                    <line x1="12" y1="15" x2="12" y2="3" />
                  </svg>
                }
                label="Export"
                onClick={() => exportEntry(entryId)}
              />
              <DropdownItem
                icon={
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8" />
                    <polyline points="16 6 12 2 8 6" />
                    <line x1="12" y1="2" x2="12" y2="15" />
                  </svg>
                }
                label="Share"
                onClick={handleShare}
              />
              </>)}
              <DropdownItem
                icon={
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="11" cy="11" r="8" />
                    <line x1="21" y1="21" x2="16.65" y2="16.65" />
                  </svg>
                }
                label="Find in article"
                shortcut="⌘F"
                active={showFind}
                onClick={() => setShowFind((v) => !v)}
              />
              {(isVisitor
                ? existingAudio.data?.status === "ready"
                : readAloudEngine === "piper" || "speechSynthesis" in window) && (
                <DropdownItem
                  icon={
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" />
                      <path d="M19.07 4.93a10 10 0 0 1 0 14.14" />
                      <path d="M15.54 8.46a5 5 0 0 1 0 7.07" />
                    </svg>
                  }
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
                    if (readAloudEngine === "piper" || isVisitor) {
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
                      if (ok || isVisitor) return;
                      // Piper unavailable/failed — fall back to the browser voice.
                      if ("speechSynthesis" in window) speakViaBrowser();
                      else toast.error("Read-aloud audio is unavailable right now.");
                      return;
                    }
                    speakViaBrowser();
                  }}
                />
              )}
              {!isVisitor && (
              <DropdownItem
                icon={
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M5 8l6 6" />
                    <path d="M4 14l6-6 2-3" />
                    <path d="M2 5h12" />
                    <path d="M7 2h1" />
                    <path d="M22 22l-5-10-5 10" />
                    <path d="M14 18h6" />
                  </svg>
                }
                label={
                  translateEntry.isPending
                    ? "Translating…"
                    : entry.translated_html
                      ? showTranslated
                        ? "Show original"
                        : "Show translation"
                      : "Translate to English"
                }
                active={showTranslated}
                onClick={handleTranslate}
              />
              )}
              {entry.url && (
                <DropdownItem
                  icon={
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                      <polyline points="15 3 21 3 21 9" />
                      <line x1="10" y1="14" x2="21" y2="3" />
                    </svg>
                  }
                  label="Open original"
                  href={entry.url}
                  newTab={openLinksNewTab}
                />
              )}
              <UploadDownloadItem metadata={entry.metadata} />
            </ToolbarDropdown>
          </div>
        </div>

        {showFind && (
          <FindInArticle
            containerRef={articleContentRef}
            onClose={() => setShowFind(false)}
          />
        )}


        <header className={styles.header} ref={articleHeaderRef}>
          <div className={styles.meta}>
            <FeedNameMenuButton feedId={entry.feed_id} className={styles.feedNameBtn}>
              {(() => {
                const sub = feedsData?.items.find((s) => s.id === entry.feed_id);
                if (!sub) return null;
                return (
                  <IntelLevelBadge
                    mode={sub.intel_extraction_mode || "selective"}
                    aiAnalysis={sub.ai_analysis_enabled ?? true}
                    autoExtract={sub.auto_extract_on_ingest ?? false}
                    size="md"
                  />
                );
              })()}
              {entry.feed_title}
            </FeedNameMenuButton>
            {/* The feed's reliability letter lives in the grade (B2), so the
                feed name carries no separate badge. */}
            <InfoGradeChip
              entryId={entry.id}
              reliability={feedsData?.items.find((s) => s.id === entry.feed_id)?.reliability_rating}
              rating={entry.info_rating}
              ratingBy={entry.info_rating_by}
              aiRating={entry.info_rating_ai}
              access={entry.info_rating_access}
              note={entry.info_rating_note}
              readOnly={isVisitor}
            />
            {/* The timestamp doubles as the way into the pipeline status popover
                (signed-in only: a visitor gets the date). */}
            {isVisitor ? (
              entry.published_at && <span className={styles.date}>{formatDateTime(entry.published_at)}</span>
            ) : (
              <EntryPipelineStatus entryId={entry.id} className={styles.date}>
                {entry.published_at ? formatDateTime(entry.published_at) : "Pipeline"}
              </EntryPipelineStatus>
            )}
            {entry.priority_score != null && (
              <SignalChip score={entry.priority_score} signals={entry.top_signals ?? []} />
            )}
          </div>
          <h1 className={styles.title}>
            {showTranslated && entry.translated_title ? entry.translated_title : entry.title}
          </h1>
          <div className={styles.byline}>
            {entry.author && <span>By {entry.author}</span>}
            {readTime && !isYouTube && !isPodcast && <span>{readTime} min read</span>}
            <UploadByline metadata={entry.metadata} feedId={entry.feed_id} />
            {isYouTube && !!entry.metadata?.view_count && (
              <span>{formatViewCount(Number(entry.metadata.view_count))}</span>
            )}
            {isPodcast && audioMedia?.duration_seconds && (
              <span>{formatDuration(audioMedia.duration_seconds)}</span>
            )}
            {(intelBadges?.[entryId] || entry.is_echo || entry.tags?.some((t) => t.display_as_chip)) && (
              <EntryIntelBadges counts={intelBadges?.[entryId]} echo={entry.is_echo} tags={entry.tags} entryId={entryId} />
            )}
          </div>
          {entry.echo_of && (
            <button
              className={styles.echoOf}
              onClick={() => entry.echo_of && openEntry(entry.echo_of.entry_id)}
              title="Open the earlier article this one echoes"
            >
              <span className={styles.echoOfIcon} aria-hidden="true">↩</span>
              <span className={styles.echoOfText}>
                Echoes earlier coverage: <strong>{entry.echo_of.title}</strong>
                {entry.echo_of.feed_title ? ` · ${entry.echo_of.feed_title}` : ""}
                {entry.echo_of.shared != null && entry.echo_of.total != null && (
                  <span className={styles.echoOfMeta}>
                    {" "}({entry.echo_of.shared}/{entry.echo_of.total} shared entities)
                  </span>
                )}
              </span>
              <span className={styles.echoOfArrow} aria-hidden="true">→</span>
            </button>
          )}
          <ArticleSummaryCard entryId={entryId} />
          {((entry.priority_score != null && (entry.priority_signals?.length ?? 0) > 0) ||
            entry.exposure) && (
            <WhyRankedCard
              // Remount per entry so the card returns to its collapsed summary
              // when the reader moves on.
              key={entryId}
              score={entry.priority_score ?? 0}
              raw={entry.priority_raw}
              signals={entry.priority_signals ?? []}
              exposure={entry.exposure}
              personal={entry.personal}
              // Without it the card has no votes: a visitor's ranking is the
              // system score alone.
              entryId={isVisitor ? undefined : entryId}
            />
          )}
        </header>

        {isYouTube && videoId && <YouTubePlayer videoId={videoId} title={entry.title} />}

        {audioMedia && (
          <div className={styles.podcastControls}>
            <button
              className={`${styles.playEpisodeBtn} ${isCurrentlyPlaying ? styles.playing : ""}`}
              onClick={handlePlayEpisode}
            >
              {isCurrentlyPlaying ? "Now Playing" : isPodcast ? "Play Episode" : "Play Audio"}
            </button>
            {audioMedia.duration_seconds && (
              <span className={styles.episodeDuration}>
                {formatDuration(audioMedia.duration_seconds)}
              </span>
            )}
          </div>
        )}

        {(() => {
          const visualMedia = entry.media?.filter((m) => {
            if (m.media_type === "photo" || m.media_type === "image") return true;
            // A "video" record pointing at a watch/embed page (e.g. a YouTube
            // watch URL) can't be played by a <video> tag — it renders a "No
            // video with supported format and MIME type found" error. These
            // already play via the iframe above, so drop them from the gallery.
            if (m.media_type === "video") return !/(?:youtube\.com|youtu\.be)/i.test(m.url);
            return false;
          })
            // Telegram media is login-only: a visitor gets the post text, not a broken image.
            .filter((m) => !isVisitor || !m.url.startsWith("/api/telegram-media/")) ?? [];
          if (visualMedia.length === 0) return null;
          // /api/telegram-media is auth-gated; img/video tags can't pass the bearer
          // header, so encode the access token in the query string for media URLs.
          const accessToken = useAuthStore.getState().accessToken;
          const sign = (u: string): string => {
            if (!accessToken || !u.startsWith("/api/telegram-media/")) return u;
            return u.includes("?") ? `${u}&token=${encodeURIComponent(accessToken)}` : `${u}?token=${encodeURIComponent(accessToken)}`;
          };
          return (
            <div className={styles.mediaGallery}>
              {visualMedia.map((m) => {
                const src = sign(m.url);
                const poster = m.thumbnail_url ? sign(m.thumbnail_url) : undefined;
                if (m.media_type === "video") {
                  return (
                    <video
                      key={m.id}
                      src={src}
                      poster={poster}
                      controls
                      preload="metadata"
                    />
                  );
                }
                return (
                  <a key={m.id} href={src} target="_blank" rel="noopener noreferrer">
                    <img src={src} alt="" loading="lazy" />
                  </a>
                );
              })}
            </div>
          );
        })()}

        {entry.duplicates && entry.duplicates.length > 0 && (
          <div className={styles.duplicates}>
            Also reported by:{" "}
            {entry.duplicates.map((d, i) => (
              <span key={d.entry_id}>
                {i > 0 && ", "}
                <button
                  className={styles.dupLink}
                  onClick={() => openEntry(d.entry_id)}
                >
                  {d.feed_title}
                </button>
              </span>
            ))}
          </div>
        )}

        {entry.metadata?.source === "github_repo" && (
          <div className={styles.ruleCardWrap}>
            <RuleEntryCard metadata={entry.metadata} />
          </div>
        )}

        {showTranslated && entry.translated_html && (
          <div className={styles.translationBanner}>
            <span>
              Translated
              {entry.translation_source_language && entry.translation_source_language !== "auto"
                ? ` from ${entry.translation_source_language.toUpperCase()}`
                : ""}
              {entry.translation_target_language
                ? ` to ${entry.translation_target_language.toUpperCase()}`
                : ""}
            </span>
            <button
              className={styles.translationToggle}
              onClick={() => setShowTranslated(false)}
            >
              Show original
            </button>
          </div>
        )}
        <div className={`${styles.content} ${isSpeechForThisEntry ? styles.speechActive : ""}`} ref={articleContentRef} onClick={handleContentClick}>
          <ReaderTOC containerRef={articleContentRef} contentLength={(entry.content_text || entry.content_html || "").length} />
          {(() => {
            const displayHtml =
              showTranslated && entry.translated_html
                ? entry.translated_html
                : entry.content_html;
            if (displayHtml) {
              return (
                <SafeHTML
                  html={isYouTube ? formatYouTubeDescription(displayHtml) : displayHtml}
                  className={styles.articleBody}
                  style={articleBodyStyle}
                  glossaryTerms={glossaryTermsForHighlight}
                />
              );
            }
            if (entry.summary) {
              return (
                <SafeHTML
                  html={isYouTube ? formatYouTubeDescription(`<p>${entry.summary}</p>`) : `<p>${entry.summary}</p>`}
                  className={styles.articleBody}
                  style={articleBodyStyle}
                  glossaryTerms={glossaryTermsForHighlight}
                />
              );
            }
            return (
              <p className={styles.noContent}>
                No content available.{" "}
                <a href={entry.url || "#"} target={openLinksNewTab ? "_blank" : undefined} rel="noopener noreferrer">
                  Open original article
                </a>
              </p>
            );
          })()}
          {glossaryMatches && glossaryMatches.length > 0 && (
            <GlossaryTooltip
              containerRef={articleContentRef}
              matches={glossaryMatches}
              onOpenPanel={() => {
                setActiveReaderPanel("intel");
                setGlossaryExpandSignal((s) => s + 1);
              }}
              onSearchArticles={isVisitor ? undefined : handleGlossarySearch}
            />
          )}
          <InlineEntityHighlighter
            containerRef={articleContentRef}
            entities={highlightEntities}
            enabled={readerHighlightEntities}
            entryId={entryId}
          />
          <SpeechHighlighter
            entryId={entryId}
            hasTitle={!!entry.title}
            headerRef={articleHeaderRef}
            contentRef={articleContentRef}
          />
          {!isVisitor && <SelectionContextMenu
            containerRef={[articleContentRef, articleHeaderRef]}
            entryId={entryId}
            onCreateEntity={(text) => {
              setEntityInitialText(text);
              setEntityKey((k) => k + 1);
              setActiveReaderPanel("create_entity");
            }}
            onCreateNote={(text) => {
              setNoteInitialContent(`<blockquote><p>${text}</p></blockquote><p></p>`);
              setNoteKey((k) => k + 1);
              setActiveReaderPanel("notes");
            }}
            onAddAlias={(text) => {
              setAliasText(text);
              setAliasKey((k) => k + 1);
              setActiveReaderPanel("add_alias");
            }}
            onLinkEntity={(text) => {
              setLinkEntitySearch(text);
              setLinkEntityKey((k) => k + 1);
              setActiveReaderPanel("link_entity");
            }}
          />}
        </div>

        <div className={styles.similarSection}>
          {!showSimilar ? (
            <button
              className={styles.similarToggle}
              onClick={() => setShowSimilar(true)}
            >
              More like this
            </button>
          ) : similarLoading ? (
            <div className={styles.similarLoading}>Finding similar entries...</div>
          ) : similarData && similarData.items.length > 0 ? (
            <>
              <h3 className={styles.similarTitle}>More like this</h3>
              <div className={styles.similarList}>
                {similarData.items.map((item) => (
                  <div key={item.id} className={styles.similarRow}>
                    <button className={styles.similarItem} onClick={() => openEntry(item.id)}>
                      <span className={styles.similarItemTitle}>{item.title || "Untitled"}</span>
                      <span className={styles.similarItemMeta}>
                        {item.similarity != null && (
                          <span className={styles.similarMatch}>{Math.round(item.similarity * 100)}%</span>
                        )}
                        {item.feed_title}
                        {item.published_at ? ` · ${formatDateTime(new Date(item.published_at * 1000))}` : ""}
                      </span>
                    </button>
                    {/* A neighbour that already belongs to a story is a way into
                        that story, not just a label. Its own element because a
                        button cannot be nested inside one. */}
                    {item.thread_slug && (
                      <button
                        className={styles.similarThread}
                        onClick={() => openThread(item.thread_slug!)}
                        title="Open this story thread"
                      >
                        ⟲ {item.thread_title}
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </>
          ) : similarData ? (
            <div className={styles.similarEmpty}>No similar entries found</div>
          ) : null}
        </div>
      </article>

      {activeReaderPanel && (() => {
        /* Rail on the panel’s left edge, same shared control the sidebar and
           copilot rails use — here it swings the panel between full width and
           its resizable half. Maximized, the panel covers the reader, so the
           rail rides along inside it. The × in the header still closes. */
        const rail = !isMobile && (
          <RailToggle
            side="right"
            collapsed={!sidePanelMaximized}
            onToggle={() => setSidePanelMaximized(!sidePanelMaximized)}
            label="panel"
            verbs={["Expand", "Restore"]}
            className={sidePanelMaximized ? styles.sidePanelRailMaximized : undefined}
          />
        );
        return (
        <>
          {!sidePanelMaximized && rail}
          {!isMobile && !sidePanelMaximized && (
            <ResizeHandle
              onResize={(delta) => {
                const container = swipeRef.current;
                const maxWidth = container ? container.clientWidth - 100 : 2400;
                setSidePanelWidth(Math.min(sidePanelWidth - delta, maxWidth));
              }}
            />
          )}
          <div className={`${styles.sidePanel} ${sidePanelMaximized ? styles.sidePanelMaximized : ""}`} style={!isMobile && !sidePanelMaximized ? { width: sidePanelWidth } : undefined}>
            {sidePanelMaximized && rail}
            <div className={styles.sidePanelHeader}>
              {activeReaderPanel === "intel" || activeReaderPanel === "ai" || activeReaderPanel === "notes" ? (
                <div className={styles.sidePanelTabs} role="tablist">
                  {(isVisitor ? (["intel"] as const) : (["intel", "ai", "notes"] as const)).map((tab) => (
                    <button
                      key={tab}
                      role="tab"
                      aria-selected={activeReaderPanel === tab}
                      className={`${styles.sidePanelTab} ${activeReaderPanel === tab ? styles.sidePanelTabActive : ""} ${activeReaderPanel === tab ? styles[`sidePanelTab_${tab}`] : ""}`}
                      onClick={() => setActiveReaderPanel(tab)}
                    >
                      {tab === "intel" ? "Intel" : tab === "ai" ? "AI" : "Notes"}
                    </button>
                  ))}
                </div>
              ) : (
                <span className={styles.sidePanelTitle}>
                  {activeReaderPanel === "tag" && "Tags"}
                  {activeReaderPanel === "create_entity" && "Create Entity"}
                  {activeReaderPanel === "add_alias" && "Add Alias"}
                  {activeReaderPanel === "link_entity" && "Link Entity"}
                </span>
              )}
              <div className={styles.sidePanelHeaderActions}>
                <button
                  className={styles.sidePanelClose}
                  onClick={() => { setSidePanelMaximized(false); setActiveReaderPanel(null); }}
                  title="Close panel"
                  aria-label="Close panel"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <line x1="18" y1="6" x2="6" y2="18" />
                    <line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                </button>
              </div>
            </div>
            <div className={styles.sidePanelContent}>
              {activeReaderPanel === "notes" && (
                <EntryNotePanel
                  key={noteKey}
                  entryId={entryId}
                  initialContent={noteInitialContent}
                  onClose={() => setNoteInitialContent(undefined)}
                />
              )}
              {activeReaderPanel === "tag" && (
                <TagInput
                  entryId={entryId}
                  onClose={() => setActiveReaderPanel(null)}
                />
              )}
              {activeReaderPanel === "intel" && (
                <WorkbenchPanel
                  entryId={entryId}
                  entryTitle={entry.title}
                  onGlossarySearch={isVisitor ? undefined : handleGlossarySearch}
                  expandGlossarySignal={glossaryExpandSignal}
                />
              )}
              {activeReaderPanel === "ai" && (
                <EntryAIPanel entryId={entryId} entryTitle={entry.title} />
              )}
              {activeReaderPanel === "create_entity" && (
                <CreateEntityPanel
                  key={entityKey}
                  entryId={entryId}
                  initialText={entityInitialText}
                  onClose={() => { setActiveReaderPanel(null); setEntityInitialText(undefined); }}
                />
              )}
              {activeReaderPanel === "add_alias" && aliasText && (
                <AddAliasPanel
                  key={aliasKey}
                  aliasText={aliasText}
                  onClose={() => { setActiveReaderPanel(null); setAliasText(undefined); }}
                />
              )}
              {activeReaderPanel === "link_entity" && (
                <LinkEntityPanel
                  key={linkEntityKey}
                  entryId={entryId}
                  initialSearch={linkEntitySearch}
                  onClose={() => { setActiveReaderPanel(null); setLinkEntitySearch(undefined); }}
                />
              )}
            </div>
          </div>
        </>
        );
      })()}

    </div>
  );
}
