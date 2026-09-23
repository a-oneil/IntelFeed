import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  useIntelReport,
  useCreateIntelReport,
  useUpdateIntelReport,
  useDeleteIntelReport,
  useIntelReportVersions,
  useExportIntelReport,
  useReportTemplates,
  useGenerateReportSection,
  useRegenerateAllSections,
  useCloneReportAsType,
} from "@/hooks/useIntelReports";
import { useEntryNames } from "@/hooks/useEntries";
import { useEntityNames } from "@/hooks/useIntelligence";
import { useSearch } from "@/hooks/useSearch";
import type { ReportTemplateSection } from "@/api/types";
import { EntityLinkedMarkdown } from "@/components/EntityLinkedMarkdown";
import CodeMirrorEditor from "@/components/CodeMirrorEditor";
import SimpleTagEditor from "@/components/SimpleTagEditor";
import { formatDateTime as formatDate } from "@/utils/formatDate";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { Breadcrumb } from "@/components/Breadcrumb";
import { Chip } from "@/components/primitives";
import { TLP_COLORS } from "@/utils/colorSchemes";
import styles from "./ReportBuilderPage.module.css";

const TLP_OPTIONS = [
  "TLP:CLEAR",
  "TLP:GREEN",
  "TLP:AMBER",
  "TLP:AMBER+STRICT",
  "TLP:RED",
] as const;

const EXPORT_FORMATS = [
  { value: "markdown", label: "Markdown" },
  { value: "html", label: "HTML" },
  { value: "pdf", label: "PDF" },
];


type SectionData = { title?: string; body?: string; items?: Record<string, unknown>[] };

/** Data-section rows rendered as a real table, shape-detected the same way
 *  the markdown exporter does (observables, threat surface, TTPs, refs...). */
function SectionItemsTable({ items }: { items: Record<string, unknown>[] }) {
  const first = items[0] || {};
  const cell = (v: unknown) => (Array.isArray(v) ? v.join(", ") : v == null ? "" : String(v));

  if ("kind" in first && "value" in first) {
    return (
      <div className={styles.docTableWrap}>
        <table className={styles.docTable}>
          <thead><tr><th>Kind</th><th>Value</th><th>Confidence</th><th>Attribution</th><th>Last seen</th></tr></thead>
          <tbody>
            {items.map((it, i) => (
              <tr key={i}>
                <td>{cell(it.kind)}</td>
                <td className={styles.docMono}>{cell(it.value)}</td>
                <td>{typeof it.confidence === "number" ? `${Math.round((it.confidence as number) * 100)}%` : ""}</td>
                <td>{cell(it.claimed_by)}</td>
                <td>{cell(it.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  if ("matched_regions" in first) {
    return (
      <div className={styles.docTableWrap}>
        <table className={styles.docTable}>
          <thead><tr><th>Entity</th><th>Type</th><th>Regions</th><th>Verticals</th><th>Entries</th><th>Victims</th></tr></thead>
          <tbody>
            {items.map((it, i) => (
              <tr key={i}>
                <td><b>{cell(it.name)}</b></td>
                <td>{cell(it.subtype || (it.entity_type === "threat_actor" ? "actor" : it.entity_type))}</td>
                <td>{cell(it.matched_regions) || "—"}</td>
                <td>{cell(it.matched_sectors) || "—"}</td>
                <td>{cell(it.entry_count)}</td>
                <td>{cell(it.victim_count) || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  if ("technique_id" in first) {
    return (
      <div className={styles.docTableWrap}>
        <table className={styles.docTable}>
          <thead><tr><th>Technique</th><th>Name</th><th>Tactic</th></tr></thead>
          <tbody>
            {items.map((it, i) => (
              <tr key={i}>
                <td className={styles.docMono}>{cell(it.technique_id)}</td>
                <td>{cell(it.name)}</td>
                <td>{cell(it.tactic)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  if ("url" in first && "title" in first) {
    return (
      <ul className={styles.docList}>
        {items.map((it, i) => (
          <li key={i}>
            <a href={String(it.url || "")} target="_blank" rel="noreferrer">{cell(it.title) || cell(it.url)}</a>
          </li>
        ))}
      </ul>
    );
  }
  if ("date" in first && "title" in first) {
    return (
      <ul className={styles.docList}>
        {items.map((it, i) => (
          <li key={i}>
            <span className={styles.docMono}>{cell(it.date)?.slice(0, 10) || "?"}</span> — {cell(it.title)}
          </li>
        ))}
      </ul>
    );
  }
  if ("cve_id" in first) {
    return (
      <div className={styles.docTableWrap}>
        <table className={styles.docTable}>
          <thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr></thead>
          <tbody>
            {items.map((it, i) => (
              <tr key={i}>
                <td className={styles.docMono}>{cell(it.cve_id)}</td>
                <td>{cell(it.severity)}</td>
                <td>{cell(it.cvss_score)}</td>
                <td>{String(it.description || "").slice(0, 160)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  return (
    <ul className={styles.docList}>
      {items.map((it, i) => (
        <li key={i}>
          <b>{cell(it.name)}</b>
          {it.aliases ? ` (${cell(it.aliases)})` : ""}
          {it.malware_type ? ` — ${cell(it.malware_type)}` : ""}
        </li>
      ))}
    </ul>
  );
}

/** Placeholder line the skeleton puts under each heading; stripped back out
 *  when the body is parsed into sections on create. */
function sectionPlaceholder(sec: ReportTemplateSection): string {
  if (sec.type === "data") {
    return "_(data section — fills automatically from linked articles and entities)_";
  }
  return sec.description ? `_${sec.description}_` : "_Write this section..._";
}

/** Markdown scaffold for a template: one ## heading per section. Selecting a
 *  template in create mode fills the editor with this. */
function buildTemplateSkeleton(secs: ReportTemplateSection[]): string {
  return secs.map((sec) => `## ${sec.title}\n\n${sectionPlaceholder(sec)}\n`).join("\n");
}

/** Split an edited skeleton back into per-section bodies by matching the
 *  template's ## headings, so text typed in create mode lands in the right
 *  section tabs after the report exists. Returns null for freeform bodies
 *  that don't use the template's headings. */
function parseBodyIntoSections(
  body: string,
  secs: ReportTemplateSection[]
): { preamble: string; sections: Record<string, { title: string; body: string }> } | null {
  if (secs.length === 0) return null;
  const titleToSec = new Map(secs.map((sec) => [sec.title.toLowerCase(), sec]));
  const sections: Record<string, { title: string; body: string }> = {};
  const preamble: string[] = [];
  let current: ReportTemplateSection | null = null;
  let buf: string[] = [];
  let matchedAny = false;

  const flush = () => {
    if (!current) {
      preamble.push(...buf);
      buf = [];
      return;
    }
    let text = buf.join("\n").trim();
    if (text === sectionPlaceholder(current)) text = "";
    if (text) sections[current.name] = { title: current.title, body: text };
    buf = [];
  };

  for (const line of body.split("\n")) {
    const heading = line.match(/^##\s+(.+?)\s*$/);
    const sec = heading ? titleToSec.get(heading[1].toLowerCase()) : undefined;
    if (sec) {
      flush();
      current = sec;
      matchedAny = true;
    } else {
      buf.push(line);
    }
  }
  flush();

  if (!matchedAny) return null;
  return { preamble: preamble.join("\n").trim(), sections };
}

const SNIPPET_INSERTS: Array<{ label: string; snippet: string }> = [
  {
    label: "TTP Matrix",
    snippet: `\n## MITRE ATT&CK TTPs\n\n| Tactic | Technique | ID | Notes |\n|--------|-----------|----|-------|\n| | | | |\n`,
  },
  {
    label: "Timeline",
    snippet: `\n## Timeline\n\n| Date | Event | Source |\n|------|-------|--------|\n| | | |\n`,
  },
  {
    label: "Recommendations",
    snippet: `\n## Recommendations\n\n1. \n2. \n3. \n`,
  },
  {
    label: "Detection Guidance",
    snippet: `\n## Detection Guidance\n\n### Log Sources\n- \n\n### Detection Logic\n\`\`\`\n\n\`\`\`\n\n### Tuning Notes\n- \n`,
  },
];

export function ReportBuilderPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const isCreateMode = !id;

  // Track whether a generation is in-flight for polling
  const [isGenerating, setIsGenerating] = useState(false);

  // Data fetching
  const { data: report, isLoading, refetch } = useIntelReport(id);
  const { data: versions } = useIntelReportVersions(id);
  const { data: templates } = useReportTemplates();
  const createReport = useCreateIntelReport();
  const updateReport = useUpdateIntelReport();
  const deleteReport = useDeleteIntelReport();
  const undoableDelete = useUndoableDelete();
  const exportReport = useExportIntelReport();
  const generateSection = useGenerateReportSection();
  const regenerateAll = useRegenerateAllSections();
  const cloneAsType = useCloneReportAsType();

  // Local editing state
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [sections, setSections] = useState<Record<string, string>>({});
  const [summary, setSummary] = useState("");
  const [tlpMarking, setTlpMarking] = useState("TLP:GREEN");
  const [tags, setTags] = useState<string[]>([]);
  const [templateType, setTemplateType] = useState("");
  const [entryIds, setEntryIds] = useState<string[]>([]);
  const [entityIds, setEntityIds] = useState<Record<string, string[]>>({});
  const [changeDescription, setChangeDescription] = useState("");
  const [hasChanges, setHasChanges] = useState(false);
  const [showVersions, setShowVersions] = useState(false);
  const [viewingVersionId, setViewingVersionId] = useState<string | null>(null);
  const [generatingSection, setGeneratingSection] = useState<string | null>(null);
  const [activeSectionTab, setActiveSectionTab] = useState<string | null>(null);
  const [docView, setDocView] = useState<"rendered" | "markdown">("rendered");
  // Create mode: template grid collapses once a template is picked, so the
  // editor gets the room. Reopens from the header row.
  const [templatePickerOpen, setTemplatePickerOpen] = useState(true);
  const [addEntrySearch, setAddEntrySearch] = useState("");
  const [showAddEntry, setShowAddEntry] = useState(false);
  const [showCloneAsType, setShowCloneAsType] = useState(false);
  const addEntryRef = useRef<HTMLDivElement>(null);

  // Resolve entry/entity names for display
  const { data: entryNamesData } = useEntryNames(entryIds);
  const { data: entityNamesData } = useEntityNames(entityIds);
  const entryNameMap = useMemo(() => {
    const map: Record<string, { title: string; feed_title: string }> = {};
    entryNamesData?.forEach((e) => { map[e.id] = { title: e.title, feed_title: e.feed_title }; });
    return map;
  }, [entryNamesData]);
  const entityNameMap = useMemo(() => {
    const map: Record<string, string> = {};
    if (entityNamesData) {
      Object.values(entityNamesData).forEach((items) => {
        items.forEach((e) => { map[e.id] = e.name; });
      });
    }
    return map;
  }, [entityNamesData]);

  // Search for adding entries
  const { data: addEntryResults } = useSearch(
    { q: addEntrySearch, limit: 10 },
    showAddEntry && addEntrySearch.length >= 2
  );

  // Sync from server data when editing
  useEffect(() => {
    if (report) {
      setTitle(report.title);
      const content = report.content as Record<string, unknown>;
      setBody(typeof content?.body === "string" ? content.body : "");
      const rawSections = (content?.sections || {}) as Record<string, unknown>;
      const sectionData: Record<string, string> = {};
      for (const [key, val] of Object.entries(rawSections)) {
        if (typeof val === "string") {
          sectionData[key] = val;
        } else if (val && typeof val === "object") {
          sectionData[key] = (val as Record<string, unknown>).body as string || "";
        }
      }
      setSections(sectionData);
      setSummary(report.summary || "");
      setTlpMarking(report.tlp_marking);
      setTags(report.tags || []);
      setTemplateType(report.template_type);
      setEntryIds(report.entry_ids || []);
      setEntityIds((report.entity_ids as Record<string, string[]>) || {});
      setHasChanges(false);
    }
  }, [report]);

  // Set default template on create
  useEffect(() => {
    if (isCreateMode && templates && templates.length > 0 && !templateType) {
      setTemplateType(templates[0].type);
    }
  }, [isCreateMode, templates, templateType]);

  // Selecting a template fills the editor below with its section skeleton.
  // Never clobbers typed content: only an empty editor or a previous
  // untouched skeleton gets replaced.
  const lastSkeletonRef = useRef<string>("");
  useEffect(() => {
    if (!isCreateMode || !templateType) return;
    const secs = (templates?.find((t) => t.type === templateType)?.sections || []).filter(
      (sec): sec is ReportTemplateSection => typeof sec === "object" && sec !== null
    );
    if (secs.length === 0) return;
    const skeleton = buildTemplateSkeleton(secs);
    if ((body.trim() === "" || body === lastSkeletonRef.current) && body !== skeleton) {
      setBody(skeleton);
    }
    lastSkeletonRef.current = skeleton;
  }, [isCreateMode, templateType, templates, body]);

  const handleBodyChange = useCallback((value: string) => {
    setBody(value);
    setHasChanges(true);
  }, []);

  const handleSaveDraft = () => {
    if (isCreateMode) return;
    if (!id) return;

    const existingContent = (report?.content || {}) as Record<string, unknown>;
    const existingSections = (existingContent.sections || {}) as Record<string, Record<string, unknown>>;
    const mergedSections: Record<string, unknown> = { ...existingSections };
    for (const [key, val] of Object.entries(sections)) {
      mergedSections[key] = { ...(existingSections[key] || {}), body: val };
    }
    const content: Record<string, unknown> = {
      ...existingContent,
      body,
      sections: mergedSections,
    };

    updateReport.mutate(
      {
        id,
        title,
        content,
        summary,
        tlp_marking: tlpMarking,
        tags,
        entry_ids: entryIds,
        entity_ids: entityIds,
        status: "draft",
        change_description: changeDescription || undefined,
      },
      {
        onSuccess: () => {
          setHasChanges(false);
          setChangeDescription("");
        },
      }
    );
  };

  const handlePublish = () => {
    if (isCreateMode) return;
    if (!id) return;

    const existingContent2 = (report?.content || {}) as Record<string, unknown>;
    const existingSections2 = (existingContent2.sections || {}) as Record<string, Record<string, unknown>>;
    const mergedSections2: Record<string, unknown> = { ...existingSections2 };
    for (const [key, val] of Object.entries(sections)) {
      mergedSections2[key] = { ...(existingSections2[key] || {}), body: val };
    }
    const content: Record<string, unknown> = {
      ...existingContent2,
      body,
      sections: mergedSections2,
    };

    updateReport.mutate(
      {
        id,
        title,
        content,
        summary,
        tlp_marking: tlpMarking,
        tags,
        entry_ids: entryIds,
        entity_ids: entityIds,
        status: "published",
        change_description: changeDescription || "Published report",
      },
      {
        onSuccess: () => {
          setHasChanges(false);
          setChangeDescription("");
        },
      }
    );
  };

  const handleCreate = () => {
    if (!title.trim() || !templateType) return;

    // Untouched skeleton → empty content so the backend scaffolds sections;
    // an edited skeleton is parsed so each heading's text lands in its
    // section tab; freeform text stays in body.
    const parsed = body === lastSkeletonRef.current ? { preamble: "", sections: {} } : parseBodyIntoSections(body, currentTemplateSections);
    const createContent = parsed ? { body: parsed.preamble, sections: parsed.sections } : { body, sections: {} };

    createReport.mutate(
      {
        title: title.trim(),
        template_type: templateType,
        tlp_marking: tlpMarking,
        content: createContent,
        summary: summary || undefined,
        tags: tags.length > 0 ? tags : undefined,
      },
      {
        onSuccess: (newReport) => {
          navigate(`/workbench/report/${newReport.id}`, { replace: true });
        },
      }
    );
  };

  const handleDelete = () => {
    if (!id) return;
    undoableDelete({
      label: "Intel report",
      key: `report-${id}`,
      onDelete: () => deleteReport.mutate(id, {
        onSuccess: () => navigate("/workbench/explore"),
      }),
    });
  };

  const handleExport = (format: string) => {
    if (!id) return;
    exportReport.mutate({ id, format, title });
  };

  const handleInsertSnippet = (snippet: string) => {
    setBody((prev) => prev + snippet);
    setHasChanges(true);
  };

  const handleSectionChange = useCallback((sectionName: string, value: string) => {
    setSections((prev) => ({ ...prev, [sectionName]: value }));
    setHasChanges(true);
  }, []);

  const handleGenerateSection = useCallback(
    (sectionName: string) => {
      if (!id || generatingSection) return;
      setGeneratingSection(sectionName);
      generateSection.mutate(
        { reportId: id, sectionName },
        {
          onSuccess: (data) => {
            setSections((prev) => ({ ...prev, [sectionName]: data.content }));
            setHasChanges(true);
            setGeneratingSection(null);
          },
          onError: () => {
            setGeneratingSection(null);
          },
        }
      );
    },
    [id, generatingSection, generateSection]
  );

  // Stored section payloads (bodies + data items) from the saved report.
  const contentSections: Record<string, SectionData> = useMemo(() => {
    const c = report?.content as { sections?: Record<string, SectionData> } | undefined;
    return c?.sections || {};
  }, [report]);

  // Get template sections for the current report
  const currentTemplateSections: ReportTemplateSection[] =
    templates?.find((t) => t.type === templateType)?.sections?.filter(
      (s): s is ReportTemplateSection => typeof s === "object" && s !== null
    ) || [];

  const removeEntryId = (eid: string) => {
    setEntryIds((prev) => prev.filter((e) => e !== eid));
    setHasChanges(true);
  };

  const removeEntityId = (entityType: string, eid: string) => {
    setEntityIds((prev) => {
      const updated = { ...prev };
      if (updated[entityType]) {
        updated[entityType] = updated[entityType].filter((e) => e !== eid);
        if (updated[entityType].length === 0) {
          delete updated[entityType];
        }
      }
      return updated;
    });
    setHasChanges(true);
  };

  const addEntryId = (eid: string) => {
    if (!entryIds.includes(eid)) {
      setEntryIds((prev) => [...prev, eid]);
      setHasChanges(true);
    }
    setAddEntrySearch("");
    setShowAddEntry(false);
  };

  const doRegenerate = useCallback(() => {
    if (!id) return;
    setIsGenerating(true);
    regenerateAll.mutate(id);
  }, [id, regenerateAll]);

  const handleRegenerateAll = () => {
    if (!id || regenerateAll.isPending) return;
    if (hasChanges) {
      // Auto-save before regenerating so new entries/edits are included
      const existingContent = (report?.content || {}) as Record<string, unknown>;
      const existingSections = (existingContent.sections || {}) as Record<string, Record<string, unknown>>;
      const mergedSections: Record<string, unknown> = { ...existingSections };
      for (const [key, val] of Object.entries(sections)) {
        mergedSections[key] = { ...(existingSections[key] || {}), body: val };
      }
      const content: Record<string, unknown> = {
        ...existingContent,
        body,
        sections: mergedSections,
      };
      updateReport.mutate(
        {
          id,
          title,
          content,
          summary,
          tlp_marking: tlpMarking,
          tags,
          entry_ids: entryIds,
          entity_ids: entityIds,
          status: "draft",
        },
        {
          onSuccess: () => {
            setHasChanges(false);
            doRegenerate();
          },
        }
      );
    } else {
      doRegenerate();
    }
  };

  const handleCloneAsType = (newTemplateType: string) => {
    if (!id || cloneAsType.isPending) return;
    setShowCloneAsType(false);
    cloneAsType.mutate(
      { reportId: id, template_type: newTemplateType },
      {
        onSuccess: (data) => {
          navigate(`/workbench/report/${data.report.id}`, { replace: false });
        },
      }
    );
  };

  const viewingVersion = viewingVersionId
    ? versions?.find((v) => v.id === viewingVersionId)
    : null;

  const viewingBody =
    viewingVersion && typeof viewingVersion.content?.body === "string"
      ? viewingVersion.content.body
      : "";

  // Generation progress: count narrative sections with/without body
  const generationProgress = useMemo(() => {
    if (!report) return null;
    const content = report.content as Record<string, unknown>;
    const secs = (content?.sections || {}) as Record<string, { body?: string; items?: unknown[] }>;
    const narrativeKeys = Object.keys(secs).filter((k) => {
      const s = secs[k];
      return s && !s.items; // narrative sections don't have items
    });
    if (narrativeKeys.length === 0) return null;
    const done = narrativeKeys.filter((k) => !!(secs[k]?.body)).length;
    if (done === narrativeKeys.length) return null; // all done
    return { done, total: narrativeKeys.length };
  }, [report]);

  // Poll for updates while generating
  useEffect(() => {
    if (!isGenerating) return;
    const interval = setInterval(() => refetch(), 3000);
    return () => clearInterval(interval);
  }, [isGenerating, refetch]);

  // Stop polling when generation completes (all sections filled)
  useEffect(() => {
    if (isGenerating && !generationProgress) {
      setIsGenerating(false);
    }
  }, [isGenerating, generationProgress]);

  // Stop polling when SSE signals generation done (handles error/partial cases)
  useEffect(() => {
    if (!isGenerating) return;
    const handler = (e: Event) => {
      const detail = (e as CustomEvent).detail;
      if (detail?.reportId === id) {
        setIsGenerating(false);
        refetch();
      }
    };
    window.addEventListener("report-generation-done", handler);
    return () => window.removeEventListener("report-generation-done", handler);
  }, [isGenerating, id, refetch]);

  // Status class helper
  const getStatusClass = (status: string) => {
    switch (status) {
      case "published":
        return styles.statusPublished;
      case "archived":
        return styles.statusArchived;
      default:
        return styles.statusDraft;
    }
  };

  // ── Create Mode ──
  if (isCreateMode) {
    return (
      <div className={styles.page}>
        <div className={styles.topBar}>
          <Breadcrumb items={[
            { label: "Workbench", to: "/workbench/explore" },
            { label: "Reports" },
            { label: "New Report" },
          ]} />
        </div>

        <div className={styles.header}>
          <input
            className={styles.titleInput}
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Report title..."
          />
        </div>

        <div className={styles.headerMeta}>
          <div className={styles.headerMetaItem}>
            <span
              className={styles.tlpDot}
              style={{ background: TLP_COLORS[tlpMarking] }}
            />
            <select
              className={styles.tlpSelect}
              value={tlpMarking}
              onChange={(e) => setTlpMarking(e.target.value)}
            >
              {TLP_OPTIONS.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Template picker — an expander: collapsed it's one row showing the
            chosen template; picking a card collapses it to hand the editor
            the vertical room. */}
        <div className={styles.templateSelector}>
          <button
            type="button"
            className={styles.templateExpander}
            onClick={() => setTemplatePickerOpen((v) => !v)}
            aria-expanded={templatePickerOpen}
          >
            <span className={`caret-glyph ${styles.templateExpanderChevron}`}>
              {templatePickerOpen ? "▾" : "▸"}
            </span>
            <span className={styles.templateSelectorTitle}>Template</span>
            {(() => {
              const sel = templates?.find((t) => t.type === templateType);
              return sel ? (
                <>
                  <span className={styles.templateExpanderName}>{sel.name}</span>
                  <span className={styles.templateExpanderMeta}>
                    {sel.sections.length} sections
                  </span>
                </>
              ) : (
                <span className={styles.templateExpanderMeta}>Choose a template…</span>
              );
            })()}
            {!templatePickerOpen && <span className={styles.templateExpanderChange}>Change</span>}
          </button>
          {templatePickerOpen && (
            <div className={styles.templateGrid}>
              {templates?.map((tmpl) => (
                <div
                  key={tmpl.type}
                  className={`${styles.templateCard} ${
                    templateType === tmpl.type ? styles.templateCardActive : ""
                  }`}
                  onClick={() => {
                    setTemplateType(tmpl.type);
                    setTemplatePickerOpen(false);
                  }}
                >
                  <div className={styles.templateCardName}>{tmpl.name}</div>
                  <div className={styles.templateCardDesc}>
                    {tmpl.description}
                  </div>
                  <div className={styles.templateCardSections}>
                    {tmpl.sections.slice(0, 5).map((s) => (
                      <Chip key={typeof s === "string" ? s : s.name} truncate>
                        {typeof s === "string" ? s : s.title}
                      </Chip>
                    ))}
                    {tmpl.sections.length > 5 && <Chip>+{tmpl.sections.length - 5}</Chip>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className={styles.createEditor}>
          <CodeMirrorEditor
            value={body}
            onChange={handleBodyChange}
            language=""
            height="560px"
            prose
          />

          <div className={styles.sectionInsertBar}>
            {SNIPPET_INSERTS.map((s) => (
              <button
                key={s.label}
                className={styles.insertBtn}
                onClick={() => handleInsertSnippet(s.snippet)}
                type="button"
              >
                + {s.label}
              </button>
            ))}
          </div>
        </div>

        <div className={styles.metaRow}>
          <div className={styles.metaSection}>
            <label className={styles.metaLabel}>Summary</label>
            <textarea
              className={styles.metaTextarea}
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              rows={2}
              placeholder="Executive summary..."
            />
          </div>

          <div className={styles.metaSection}>
            <label className={styles.metaLabel}>Tags</label>
            <SimpleTagEditor
              tags={tags}
              onChange={(t) => setTags(t)}
            />
          </div>
        </div>

        <div className={styles.createActions}>
          <button
            className={styles.createBtn}
            onClick={handleCreate}
            disabled={!title.trim() || !templateType || createReport.isPending}
          >
            {createReport.isPending ? "Creating..." : "Create Report"}
          </button>
        </div>
      </div>
    );
  }

  // ── Edit Mode ──
  if (isLoading) {
    return (
      <div className={styles.page}>
        <div className={styles.loading}>Loading report...</div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className={styles.page}>
        <div className={styles.loading}>Report not found</div>
      </div>
    );
  }

  return (
    <div className={styles.page}>
      {/* Top Bar */}
      <div className={styles.topBar}>
        <Breadcrumb items={[
          { label: "Workbench", to: "/workbench/explore" },
          { label: "Reports" },
          { label: title || "Untitled Report" },
        ]} />
        <div className={styles.topActions}>
          <button
            className={`${styles.statusBtn} ${getStatusClass(report.status)}`}
            disabled
          >
            {report.status}
          </button>
          <button className={styles.deleteBtn} onClick={handleDelete}>
            Delete
          </button>
        </div>
      </div>

      {/* Header */}
      <div className={styles.header}>
        <span className={styles.templateBadge}>
          {report.template_type.replace(/_/g, " ")}
        </span>
        <input
          className={styles.titleInput}
          value={title}
          onChange={(e) => {
            setTitle(e.target.value);
            setHasChanges(true);
          }}
        />
      </div>

      <div className={styles.headerMeta}>
        <div className={styles.headerMetaItem}>
          <span
            className={styles.tlpDot}
            style={{ background: TLP_COLORS[tlpMarking] }}
          />
          <select
            className={styles.tlpSelect}
            value={tlpMarking}
            onChange={(e) => {
              setTlpMarking(e.target.value);
              setHasChanges(true);
            }}
          >
            {TLP_OPTIONS.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
        <div className={styles.headerMetaItem}>
          Version: v{report.version}
        </div>
        <div className={styles.headerMetaItem}>
          Status: {report.status}
        </div>
      </div>

      {/* Generation progress bar */}
      {isGenerating && generationProgress && (
        <div className={styles.progressBar}>
          <div className={styles.progressLabel}>
            Generating sections... {generationProgress.done} of{" "}
            {generationProgress.total} complete
          </div>
          <div className={styles.progressTrack}>
            <div
              className={styles.progressFill}
              style={{
                width: `${(generationProgress.done / generationProgress.total) * 100}%`,
              }}
            />
          </div>
        </div>
      )}

      {/* Two-column layout */}
      <div className={styles.layout}>
        {/* Left: Editor */}
        <div className={styles.editorPanel}>
          {/* Section tabs (if template has sections) */}
          {currentTemplateSections.length > 0 && !viewingVersionId && (
            <div className={styles.sectionTabs}>
              <button
                className={`${styles.sectionTab} ${activeSectionTab === null ? styles.sectionTabActive : ""}`}
                onClick={() => setActiveSectionTab(null)}
              >
                Full Document
              </button>
              {currentTemplateSections.map((sec) => (
                <button
                  key={sec.name}
                  className={`${styles.sectionTab} ${activeSectionTab === sec.name ? styles.sectionTabActive : ""}`}
                  onClick={() => setActiveSectionTab(sec.name)}
                >
                  {sec.title}
                  {sec.required && <span className={styles.requiredDot} />}
                  {sections[sec.name] ? (
                    <span className={styles.sectionFilled} />
                  ) : null}
                </button>
              ))}
            </div>
          )}

          {/* Full document view — rendered document by default, raw markdown
              behind a toggle. Data sections draw their items as tables. */}
          {(activeSectionTab === null || viewingVersionId) && (
            <>
              {!viewingVersionId && currentTemplateSections.length > 0 && (
                <div className={styles.docViewToggle}>
                  <button
                    className={`${styles.docViewBtn} ${docView === "rendered" ? styles.docViewBtnOn : ""}`}
                    onClick={() => setDocView("rendered")}
                    type="button"
                  >
                    Document
                  </button>
                  <button
                    className={`${styles.docViewBtn} ${docView === "markdown" ? styles.docViewBtnOn : ""}`}
                    onClick={() => setDocView("markdown")}
                    type="button"
                  >
                    Markdown
                  </button>
                </div>
              )}
              {!viewingVersionId && currentTemplateSections.length > 0 && docView === "rendered" ? (
                <div className={styles.docSurface}>
                  {currentTemplateSections.map((sec) => {
                    const data = (contentSections[sec.name] || {}) as SectionData;
                    let bodyText = sections[sec.name] || data.body || "";
                    // Generated bodies often open with their own "## Title"
                    // heading — the doc view already draws one, so drop it
                    // (same rule as the markdown exporter).
                    bodyText = bodyText.replace(/^\s*##\s+[^\n]*\n+/, "");
                    const items = Array.isArray(data.items) ? data.items : [];
                    return (
                      <section key={sec.name} className={styles.docSection}>
                        <h2 className={styles.docHeading}>{sec.title || data.title || sec.name}</h2>
                        {bodyText && <EntityLinkedMarkdown text={bodyText} />}
                        {items.length > 0 && <SectionItemsTable items={items} />}
                        {!bodyText && items.length === 0 && (
                          <p className={styles.docEmpty}>
                            {sec.type === "data"
                              ? "No data yet — fills from linked articles and entities."
                              : "Not written yet — open the section tab to write it or generate with AI."}
                          </p>
                        )}
                      </section>
                    );
                  })}
                </div>
              ) : (
                <CodeMirrorEditor
                  value={viewingVersionId ? viewingBody : (currentTemplateSections.length > 0 ? currentTemplateSections.map((sec) => sections[sec.name] || "").filter(Boolean).join("\n\n---\n\n") : body)}
                  onChange={viewingVersionId ? undefined : (currentTemplateSections.length > 0 ? undefined : handleBodyChange)}
                  language=""
                  readOnly={!!viewingVersionId || currentTemplateSections.length > 0}
                  height="500px"
                  prose
                />
              )}

              {viewingVersionId && viewingVersion && (
                <div className={styles.versionBanner}>
                  Viewing version {viewingVersion.version} (read-only)
                  <button
                    className={styles.versionBannerBtn}
                    onClick={() => setViewingVersionId(null)}
                  >
                    Back to current
                  </button>
                </div>
              )}

              {/* Snippet insert buttons */}
              {!viewingVersionId && (
                <div className={styles.sectionInsertBar}>
                  {SNIPPET_INSERTS.map((s) => (
                    <button
                      key={s.label}
                      className={styles.insertBtn}
                      onClick={() => handleInsertSnippet(s.snippet)}
                      type="button"
                    >
                      + {s.label}
                    </button>
                  ))}
                </div>
              )}
            </>
          )}

          {/* Section-specific editor */}
          {activeSectionTab !== null && !viewingVersionId && (() => {
            const sec = currentTemplateSections.find((s) => s.name === activeSectionTab);
            if (!sec) return null;
            return (
              <div className={styles.sectionEditor}>
                <div className={styles.sectionEditorHeader}>
                  <div>
                    <div className={styles.sectionEditorTitle}>{sec.title}</div>
                    {sec.description && (
                      <div className={styles.sectionEditorDesc}>{sec.description}</div>
                    )}
                  </div>
                  <div className={styles.sectionEditorActions}>
                    <Chip
                      tone="toned"
                      tint={sec.type === "data" ? "var(--warning)" : "var(--accent-intel)"}
                      className={styles.sectionTypeBadge}
                    >
                      {sec.type}
                    </Chip>
                    <button
                      className={styles.generateBtn}
                      onClick={() => handleGenerateSection(sec.name)}
                      disabled={generatingSection !== null}
                      type="button"
                    >
                      {generatingSection === sec.name ? (
                        <>Generating...</>
                      ) : (
                        <>Generate with AI</>
                      )}
                    </button>
                  </div>
                </div>
                <CodeMirrorEditor
                  value={sections[sec.name] || ""}
                  onChange={(val) => handleSectionChange(sec.name, val)}
                  language=""
                  height="400px"
                  prose
                />
              </div>
            );
          })()}

          {/* Save Bar */}
          {!viewingVersionId && (
            <div className={styles.saveBar}>
              {hasChanges && (
                <input
                  className={styles.changeDesc}
                  placeholder="Change description (optional)..."
                  value={changeDescription}
                  onChange={(e) => setChangeDescription(e.target.value)}
                />
              )}
              <button
                className={styles.saveBtn}
                onClick={handleSaveDraft}
                disabled={!hasChanges || updateReport.isPending}
              >
                {updateReport.isPending ? "Saving..." : "Save Draft"}
              </button>
              <button
                className={styles.publishBtn}
                onClick={handlePublish}
                disabled={updateReport.isPending}
              >
                Publish
              </button>
              <button
                className={styles.regenerateBtn}
                onClick={handleRegenerateAll}
                disabled={regenerateAll.isPending}
                type="button"
                title="Regenerate all narrative sections with AI"
              >
                {regenerateAll.isPending ? "Regenerating..." : "Regenerate All"}
              </button>
            </div>
          )}
        </div>

        {/* Right: Metadata Panel */}
        <div className={styles.metaPanel}>
          {/* Summary */}
          <div className={styles.metaSection}>
            <label className={styles.metaLabel}>Summary</label>
            <textarea
              className={styles.metaTextarea}
              value={summary}
              onChange={(e) => {
                setSummary(e.target.value);
                setHasChanges(true);
              }}
              rows={3}
              placeholder="Executive summary..."
            />
          </div>

          {/* Tags */}
          <div className={styles.metaSection}>
            <label className={styles.metaLabel}>Tags</label>
            <SimpleTagEditor
              tags={tags}
              onChange={(t) => {
                setTags(t);
                setHasChanges(true);
              }}
            />
          </div>

          {/* Linked Entries */}
          <div className={styles.metaSection}>
            <div className={styles.metaLabelRow}>
              <label className={styles.metaLabel}>
                Linked Entries ({entryIds.length})
              </label>
              <button
                className={styles.addBtn}
                onClick={() => setShowAddEntry(!showAddEntry)}
                type="button"
                title="Add entry"
              >
                +
              </button>
            </div>
            {showAddEntry && (
              <div className={styles.addPopover} ref={addEntryRef}>
                <input
                  className={styles.addSearchInput}
                  placeholder="Search entries..."
                  value={addEntrySearch}
                  onChange={(e) => setAddEntrySearch(e.target.value)}
                  autoFocus
                />
                {addEntryResults?.hits && addEntryResults.hits.length > 0 && (
                  <div className={styles.addResults}>
                    {addEntryResults.hits
                      .filter((h) => !entryIds.includes(h.id))
                      .map((hit) => (
                        <button
                          key={hit.id}
                          className={styles.addResultItem}
                          onClick={() => addEntryId(hit.id)}
                          type="button"
                        >
                          <span className={styles.addResultTitle}>{hit.title}</span>
                          <span className={styles.addResultMeta}>{hit.feed_title}</span>
                        </button>
                      ))}
                  </div>
                )}
              </div>
            )}
            {entryIds.length === 0 ? (
              <div className={styles.emptyLinked}>No linked entries</div>
            ) : (
              <div className={styles.linkedList}>
                {entryIds.map((eid) => (
                  <div key={eid} className={styles.linkedItem}>
                    <span className={styles.linkedItemType}>Entry</span>
                    <span
                      className={`${styles.linkedItemLabel} ${styles.linkedItemClickable}`}
                      title={entryNameMap[eid]?.title || eid}
                      onClick={() => navigate(`/?entry=${eid}`)}
                    >
                      {entryNameMap[eid]?.title || `${eid.slice(0, 8)}...`}
                    </span>
                    <button
                      className={styles.linkedItemRemove}
                      onClick={() => removeEntryId(eid)}
                      type="button"
                    >
                      x
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Linked Entities */}
          <div className={styles.metaSection}>
            <label className={styles.metaLabel}>
              Linked Entities (
              {Object.values(entityIds).reduce(
                (sum, ids) => sum + ids.length,
                0
              )}
              )
            </label>
            {Object.keys(entityIds).length === 0 ? (
              <div className={styles.emptyLinked}>No linked entities</div>
            ) : (
              <div className={styles.linkedList}>
                {Object.entries(entityIds).flatMap(([entityType, ids]) =>
                  ids.map((eid) => (
                    <div key={`${entityType}-${eid}`} className={styles.linkedItem}>
                      <span className={styles.linkedItemType}>
                        {entityType}
                      </span>
                      <span className={styles.linkedItemLabel} title={entityNameMap[eid] || eid}>
                        {entityNameMap[eid] || `${eid.slice(0, 8)}...`}
                      </span>
                      <button
                        className={styles.linkedItemRemove}
                        onClick={() => removeEntityId(entityType, eid)}
                        type="button"
                      >
                        x
                      </button>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>

          {/* Generate as Different Type */}
          <div className={styles.metaSection}>
            <label className={styles.metaLabel}>Generate as Different Type</label>
            {cloneAsType.isPending ? (
              <div className={styles.cloneStatus}>Creating report...</div>
            ) : (
              <>
                <button
                  className={styles.cloneToggleBtn}
                  onClick={() => setShowCloneAsType(!showCloneAsType)}
                  type="button"
                >
                  {showCloneAsType ? "Cancel" : "Choose template..."}
                </button>
                {showCloneAsType && (
                  <div className={styles.cloneTemplateList}>
                    {templates
                      ?.filter((t) => t.type !== templateType)
                      .map((t) => (
                        <button
                          key={t.type}
                          className={styles.cloneTemplateItem}
                          onClick={() => handleCloneAsType(t.type)}
                          type="button"
                        >
                          <span className={styles.cloneTemplateName}>{t.name}</span>
                          <span className={styles.cloneTemplateDesc}>{t.description}</span>
                        </button>
                      ))}
                  </div>
                )}
              </>
            )}
          </div>

          {/* Export */}
          <div className={styles.metaSection}>
            <label className={styles.metaLabel}>Export</label>
            <div className={styles.exportGroup}>
              {EXPORT_FORMATS.map((fmt) => (
                <button
                  key={fmt.value}
                  className={styles.exportBtn}
                  onClick={() => handleExport(fmt.value)}
                  disabled={exportReport.isPending}
                >
                  {fmt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Version History */}
          <div className={styles.metaSection}>
            <button
              className={styles.versionToggle}
              onClick={() => setShowVersions(!showVersions)}
            >
              Version History ({versions?.length ?? 0})
              <span>{showVersions ? "\u25BE" : "\u25B8"}</span>
            </button>
            {showVersions && (
              <div className={styles.versionList}>
                {!versions || versions.length === 0 ? (
                  <div className={styles.versionEmpty}>
                    No previous versions
                  </div>
                ) : (
                  versions.map((v) => (
                    <div
                      key={v.id}
                      className={`${styles.versionItem} ${
                        viewingVersionId === v.id ? styles.versionActive : ""
                      }`}
                      onClick={() =>
                        setViewingVersionId(
                          viewingVersionId === v.id ? null : v.id
                        )
                      }
                    >
                      <div className={styles.versionHeader}>
                        <span className={styles.versionNum}>
                          v{v.version}
                        </span>
                        <span className={styles.versionDate}>
                          {formatDate(v.created_at)}
                        </span>
                      </div>
                      {v.change_description && (
                        <div className={styles.versionDesc}>
                          {v.change_description}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            )}
          </div>

          {/* Meta Info */}
          <div className={styles.metaSection}>
            <div className={styles.metaInfo}>
              <span>Created: {formatDate(report.created_at)}</span>
              <span>Updated: {formatDate(report.updated_at)}</span>
              {report.published_at && (
                <span>Published: {formatDate(report.published_at)}</span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
