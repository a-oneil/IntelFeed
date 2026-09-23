import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { useUIStore, type ReportWizardState } from "@/stores/uiStore";
import { useReportTemplates, useGenerateFullReport } from "@/hooks/useIntelReports";
import { useSavedSearches } from "@/hooks/useSearch";
import SimpleTagEditor from "@/components/SimpleTagEditor";
import { Chip } from "@/components/primitives/Chip";
import type { ReportTemplate } from "@/api/types";
import styles from "./ReportWizardModal.module.css";

const TLP_OPTIONS = [
  "TLP:CLEAR",
  "TLP:GREEN",
  "TLP:AMBER",
  "TLP:AMBER+STRICT",
  "TLP:RED",
] as const;

export function ReportWizardModal() {
  const wizardState = useUIStore((s) => s.reportWizardState);
  const closeWizard = useUIStore((s) => s.closeReportWizard);

  if (!wizardState?.isOpen) return null;

  return (
    <div className={styles.overlay} onClick={closeWizard}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <WizardContent
          wizardState={wizardState}
          onClose={closeWizard}
        />
      </div>
    </div>
  );
}

interface WizardContentProps {
  wizardState: ReportWizardState;
  onClose: () => void;
}

function WizardContent({ wizardState, onClose }: WizardContentProps) {
  const navigate = useNavigate();
  const { data: templates } = useReportTemplates();
  const generateFull = useGenerateFullReport();

  const [step, setStep] = useState(1);
  const [selectedTemplate, setSelectedTemplate] = useState<string>(wizardState.templateType ?? "");
  const [searchLimit, setSearchLimit] = useState(50);
  const [title, setTitle] = useState("");
  const [tlpMarking, setTlpMarking] = useState("TLP:GREEN");
  const [focus, setFocus] = useState("");
  const [audience, setAudience] = useState("");
  const [tags, setTags] = useState<string[]>([]);

  // Mutable source state — allows editing search query or picking a saved search
  const [sourceType, setSourceType] = useState(wizardState.sourceType);
  const [searchQuery, setSearchQuery] = useState(wizardState.searchQuery || "");
  const [savedSearchId, setSavedSearchId] = useState(wizardState.savedSearchId || "");

  // Step 1 requires valid source: search needs a query, saved_search needs an ID
  const sourceValid =
    sourceType === "entry" ||
    sourceType === "entries" ||
    (sourceType === "search" && searchQuery.trim().length > 0) ||
    (sourceType === "saved_search" && savedSearchId.length > 0);

  const canNext = (step === 1 && sourceValid) || (step === 2 && !!selectedTemplate);

  const handleGenerate = useCallback(() => {
    if (!selectedTemplate) return;

    const templateName = templates?.find(
      (t) => t.type === selectedTemplate
    )?.name || selectedTemplate;

    const autoTitle =
      title || `${templateName} - ${new Date().toISOString().slice(0, 16).replace("T", " ")}`;

    generateFull.mutate(
      {
        source_type: sourceType,
        entry_id: wizardState.entryId,
        entry_ids: wizardState.entryIds,
        search_query: sourceType === "search" ? searchQuery : undefined,
        saved_search_id: sourceType === "saved_search" ? savedSearchId : undefined,
        search_limit:
          sourceType === "search" || sourceType === "saved_search"
            ? searchLimit
            : undefined,
        template_type: selectedTemplate,
        title: autoTitle,
        tlp_marking: tlpMarking,
        focus: focus || undefined,
        audience: audience || undefined,
        tags,
      },
      {
        onSuccess: (data) => {
          toast.success("Report created. Generating sections with AI...");
          navigate(`/workbench/report/${data.report.id}`);
          onClose();
        },
        onError: (err: unknown) => {
          const msg = err instanceof Error ? err.message : "Failed to create report";
          toast.error(msg);
        },
      }
    );
  }, [
    selectedTemplate,
    templates,
    title,
    wizardState,
    sourceType,
    searchQuery,
    savedSearchId,
    searchLimit,
    tlpMarking,
    focus,
    audience,
    tags,
    generateFull,
    navigate,
    onClose,
  ]);

  const stepTitles = ["Source", "Template", "Configuration"];

  return (
    <>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <span className={styles.title}>Generate AI Report</span>
          <span className={styles.stepIndicator}>
            Step {step} of 3: {stepTitles[step - 1]}
          </span>
        </div>
        <button className={styles.closeBtn} onClick={onClose}>
          &times;
        </button>
      </div>

      <div className={styles.body}>
        {step === 1 && (
          <SourceStep
            wizardState={wizardState}
            sourceType={sourceType}
            onSourceTypeChange={setSourceType}
            searchQuery={searchQuery}
            onSearchQueryChange={setSearchQuery}
            savedSearchId={savedSearchId}
            onSavedSearchChange={(id) => {
              setSavedSearchId(id);
            }}
            searchLimit={searchLimit}
            onSearchLimitChange={setSearchLimit}
          />
        )}
        {step === 2 && (
          <TemplateStep
            templates={templates || []}
            selected={selectedTemplate}
            onSelect={setSelectedTemplate}
          />
        )}
        {step === 3 && (
          <ConfigStep
            title={title}
            onTitleChange={setTitle}
            tlpMarking={tlpMarking}
            onTlpChange={setTlpMarking}
            focus={focus}
            onFocusChange={setFocus}
            audience={audience}
            onAudienceChange={setAudience}
            tags={tags}
            onTagsChange={setTags}
          />
        )}
      </div>

      <div className={styles.footer}>
        {step > 1 && (
          <button
            className={styles.backBtn}
            onClick={() => setStep((s) => s - 1)}
          >
            Back
          </button>
        )}
        {step < 3 ? (
          <button
            className={styles.nextBtn}
            onClick={() => setStep((s) => s + 1)}
            disabled={!canNext}
          >
            Next
          </button>
        ) : (
          <button
            className={styles.generateBtn}
            onClick={handleGenerate}
            disabled={generateFull.isPending || !selectedTemplate}
          >
            {generateFull.isPending ? "Generating..." : "Generate"}
          </button>
        )}
      </div>
    </>
  );
}

/* Step 1: Source */
function SourceStep({
  wizardState,
  sourceType,
  onSourceTypeChange,
  searchQuery,
  onSearchQueryChange,
  savedSearchId,
  onSavedSearchChange,
  searchLimit,
  onSearchLimitChange,
}: {
  wizardState: ReportWizardState;
  sourceType: string;
  onSourceTypeChange: (t: "search" | "saved_search") => void;
  searchQuery: string;
  onSearchQueryChange: (q: string) => void;
  savedSearchId: string;
  onSavedSearchChange: (id: string) => void;
  searchLimit: number;
  onSearchLimitChange: (n: number) => void;
}) {
  const { data: savedSearches } = useSavedSearches();

  // Fixed sources (entry, entries) — read-only confirmation
  if (wizardState.sourceType === "entry" || wizardState.sourceType === "entries") {
    const desc =
      wizardState.sourceType === "entry"
        ? wizardState.entryTitle || "1 selected article"
        : `${wizardState.entryIds?.length || 0} selected articles`;

    return (
      <div className={styles.sourceSummary}>
        <Chip tone="solid" tint="var(--accent)" className={styles.sourceBadge}>
          {wizardState.sourceType.replace("_", " ")}
        </Chip>
        <p className={styles.sourceDesc}>{desc}</p>
      </div>
    );
  }

  // Editable sources (search, saved_search) — user can type query or pick saved search
  const showLimit = sourceType === "search" || sourceType === "saved_search";

  return (
    <>
      <div className={styles.sourceToggle}>
        <button
          className={sourceType === "search" ? styles.sourceTabActive : styles.sourceTab}
          onClick={() => onSourceTypeChange("search")}
        >
          Search Query
        </button>
        <button
          className={sourceType === "saved_search" ? styles.sourceTabActive : styles.sourceTab}
          onClick={() => onSourceTypeChange("saved_search")}
        >
          Saved Search
        </button>
      </div>

      <div className={styles.sourceSummary}>
        {sourceType === "search" && (
          <div className={styles.field}>
            <label className={styles.label}>Search query</label>
            <input
              className={styles.input}
              placeholder="e.g., ransomware, APT29, CVE-2024-..."
              value={searchQuery}
              onChange={(e) => onSearchQueryChange(e.target.value)}
              autoFocus
            />
          </div>
        )}

        {sourceType === "saved_search" && (
          <div className={styles.field}>
            <label className={styles.label}>Select a saved search</label>
            {savedSearches && savedSearches.length > 0 ? (
              <div className={styles.savedSearchList}>
                {savedSearches.map((ss) => (
                  <button
                    key={ss.id}
                    className={
                      savedSearchId === ss.id
                        ? styles.savedSearchItemSelected
                        : styles.savedSearchItem
                    }
                    onClick={() => onSavedSearchChange(ss.id)}
                  >
                    <span className={styles.savedSearchName}>
                      {ss.display_name || ss.name}
                    </span>
                    {ss.query && (
                      <span className={styles.savedSearchQuery}>{ss.query}</span>
                    )}
                  </button>
                ))}
              </div>
            ) : (
              <p className={styles.sourceDesc}>No saved searches found.</p>
            )}
          </div>
        )}

        {showLimit && (
          <div className={styles.limitSlider}>
            <label className={styles.label}>Max articles:</label>
            <input
              type="range"
              min={10}
              max={200}
              step={10}
              value={searchLimit}
              onChange={(e) => onSearchLimitChange(Number(e.target.value))}
            />
            <span>{searchLimit}</span>
          </div>
        )}
      </div>
    </>
  );
}

/* Step 2: Template selection */
function TemplateStep({
  templates,
  selected,
  onSelect,
}: {
  templates: ReportTemplate[];
  selected: string;
  onSelect: (type: string) => void;
}) {
  return (
    <div className={styles.templateGrid}>
      {templates.map((t) => (
        <div
          key={t.type}
          className={
            selected === t.type
              ? styles.templateCardSelected
              : styles.templateCard
          }
          onClick={() => onSelect(t.type)}
        >
          <p className={styles.templateName}>{t.name}</p>
          <p className={styles.templateDesc}>{t.description}</p>
          <div className={styles.sectionPills}>
            {((t.sections || []) as Array<{ name: string } | string>).map((s) => {
              const name = typeof s === "string" ? s : s.name;
              return (
                <Chip key={name} className={styles.sectionPill} truncate>
                  {name.replace(/_/g, " ")}
                </Chip>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

/* Step 3: Configuration */
function ConfigStep({
  title,
  onTitleChange,
  tlpMarking,
  onTlpChange,
  focus,
  onFocusChange,
  audience,
  onAudienceChange,
  tags,
  onTagsChange,
}: {
  title: string;
  onTitleChange: (v: string) => void;
  tlpMarking: string;
  onTlpChange: (v: string) => void;
  focus: string;
  onFocusChange: (v: string) => void;
  audience: string;
  onAudienceChange: (v: string) => void;
  tags: string[];
  onTagsChange: (t: string[]) => void;
}) {
  return (
    <>
      <div className={styles.field}>
        <label className={styles.label}>Title</label>
        <input
          className={styles.input}
          placeholder="Auto-generated if left blank"
          value={title}
          onChange={(e) => onTitleChange(e.target.value)}
        />
      </div>

      <div className={styles.field}>
        <label className={styles.label}>TLP Marking</label>
        <select
          className={styles.select}
          value={tlpMarking}
          onChange={(e) => onTlpChange(e.target.value)}
        >
          {TLP_OPTIONS.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </div>

      <div className={styles.field}>
        <label className={styles.label}>
          Focus <span className={styles.optional}>(optional)</span>
        </label>
        <textarea
          className={styles.textarea}
          placeholder="e.g., Detection opportunities, lateral movement TTPs, infrastructure overlaps..."
          value={focus}
          onChange={(e) => onFocusChange(e.target.value)}
          maxLength={1000}
        />
      </div>

      <div className={styles.field}>
        <label className={styles.label}>
          Audience <span className={styles.optional}>(optional)</span>
        </label>
        <input
          className={styles.input}
          placeholder="e.g., SOC analysts, executive leadership, detection engineers..."
          value={audience}
          onChange={(e) => onAudienceChange(e.target.value)}
          maxLength={500}
        />
      </div>

      <div className={styles.field}>
        <label className={styles.label}>
          Tags <span className={styles.optional}>(optional)</span>
        </label>
        <SimpleTagEditor tags={tags} onChange={onTagsChange} />
      </div>
    </>
  );
}
