import { useState, useEffect, useCallback, useRef } from "react";
import { useParams, useNavigate, useSearchParams } from "react-router-dom";
import { useDetectionRule, useUpdateDetectionRule, useDeleteDetectionRule } from "@/hooks/useIntelligence";
import {
  useCreateDetectionRule,
  useDetectionRuleVersions,
  useRollbackVersion,
  useToggleRuleStatus,
  useValidateRule,
  useCheckFeasibility,
  useVersionDiff,
  useExtractRuleMetadata,
  useRuleCommitTimeline,
  useConvertRule,
  useRelatedRules,
  useRuleFreshIntel,
  streamRuleChat,
} from "@/hooks/useDetectionRules";
import type { ChatMessage } from "@/hooks/useDetectionRules";
import { generateRuleContent } from "@/hooks/useCreateRuleFromEntity";
import RuleBuilderShell from "@/components/RuleBuilderShell";
import type { RuleValidationResult, FeasibilityResult } from "@/api/types";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { useRailWidth } from "@/hooks/useRailWidth";
import { useMediaQuery } from "@/hooks/useMediaQuery";
import { Breadcrumb } from "@/components/Breadcrumb";
import { useIntelStore } from "@/stores/intelStore";
import { toast } from "sonner";
import { type SegmentedOption } from "@/components/primitives";
import {
  RuleAIActions,
  RuleChatPanel,
  RuleCompare,
  RuleContextRail,
  RuleConvertPanel,
  RuleDetailsForm,
  RuleHistoryPanel,
  RuleSlideOver,
  RuleStatusLine,
  RuleStructureRail,
  scrollEditorToLine,
  type RuleConversion,
  type RuleFormValues,
} from "@/components/ruleBench";
import styles from "./RuleDetailPage.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";
import { confirmDialog } from "@/utils/dialog";

const RULE_TYPE_LABELS: Record<string, string> = {
  sigma: "SIGMA",
  splunk_spl: "Splunk SPL",
  kql: "KQL",
  elastic_ql: "Elastic QL",
  crowdstrike_ql: "CrowdStrike QL",
  snort_suricata: "Snort/Suricata",
  yara: "YARA",
  nuclei: "Nuclei",
  panther: "Panther",
};

interface BenchSeed {
  entityType: string;
  entityKey: string;
  label: string;
  window: string;
  techniqueId: string | null;
  techniqueName: string | null;
  suggestedType: string;
  quotes: {
    entry_id: string;
    entry_title: string;
    text: string;
    paragraph_indices: number[];
    observable_type: string | null;
    observable_value: string | null;
  }[];
  entryIds: string[];
}

/** Line-comment prefix per format, for the evidence header a seeded draft opens with. */
const COMMENT_PREFIX: Record<string, string> = {
  sigma: "#",
  yara: "//",
  kql: "//",
  elastic_ql: "//",
  splunk_spl: "```", // SPL has no line comments; backtick block reads as annotation
  crowdstrike_ql: "//",
  nuclei: "#",
  snort_suricata: "#",
  panther: "#",
};

function seedHeader(seed: BenchSeed, ruleType: string): string {
  const c = COMMENT_PREFIX[ruleType] ?? "#";
  const lines = [
    `${c} Draft for ${seed.techniqueId ?? seed.label}${seed.techniqueName ? ` — ${seed.techniqueName}` : ""} (${seed.label})`,
  ];
  for (const q of seed.quotes) {
    lines.push(`${c} evidence: "${q.text.slice(0, 200)}"`);
    lines.push(
      `${c}   — ${q.entry_title}${q.paragraph_indices?.length ? ` ¶${q.paragraph_indices[0]}` : ""}`
    );
    if (q.observable_value) {
      lines.push(`${c} observable (${q.observable_type ?? "artefact"}): ${q.observable_value}`);
    }
  }
  return lines.join("\n") + "\n\n";
}

/** The drafting prompt: evidence-only, format-explicit, and the answer comes
    back as a code block the user applies to the buffer — the same diff-accept
    contract as Reduce noise / Evasion check. Never a silent save. */
function draftWithAiPrompt(seed: BenchSeed, ruleType: string): string {
  const evidence = seed.quotes.length
    ? seed.quotes
        .map((q) => {
          const cite = `${q.entry_title}${q.paragraph_indices?.length ? ` ¶${q.paragraph_indices[0]}` : ""}`;
          const obs = q.observable_value ? `\n  observable (${q.observable_type ?? "artefact"}): ${q.observable_value}` : "";
          return `- "${q.text}" — ${cite}${obs}`;
        })
        .join("\n")
    : "- (no verbatim quotes captured this window — draft from the technique's documented behaviour)";
  return [
    `Draft a complete ${ruleType} detection rule for ${seed.techniqueId ?? "the behaviour"}${seed.techniqueName ? ` (${seed.techniqueName})` : ""} as used by ${seed.label}.`,
    "",
    "Evidence from this window's reporting:",
    evidence,
    "",
    "Requirements: detect the documented behaviour, not the threat name; compile any typed observable into a selection clause verbatim; keep the rule specific enough to review. Return ONLY the rule in a single code block.",
  ].join("\n");
}

const RULE_EXT: Record<string, string> = {
  sigma: "yml", yara: "yar", kql: "kql", elastic_ql: "eql", splunk_spl: "spl",
  crowdstrike_ql: "cql", snort_suricata: "rules", nuclei: "yaml", panther: "py",
};

/** Everything that is not the rule body lives in the slide-over. */
type Pane = "details" | "ai" | "convert" | "history" | "structure" | "context" | "compare";

const PANE_TITLES: Record<Pane, string> = {
  details: "Details",
  ai: "AI Assist",
  convert: "Convert",
  history: "History",
  structure: "Structure",
  context: "Context",
  compare: "Compare",
};

export default function RuleDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const setActiveSection = useIntelStore((s) => s.setActiveSection);
  const isCreateMode = id === "new";
  const fromSet = searchParams.get("from_set") === "1";
  const isExtendMode = searchParams.get("extend") === "1";
  // The coverage workspace stashes the behaviour's evidence before navigating
  // here: technique, quotes with typed observables, entity link, format hint.
  // Read once; only trusted when from_set=1 rides on the URL.
  const [benchSeed] = useState<BenchSeed | null>(() => {
    if (typeof sessionStorage === "undefined") return null;
    try {
      const raw = sessionStorage.getItem("intelfeed-bench-seed");
      return raw ? (JSON.parse(raw) as BenchSeed) : null;
    } catch {
      return null;
    }
  });
  const seed = fromSet ? benchSeed : null;
  const { data: rule, isLoading } = useDetectionRule(isCreateMode ? undefined : id);
  // Extend mode: this rule is a derived_from child; show the upstream
  // read-only beside your edit so the diff is the interface.
  const { data: upstream } = useDetectionRule(
    isExtendMode && rule?.derived_from ? rule.derived_from : undefined
  );
  const [upstreamOpen, setUpstreamOpen] = useState(true);
  // The rule shelf docks on the right like the entry reader — its own
  // persisted width, its own collapse. Opening a fresh pane un-collapses it.
  const shelfRail = useRailWidth("rule-shelf", { default: 560, min: 380, max: 920 });
  const [shelfCollapsed, setShelfCollapsed] = useState(false);
  // The window's observables as a checklist: ticked items become the version
  // note, so the change record says which evidence the extension covers.
  const [coveredObs, setCoveredObs] = useState<number[]>([]);
  const toggleObs = (i: number, text: string) => {
    setCoveredObs((prev) => {
      const next = prev.includes(i) ? prev.filter((x) => x !== i) : [...prev, i];
      const quotes = seed?.quotes ?? [];
      setChangeDescription(
        next.length
          ? `Covers: ${next
              .sort()
              .map((n) => quotes[n]?.text.slice(0, 60) ?? text)
              .join(" · ")}`
          : ""
      );
      return next;
    });
  };
  const { data: versions } = useDetectionRuleVersions(isCreateMode ? undefined : id);
  const createRule = useCreateDetectionRule();
  const updateRule = useUpdateDetectionRule();
  const deleteRule = useDeleteDetectionRule();
  const undoableDelete = useUndoableDelete();
  const rollbackVersion = useRollbackVersion();
  const toggleStatus = useToggleRuleStatus();
  const validateRule = useValidateRule();
  const checkFeasibility = useCheckFeasibility();
  const extractMetadata = useExtractRuleMetadata();
  const { data: commitTimeline } = useRuleCommitTimeline(isCreateMode ? undefined : id);
  const { data: relatedRules } = useRelatedRules(isCreateMode ? undefined : id);
  const { data: freshIntel } = useRuleFreshIntel(isCreateMode ? undefined : id);
  const convertRule = useConvertRule();

  // Three columns need ~1200px. Below that each rail folds into the slide-over
  // rather than squeezing the editor, which is the thing being worked in.
  const railsCollapsed = useMediaQuery("(max-width: 1199px)");
  const structureCollapsed = useMediaQuery("(max-width: 899px)");

  // AI Chat state
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatStreaming, setChatStreaming] = useState(false);
  const chatAbortRef = useRef<AbortController | null>(null);

  // Local state for editing
  const [title, setTitle] = useState("");
  const [ruleType, setRuleType] = useState("sigma");
  const [ruleContent, setRuleContent] = useState("");
  const [pane, setPane] = useState<Pane | null>(null);
  useEffect(() => {
    if (pane) setShelfCollapsed(false);
  }, [pane]);
  // On a phone the shelf's tab strip is wider than the panel and scrolls, so a
  // tab selected from off-screen (History, Convert) would activate with no
  // visible trace. Pull the active one into view whenever the pane changes.
  const activeTabRef = useRef<HTMLButtonElement | null>(null);
  useEffect(() => {
    activeTabRef.current?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [pane]);
  const [compareRuleId, setCompareRuleId] = useState<string | null>(null);
  const [activeLine, setActiveLine] = useState<number | null>(null);
  const [issuesOpen, setIssuesOpen] = useState(false);
  const [copiedRule, setCopiedRule] = useState(false);
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("");
  const [tags, setTags] = useState<string[]>([]);
  const [mitreTactics, setMitreTactics] = useState<string[]>([]);
  const [dataSources, setDataSources] = useState<string[]>([]);
  const [sourceTtps, setSourceTtps] = useState<string[]>([]);
  const [notes, setNotes] = useState("");
  const [changeDescription, setChangeDescription] = useState("");
  const [validation, setValidation] = useState<RuleValidationResult | null>(null);
  const [feasibility, setFeasibility] = useState<FeasibilityResult | null>(null);
  const [viewingVersion, setViewingVersion] = useState<string | null>(null);
  const [diffVersionNum, setDiffVersionNum] = useState<number | null>(null);
  const [hasChanges, setHasChanges] = useState(false);
  const [extractedMeta, setExtractedMeta] = useState<Record<string, unknown> | null>(null);
  const [mappedFields, setMappedFields] = useState<Record<string, unknown> | null>(null);

  // Rule conversions: { [ruleType]: { content, converted_at, model } }
  const [conversions, setConversions] = useState<Record<string, RuleConversion>>({});
  const [activeConversionTab, setActiveConversionTab] = useState<string | null>(null);

  const versionDiff = useVersionDiff();
  const editorRef = useRef<HTMLDivElement>(null);
  const validateTimerRef = useRef<ReturnType<typeof setTimeout>>();
  const metaTimerRef = useRef<ReturnType<typeof setTimeout>>();
  const initializedCreate = useRef(false);

  // Pre-fill from query params in create mode
  useEffect(() => {
    if (!isCreateMode || initializedCreate.current) return;
    initializedCreate.current = true;

    // Seeded from the coverage workspace: technique + quotes as a cited
    // comment header, format from the telemetry tier. Saving returns to the set.
    if (seed) {
      const type = seed.suggestedType || "sigma";
      setRuleType(type);
      setRuleContent(seedHeader(seed, type));
      if (seed.techniqueId) setTags([`attack.${seed.techniqueId.toLowerCase()}`]);
      setHasChanges(true);
      return;
    }

    const entityType = searchParams.get("entity_type") as "cve" | "ttp" | null;
    const entityValue = searchParams.get("entity_value");
    const entryId = searchParams.get("entry_id") || undefined;

    if (entityType && entityValue) {
      const template = generateRuleContent({ entityType, entityValue, entryId });
      setTitle(template.title);
      setRuleType(template.rule_type);
      setRuleContent(template.rule_content);
      setSeverity(template.severity);
      setTags(template.tags);
    }
    setHasChanges(true);
  }, [isCreateMode, searchParams]);

  // Sync from server data
  useEffect(() => {
    if (rule) {
      setTitle(rule.title);
      setRuleType(rule.rule_type);
      setRuleContent(rule.rule_content);
      setDescription(rule.description || "");
      setSeverity(rule.severity || "");
      setTags(rule.tags);
      setMitreTactics(rule.mitre_tactics);
      setDataSources(rule.data_sources);
      setSourceTtps((rule.source_ttps as string[]) || []);
      setNotes(rule.notes || "");
      setExtractedMeta(rule.metadata || null);
      // Restore chat history from metadata
      const meta = rule.metadata as Record<string, unknown> | null;
      const savedChat = meta?.ai_chat_history;
      if (Array.isArray(savedChat) && savedChat.length > 0) {
        setChatMessages(savedChat as ChatMessage[]);
      }
      // Restore conversions from metadata
      const savedConversions = meta?.rule_conversions;
      if (savedConversions && typeof savedConversions === "object") {
        setConversions(savedConversions as Record<string, RuleConversion>);
      }
      setHasChanges(false);
    }
  }, [rule]);

  // Debounced validation
  const runValidation = useCallback(
    (content: string, ruleType: string) => {
      if (validateTimerRef.current) clearTimeout(validateTimerRef.current);
      validateTimerRef.current = setTimeout(() => {
        validateRule.mutate({ rule_type: ruleType, rule_content: content }, { onSuccess: setValidation });
      }, 800);
    },
    [validateRule]
  );

  // Debounced metadata extraction
  useEffect(() => {
    if (!ruleContent || ruleContent.length < 10) return;
    if (metaTimerRef.current) clearTimeout(metaTimerRef.current);
    metaTimerRef.current = setTimeout(() => {
      extractMetadata.mutate(
        { rule_type: ruleType, rule_content: ruleContent },
        {
          onSuccess: (result) => {
            if (result.metadata && Object.keys(result.metadata).length > 0) {
              setExtractedMeta(result.metadata);
              setMappedFields(result.mapped_fields);
              // In create mode, auto-fill empty fields
              if (isCreateMode) {
                autoFillFromMapped(result.mapped_fields);
              }
            }
          },
        }
      );
    }, 1200);
    return () => {
      if (metaTimerRef.current) clearTimeout(metaTimerRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ruleContent, ruleType]);

  const autoFillFromMapped = (mapped: Record<string, unknown>) => {
    if (!mapped) return;
    if (mapped.severity && !severity) setSeverity(mapped.severity as string);
    if (mapped.description && !description) setDescription(mapped.description as string);
    if (mapped.mitre_tactics && mitreTactics.length === 0) setMitreTactics(mapped.mitre_tactics as string[]);
    if (mapped.tags && tags.length === 0) setTags(mapped.tags as string[]);
    if (mapped.data_sources && dataSources.length === 0) setDataSources(mapped.data_sources as string[]);
    if (mapped.source_ttps && sourceTtps.length === 0) setSourceTtps(mapped.source_ttps as string[]);
  };

  const applyExtractedFields = () => {
    if (!mappedFields) return;
    if (mappedFields.severity) setSeverity(mappedFields.severity as string);
    if (mappedFields.description) setDescription(mappedFields.description as string);
    if (mappedFields.mitre_tactics) setMitreTactics(mappedFields.mitre_tactics as string[]);
    if (mappedFields.tags) setTags([...new Set([...tags, ...(mappedFields.tags as string[])])]);
    if (mappedFields.data_sources) setDataSources(mappedFields.data_sources as string[]);
    if (mappedFields.source_ttps) setSourceTtps(mappedFields.source_ttps as string[]);
    setHasChanges(true);
  };

  // Check feasibility when data sources change
  useEffect(() => {
    if (dataSources.length > 0) {
      checkFeasibility.mutate(dataSources, { onSuccess: setFeasibility });
    } else {
      setFeasibility(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dataSources]);

  const handleContentChange = (content: string) => {
    setRuleContent(content);
    setHasChanges(true);
    if (rule) runValidation(content, ruleType);
  };

  const formValues: RuleFormValues = { severity, description, tags, mitreTactics, dataSources, notes };
  const setters: { [K in keyof RuleFormValues]: (v: RuleFormValues[K]) => void } = {
    severity: setSeverity,
    description: setDescription,
    tags: setTags,
    mitreTactics: setMitreTactics,
    dataSources: setDataSources,
    notes: setNotes,
  };
  const handleFieldChange = <K extends keyof RuleFormValues>(key: K, value: RuleFormValues[K]) => {
    (setters[key] as (v: RuleFormValues[K]) => void)(value);
    setHasChanges(true);
  };

  const handleCopyRule = () => {
    navigator.clipboard.writeText(ruleContent);
    setCopiedRule(true);
    setTimeout(() => setCopiedRule(false), 2000);
  };

  const handleExportRule = () => {
    const blob = new Blob([ruleContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${(title || "rule").replace(/[^a-z0-9-_ ]/gi, "").slice(0, 80) || "rule"}.${RULE_EXT[ruleType] || "txt"}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleSaveCopy = () => {
    createRule.mutate(
      { rule_type: ruleType, title: `Copy of ${title}`, rule_content: ruleContent, description: description || undefined, is_draft: true },
      { onSuccess: (r: { id: string }) => navigate(`/workbench/rule/${r.id}`) }
    );
  };

  const returnToSet = (created: { id: string; title: string; rule_type: string }, op: "new" | "extend") => {
    if (!seed) return false;
    sessionStorage.setItem(
      "intelfeed-bench-return",
      JSON.stringify({
        entityType: seed.entityType,
        entityKey: seed.entityKey,
        ruleId: created.id,
        title: created.title,
        ruleType: created.rule_type,
        techniqueId: seed.techniqueId,
        op,
      })
    );
    sessionStorage.removeItem("intelfeed-bench-seed");
    navigate(`/workbench/${seed.entityType}/${seed.entityKey}?tab=detection`);
    return true;
  };

  const handleSave = () => {
    if (isCreateMode) {
      createRule.mutate(
        {
          title: title || "Untitled Rule",
          rule_type: ruleType,
          rule_content: ruleContent,
          description: description || undefined,
          is_draft: true,
          ...(seed
            ? {
                tags,
                source_ttps: seed.techniqueId ? [seed.techniqueId] : [],
                source_entries: seed.entryIds ?? [],
                source_actors: seed.entityType === "threat_actor" ? [seed.entityKey] : [],
              }
            : {}),
        },
        {
          onSuccess: (newRule) => {
            // The workspace picks the rule up from the return stash and adds it
            // to the set; rule_coverage rows were written on create, so it
            // counts on the board the moment it exists.
            if (!returnToSet(newRule, "new")) {
              navigate(`/workbench/rule/${newRule.id}`, { replace: true });
            }
          },
        }
      );
      return;
    }

    if (!id || !rule) return;
    const updates: Record<string, unknown> = { id };

    if (title !== rule.title) updates.title = title;
    if (ruleType !== rule.rule_type) updates.rule_type = ruleType;
    if (ruleContent !== rule.rule_content) {
      updates.rule_content = ruleContent;
      updates.change_description = changeDescription || undefined;
    }
    if (description !== (rule.description || "")) updates.description = description;
    if (severity !== (rule.severity || "")) updates.severity = severity;
    if (JSON.stringify(tags) !== JSON.stringify(rule.tags)) updates.tags = tags;
    if (JSON.stringify(mitreTactics) !== JSON.stringify(rule.mitre_tactics)) updates.mitre_tactics = mitreTactics;
    if (JSON.stringify(dataSources) !== JSON.stringify(rule.data_sources)) updates.data_sources = dataSources;
    if (JSON.stringify(sourceTtps) !== JSON.stringify(rule.source_ttps || [])) updates.source_ttps = sourceTtps;
    if (notes !== (rule.notes || "")) updates.notes = notes;
    // Merge chat history into metadata. Conversions are NOT persisted here:
    // each conversion is a sibling detection_rules row (derived_from) written
    // by the convert endpoint — re-writing the legacy metadata.rule_conversions
    // blob on every save is exactly what the sibling backfill exists to remove.
    // Any blob already in extractedMeta is passed through untouched so a
    // not-yet-backfilled legacy conversion is never silently deleted.
    const metaToSave: Record<string, unknown> = { ...(extractedMeta || {}) };
    if (chatMessages.length > 0) {
      metaToSave.ai_chat_history = chatMessages;
    } else {
      delete metaToSave.ai_chat_history;
    }
    updates.metadata = metaToSave;

    updateRule.mutate(updates as Parameters<typeof updateRule.mutate>[0], {
      onSuccess: () => {
        setHasChanges(false);
        setChangeDescription("");
      },
    });
  };

  const handleDelete = () => {
    if (!id) return;
    undoableDelete({
      label: "Detection rule",
      key: `rule-${id}`,
      onDelete: () => deleteRule.mutate(id, { onSuccess: () => navigate("/workbench/explore") }),
    });
  };

  const handleToggleStatus = () => {
    if (!id || !rule) return;
    toggleStatus.mutate({ ruleId: id, is_draft: !rule.is_draft });
  };

  const handleRollback = async (versionId: string) => {
    if (!id) return;
    if (
      !(await confirmDialog({
        title: "Roll back",
        message: "Rollback to this version? Current content will be saved as a new version.",
        confirmLabel: "Roll back",
      }))
    )
      return;
    rollbackVersion.mutate({ ruleId: id, versionId }, { onSuccess: () => setViewingVersion(null) });
  };

  const handleConvert = (targetType: string) => {
    if (!id || isCreateMode) return;
    convertRule.mutate(
      { ruleId: id, target_type: targetType },
      {
        onSuccess: (result) => {
          setConversions((prev) => ({
            ...prev,
            [result.target_type]: {
              content: result.converted_content,
              converted_at: new Date().toISOString(),
              model: result.model,
              tokens_used: result.tokens_used,
              cost: result.cost,
            },
          }));
          setActiveConversionTab(result.target_type);
          setHasChanges(true);
        },
        onError: (err) => {
          const e = err as { code?: string; response?: { data?: { error?: { message?: string } } }; message?: string };
          toast.error(
            e.code === "ECONNABORTED"
              ? "Conversion timed out — the AI provider took too long to respond."
              : e.response?.data?.error?.message ?? e.message ?? "Conversion failed"
          );
        },
      }
    );
  };

  const handleRemoveConversion = (type: string) => {
    setConversions((prev) => {
      const next = { ...prev };
      delete next[type];
      return next;
    });
    if (activeConversionTab === type) {
      const remaining = Object.keys(conversions).filter((k) => k !== type);
      setActiveConversionTab(remaining.length > 0 ? remaining[0] : null);
    }
    setHasChanges(true);
  };

  const handleUpdateConversionContent = (type: string, content: string) => {
    setConversions((prev) => ({ ...prev, [type]: { ...prev[type], content } }));
    setHasChanges(true);
  };

  // Auto-save chat history to rule metadata (no need to click Save).
  // Conversions live as sibling rows, not in the blob — see handleSave.
  const autoSaveMeta = useCallback(
    (messages: ChatMessage[], _convs: Record<string, RuleConversion>) => {
      if (isCreateMode || !id) return;
      const meta: Record<string, unknown> = { ...(extractedMeta || {}) };
      if (messages.length > 0) {
        meta.ai_chat_history = messages;
      } else {
        delete meta.ai_chat_history;
      }
      updateRule.mutate({ id, metadata: meta } as Parameters<typeof updateRule.mutate>[0]);
    },
    [isCreateMode, id, extractedMeta, updateRule]
  );

  const sendChat = (text: string) => {
    const message = text.trim();
    if (!message || chatStreaming) return;
    setPane("ai");
    setChatMessages((prev) => [...prev, { role: "user", content: message }]);
    setChatInput("");
    setChatStreaming(true);

    const abortCtrl = new AbortController();
    chatAbortRef.current = abortCtrl;

    // Add a placeholder assistant message that will be streamed into
    setChatMessages((prev) => [...prev, { role: "assistant", content: "" }]);

    streamRuleChat(
      {
        message,
        ruleContent,
        ruleType,
        title,
        severity,
        mitreTactics,
        dataSources,
        history: chatMessages,
        onChunk: (text) => {
          setChatMessages((prev) => {
            const updated = [...prev];
            const last = updated[updated.length - 1];
            if (last?.role === "assistant") {
              updated[updated.length - 1] = { ...last, content: last.content + text };
            }
            return updated;
          });
        },
        onDone: () => {
          setChatStreaming(false);
          chatAbortRef.current = null;
          // Auto-save chat — need latest messages from state
          setChatMessages((msgs) => {
            autoSaveMeta(msgs, conversions);
            return msgs;
          });
        },
        onError: (error) => {
          setChatMessages((prev) => {
            const updated = [...prev];
            const last = updated[updated.length - 1];
            if (last?.role === "assistant" && !last.content) {
              updated[updated.length - 1] = { ...last, content: `Error: ${error}` };
            } else {
              updated.push({ role: "assistant", content: `Error: ${error}` });
            }
            return updated;
          });
          setChatStreaming(false);
          chatAbortRef.current = null;
        },
      },
      abortCtrl.signal
    );
  };

  const handleChatStop = () => {
    chatAbortRef.current?.abort();
    setChatStreaming(false);
    chatAbortRef.current = null;
  };

  const handleOutlineSelect = (line: number) => {
    setActiveLine(line);
    scrollEditorToLine(editorRef.current, line, styles.lineFlash);
  };

  const openCompare = (otherId: string) => {
    setCompareRuleId(otherId);
    setPane("compare");
  };

  if (!isCreateMode && isLoading) return <div className={styles.page}><AsyncStateLoading label="Loading rule…" /></div>;
  if (!isCreateMode && !rule) return <div className={styles.page}><div className={styles.loading}>Rule not found</div></div>;

  const nearDupeCount = relatedRules?.near_duplicate.length ?? 0;
  const telemetryCounts = rule?.telemetry?.required.length
    ? { required: rule.telemetry.required.length, collected: rule.telemetry.collected.length }
    : feasibility
      ? { required: feasibility.feasible.length + feasibility.missing.length, collected: feasibility.feasible.length }
      : null;

  const paneTabs: SegmentedOption<Pane>[] = [
    ...(structureCollapsed ? [{ value: "structure" as Pane, label: "Structure" }] : []),
    ...(railsCollapsed ? [{ value: "context" as Pane, label: "Context" }] : []),
    { value: "details", label: "Details" },
    { value: "ai", label: "AI Assist" },
    ...(isCreateMode
      ? []
      : ([
          { value: "convert" as Pane, label: `Convert${Object.keys(conversions).length ? ` (${Object.keys(conversions).length})` : ""}` },
          { value: "history" as Pane, label: `History${versions?.length ? ` (${versions.length})` : ""}` },
        ])),
  ];

  return (
    <div className={styles.page}>
      <div className={styles.shell}>
      <div className={styles.shellMain}>
      <div className={styles.topBar}>
        <Breadcrumb items={[
          { label: "Workbench", to: "/workbench/explore" },
          { label: "Rules", onClick: () => { setActiveSection("rules"); navigate("/workbench/explore"); } },
          { label: isCreateMode ? "New Rule" : (title || "Untitled Rule") },
        ]} />
        <div className={styles.topActions}>
          {structureCollapsed && (
            <button className={styles.metaToggle} onClick={() => setPane("structure")}>Structure</button>
          )}
          {railsCollapsed && !isCreateMode && (
            <button className={styles.metaToggle} onClick={() => setPane("context")}>Context</button>
          )}
          <button className={styles.metaToggle} onClick={() => setPane("details")}>Details</button>
          {!isCreateMode && (
            <>
              <button
                className={`${styles.statusBtn} ${rule?.is_draft ? styles.draft : styles.published}`}
                onClick={handleToggleStatus}
              >
                {rule?.is_draft ? "Draft" : "Published"}
              </button>
              <button className={styles.deleteBtn} onClick={handleDelete}>Delete</button>
            </>
          )}
        </div>
      </div>

      <div className={styles.bench}>
        {!structureCollapsed && (
          <aside className={`${styles.rail} ${styles.railLeft}`}>
            <RuleStructureRail
              ruleContent={ruleContent}
              ruleType={ruleType}
              rule={rule}
              activeLine={activeLine}
              onSelectLine={handleOutlineSelect}
            />
          </aside>
        )}

        <div className={styles.center}>
          {!isCreateMode && (
            <div className={styles.edHeadline}>
              <span className={`${styles.edFmt} ${styles[`edFmt_${ruleType}`] || ""}`}>{RULE_TYPE_LABELS[ruleType] || ruleType}</span>
              {severity && <span className={styles.edSev} data-sev={severity}>{severity}</span>}
              {(rule?.source_cves as string[] | undefined)?.[0] && (
                <span className={styles.edCve}>{(rule?.source_cves as string[])[0]}</span>
              )}
              <div className={styles.edHeadlineActions}>
                <button className={styles.metaToggle} onClick={handleCopyRule}>{copiedRule ? "Copied!" : "Copy"}</button>
                <button className={styles.metaToggle} onClick={handleExportRule}>Export ↧</button>
                <button className={styles.metaToggle} onClick={handleSaveCopy} disabled={createRule.isPending}>Save a copy</button>
              </div>
            </div>
          )}
          {isCreateMode && (
            <div className={styles.createHeadline}>
              <select
                className={styles.createType}
                value={ruleType}
                onChange={(e) => { setRuleType(e.target.value); setHasChanges(true); }}
              >
                {Object.entries(RULE_TYPE_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
              <input
                className={styles.createTitle}
                placeholder="Untitled detection rule"
                value={title}
                onChange={(e) => { setTitle(e.target.value); setHasChanges(true); }}
              />
            </div>
          )}

          {seed && (
            <div className={styles.seedBanner}>
              <span className={styles.seedFact}>
                set: {seed.label}
                {seed.techniqueId ? ` · ${seed.techniqueId}` : ""}
                {isExtendMode ? " · extending" : " · drafting"}
              </span>
              {isCreateMode && (
                <button
                  className={styles.metaToggle}
                  disabled={chatStreaming}
                  title="Builds a first cut from the behaviour's evidence — arrives as a code block you apply to the editor, never a silent save"
                  onClick={() => sendChat(draftWithAiPrompt(seed, ruleType))}
                >
                  Draft with AI
                </button>
              )}
              <button
                className={styles.metaToggle}
                onClick={() => navigate(`/workbench/${seed.entityType}/${seed.entityKey}?tab=detection`)}
              >
                ← Back to set
              </button>
            </div>
          )}

          {isExtendMode && upstream && (
            <div className={styles.upstreamPane}>
              <button className={styles.upstreamHead} onClick={() => setUpstreamOpen((v) => !v)}>
                UPSTREAM · read-only · {upstream.source_repo ?? "local"}
                {upstream.license ? ` · ${upstream.license}` : ""}{" "}
                <span className="caret-glyph">{upstreamOpen ? "▾" : "▸"}</span>
              </button>
              {upstreamOpen && <pre className={styles.upstreamCode}>{upstream.rule_content}</pre>}
            </div>
          )}

          <div className={styles.editorWrap} ref={editorRef}>
            <RuleBuilderShell
              ruleType={ruleType}
              value={viewingVersion ? (versions?.find((v) => v.id === viewingVersion)?.rule_content || "") : ruleContent}
              onChange={viewingVersion ? () => {} : handleContentChange}
              readOnly={!!viewingVersion}
              validationErrors={viewingVersion ? [] : (validation?.errors || [])}
            />
          </div>

          {!viewingVersion && (
            <>
              <RuleAIActions onAsk={sendChat} disabled={chatStreaming} />
              <p className={styles.aiNote}>
                Each answer comes back as a block you accept into the buffer — not prose you copy out of a chat pane.
              </p>
            </>
          )}

          <RuleStatusLine
            validation={viewingVersion ? null : validation}
            ruleTypeLabel={RULE_TYPE_LABELS[ruleType] || ruleType}
            telemetry={telemetryCounts}
            nearDupeCount={nearDupeCount}
            freshIntelCount={freshIntel?.total ?? 0}
            issuesOpen={issuesOpen}
            onToggleIssues={() => setIssuesOpen((v) => !v)}
          />

          {issuesOpen && validation && !viewingVersion && (
            <div className={styles.errorList}>
              {validation.errors.map((err, i) => (
                <div key={i} className={err.severity === "error" ? styles.errorItem : styles.warningItem}>
                  {err.line && <span className={styles.lineNum}>L{err.line}</span>}
                  {err.message}
                </div>
              ))}
              {validation.suggestions.map((s, i) => (
                <div key={`s-${i}`} className={styles.suggestionItem}>{s}</div>
              ))}
            </div>
          )}

          {viewingVersion && (
            <div className={styles.versionViewBar}>
              Viewing version {versions?.find((v) => v.id === viewingVersion)?.version_number} (read-only)
              <button onClick={() => setViewingVersion(null)}>Back to current</button>
              <button onClick={() => handleRollback(viewingVersion)}>Rollback to this version</button>
            </div>
          )}

          {!viewingVersion && (
            <div className={styles.saveBar}>
              {!isCreateMode && hasChanges && ruleContent !== rule?.rule_content && (
                <input
                  className={styles.changeDesc}
                  placeholder="Change description (optional)..."
                  value={changeDescription}
                  onChange={(e) => setChangeDescription(e.target.value)}
                />
              )}
              <button
                className={styles.saveBtn}
                onClick={handleSave}
                disabled={!hasChanges || updateRule.isPending || createRule.isPending}
              >
                {updateRule.isPending || createRule.isPending
                  ? "Saving..."
                  : isCreateMode
                    ? seed
                      ? "Create → back to set"
                      : "Create Rule"
                    : "Save"}
              </button>
            </div>
          )}

          {isExtendMode && seed && seed.quotes.length > 0 && !viewingVersion && (
            <div className={styles.obsChecklist}>
              <div className={styles.obsHead}>The window&rsquo;s observables — ticked items become the version note</div>
              {seed.quotes.map((q, i) => (
                <label key={`${q.entry_id}-${i}`} className={styles.obsRow}>
                  <input
                    type="checkbox"
                    checked={coveredObs.includes(i)}
                    onChange={() => toggleObs(i, q.text)}
                  />
                  <span className={coveredObs.includes(i) ? styles.obsDone : styles.obsText}>
                    {q.observable_value ? `${q.observable_value} — ` : ""}
                    {q.text.slice(0, 120)}
                    <i className={styles.obsCite}>
                      {q.entry_title}
                      {q.paragraph_indices?.length ? ` ¶${q.paragraph_indices[0]}` : ""}
                    </i>
                  </span>
                </label>
              ))}
            </div>
          )}

        </div>

        {!railsCollapsed && !isCreateMode && (
          <aside className={`${styles.rail} ${styles.railRight}`}>
            <RuleContextRail
              rule={rule}
              freshIntel={freshIntel}
              related={relatedRules}
              feasibility={feasibility}
              onDiff={openCompare}
            />
          </aside>
        )}
      </div>
      </div>

      {pane && (
        <RuleSlideOver
          title={PANE_TITLES[pane]}
          onClose={() => setPane(null)}
          collapsed={shelfCollapsed}
          onToggleCollapse={() => setShelfCollapsed((v) => !v)}
          railStyle={shelfRail.style}
          onResize={shelfRail.handleProps.onResize}
          onResizeStart={shelfRail.handleProps.onResizeStart}
          onResizeEnd={shelfRail.handleProps.onResizeEnd}
          onResizeReset={shelfRail.handleProps.onReset}
          tabs={
            pane === "compare" ? (
              <button className={styles.metaToggle} onClick={() => setPane("details")}>← Back</button>
            ) : (
              <div className={styles.shelfTabs} role="tablist" aria-label="Rule shelf">
                {paneTabs.map((t) => (
                  <button
                    key={t.value}
                    type="button"
                    role="tab"
                    aria-selected={pane === t.value}
                    ref={pane === t.value ? activeTabRef : undefined}
                    className={`${styles.shelfTab} ${pane === t.value ? styles.shelfTabActive : ""}`}
                    onClick={() => setPane(t.value)}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            )
          }
        >
          {pane === "structure" && (
            <RuleStructureRail
              ruleContent={ruleContent}
              ruleType={ruleType}
              rule={rule}
              activeLine={activeLine}
              onSelectLine={(line) => { handleOutlineSelect(line); setPane(null); }}
            />
          )}
          {pane === "context" && (
            <RuleContextRail
              rule={rule}
              freshIntel={freshIntel}
              related={relatedRules}
              feasibility={feasibility}
              onDiff={openCompare}
            />
          )}
          {pane === "details" && (
            <RuleDetailsForm
              rule={rule}
              values={formValues}
              onChange={handleFieldChange}
              extractedMeta={extractedMeta}
              extracting={extractMetadata.isPending}
              mappedFields={mappedFields}
              onAutoFill={applyExtractedFields}
              feasibility={feasibility}
              commitTimeline={commitTimeline}
            />
          )}
          {pane === "ai" && (
            <RuleChatPanel
              embedded
              messages={chatMessages}
              input={chatInput}
              streaming={chatStreaming}
              onInput={setChatInput}
              onSend={() => sendChat(chatInput)}
              onStop={handleChatStop}
              onClear={() => { setChatMessages([]); autoSaveMeta([], conversions); }}
              onClose={() => setPane(null)}
              onApplyCode={(code) => { setRuleContent(code); setHasChanges(true); }}
            />
          )}
          {pane === "convert" && !isCreateMode && (
            <RuleConvertPanel
              ruleId={id}
              ruleType={ruleType}
              typeLabels={RULE_TYPE_LABELS}
              conversions={conversions}
              activeType={activeConversionTab}
              convertingType={convertRule.isPending ? ((convertRule.variables as { target_type?: string } | undefined)?.target_type ?? null) : null}
              onSelect={setActiveConversionTab}
              onConvert={handleConvert}
              onRemove={handleRemoveConversion}
              onUpdateContent={handleUpdateConversionContent}
            />
          )}
          {pane === "history" && !isCreateMode && (
            <RuleHistoryPanel
              versions={versions}
              viewingVersion={viewingVersion}
              diffVersion={diffVersionNum}
              diff={versionDiff.data}
              diffPending={versionDiff.isPending}
              onView={(versionId) => { setViewingVersion(versionId); setPane(null); }}
              onDiff={(versionNumber) => {
                setDiffVersionNum(versionNumber);
                versionDiff.mutate({ ruleId: id!, v1: versionNumber });
              }}
              onRollback={handleRollback}
            />
          )}
          {pane === "compare" && compareRuleId && (
            <RuleCompare otherRuleId={compareRuleId} currentContent={ruleContent} />
          )}
        </RuleSlideOver>
      )}
      </div>
    </div>
  );
}
