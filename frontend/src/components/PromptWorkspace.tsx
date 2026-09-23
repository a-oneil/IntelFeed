import {
  useState,
  useMemo,
  useRef,
  useEffect,
  useCallback,
  forwardRef,
  useImperativeHandle,
} from "react";
import { Link } from "react-router-dom";
import { EditorView, keymap, placeholder as cmPlaceholder } from "@codemirror/view";
import { EditorState } from "@codemirror/state";
import { StreamLanguage, HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { tags } from "@lezer/highlight";
import type { AITask, AIProvider, AITaskAssignment, AIPromptTemplate, AutomationRule } from "@/api/types";
import {
  useAITasks,
  useAIProviders,
  useAllTaskAssignments,
  useUpsertTaskAssignment,
  useCreateAITask,
  useUpdateAITask,
  useDeleteAITask,
  useActivePrompt,
  useUpdatePrompt,
  useResetPrompt,
  usePromptHistory,
  usePromptPreview,
  useRunAIOnEntry,
  usePromptBenchEntries,
  useAgentTools,
} from "@/hooks/useAI";
import { useCopilotConfig } from "@/hooks/useCopilotAuth";
import { useAutomationRules } from "@/hooks/useAutomation";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { AI_VARIABLE_GROUPS } from "@/utils/aiVariables";
import { formatDate } from "@/utils/formatDate";
import { NON_ENTRY_CATEGORIES } from "./AIAnalysisSection";
import { ResultContent } from "./AIResultsDisplay";
import AssignmentSelect from "./AssignmentSelect";
import { Chip } from "./primitives";
import styles from "./PromptWorkspace.module.css";
import { ResizeHandle } from "@/components/ResizeHandle";
import { useRailWidth } from "@/hooks/useRailWidth";
import { AsyncStateLoading } from "@/components/AsyncState";

/* ─── Jinja2 syntax highlighting (StreamLanguage, same pattern as
       CodeMirrorEditor's rule modes) ─────────────────────────────── */

const jinja2Mode: Parameters<typeof StreamLanguage.define>[0] = {
  token(stream) {
    if (stream.match(/^\{#.*?#\}/)) return "comment";
    if (stream.match(/^\{\{.*?\}\}/)) return "variableName";
    if (stream.match(/^\{%.*?%\}/)) return "keyword";
    if (stream.match(/^[^{]+/)) return null;
    stream.next();
    return null;
  },
};

const jsonMode: Parameters<typeof StreamLanguage.define>[0] = {
  token(stream) {
    if (stream.match(/^"(?:[^"\\]|\\.)*"(?=\s*:)/)) return "propertyName";
    if (stream.match(/^"(?:[^"\\]|\\.)*"/)) return "string";
    if (stream.match(/^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/)) return "number";
    if (stream.match(/^(?:true|false|null)\b/)) return "keyword";
    stream.next();
    return null;
  },
};

const promptHighlight = HighlightStyle.define([
  { tag: tags.variableName, color: "var(--accent)" },
  { tag: tags.keyword, color: "#79c0ff" },
  { tag: tags.comment, color: "var(--text-muted)", fontStyle: "italic" },
  { tag: tags.propertyName, color: "var(--accent)" },
  { tag: tags.string, color: "#a5d6a7" },
  { tag: tags.number, color: "#79c0ff" },
]);

const promptTheme = EditorView.theme(
  {
    "&": { backgroundColor: "transparent", fontSize: "0.75rem" },
    ".cm-content": {
      fontFamily: "var(--font-mono, monospace)",
      lineHeight: "1.65",
      padding: "0.6rem 0.85rem",
      caretColor: "var(--text-primary)",
    },
    "&.cm-focused": { outline: "none" },
    ".cm-placeholder": { color: "var(--text-muted)" },
  },
  { dark: true }
);

export interface PromptEditorHandle {
  insert: (text: string) => void;
}

const PromptCodeEditor = forwardRef<
  PromptEditorHandle,
  {
    value: string;
    onChange: (value: string) => void;
    placeholder?: string;
    minHeight?: string;
    language?: "jinja" | "json";
  }
>(function PromptCodeEditor({ value, onChange, placeholder, minHeight = "6rem", language = "jinja" }, ref) {
  const containerRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  useImperativeHandle(ref, () => ({
    insert(text: string) {
      const view = viewRef.current;
      if (!view) return;
      view.dispatch(view.state.replaceSelection(text));
      view.focus();
    },
  }));

  useEffect(() => {
    if (!containerRef.current) return;
    const extensions = [
      history(),
      keymap.of([...defaultKeymap, ...historyKeymap]),
      StreamLanguage.define(language === "json" ? jsonMode : jinja2Mode),
      syntaxHighlighting(promptHighlight),
      promptTheme,
      EditorView.lineWrapping,
      EditorView.updateListener.of((update) => {
        if (update.docChanged) onChangeRef.current(update.state.doc.toString());
      }),
    ];
    if (placeholder) extensions.push(cmPlaceholder(placeholder));
    const view = new EditorView({
      state: EditorState.create({ doc: value, extensions }),
      parent: containerRef.current,
    });
    viewRef.current = view;
    return () => {
      view.destroy();
      viewRef.current = null;
    };
    // Recreate only on mount — value sync below handles external changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    const current = view.state.doc.toString();
    if (value !== current) {
      view.dispatch({ changes: { from: 0, to: current.length, insert: value } });
    }
  }, [value]);

  return <div ref={containerRef} className={styles.editorShell} style={{ minHeight }} />;
});

/* ─── Helpers ────────────────────────────────────────────────────── */

function apiErrorMessage(err: unknown): string {
  const axiosErr = err as { response?: { data?: { error?: { message?: string } } }; message?: string };
  return axiosErr.response?.data?.error?.message ?? axiosErr.message ?? "Unknown error";
}

/** Chip props for the accent-outlined variants — was `.badgeAccent` / `.customTag`. */
const ACCENT_OUTLINE = {
  tone: "outline",
  tint: "color-mix(in srgb, var(--accent) 45%, transparent)",
  fg: "var(--accent)",
} as const;

/** Chip props for a plain outlined micro tag — was `.deprecatedTag` / `.histTag`. */
const MUTED_OUTLINE = {
  tone: "outline",
  tint: "var(--border)",
  fg: "var(--text-muted)",
} as const;

const GROUP_LABELS: Record<string, string> = {
  analysis: "Analysis",
  generation: "Generation",
  extraction: "Extraction",
  custom: "Custom",
};
const GROUP_ORDER = ["analysis", "generation", "extraction", "custom"];

function taskGroup(task: AITask): string {
  return task.category || "other";
}

function isActionEligible(task: AITask): boolean {
  return (
    !NON_ENTRY_CATEGORIES.has(task.category ?? "") &&
    task.name !== "entry_qa" &&
    !task.is_deprecated
  );
}

const groupRank = (c: string | null) => (c === "analysis" ? 0 : c === "generation" ? 1 : 2);

/** Eligible reader-panel tasks in display order (same sort the reader uses). */
function orderedActionTasks(tasks: AITask[]): AITask[] {
  return tasks
    .filter(isActionEligible)
    .sort((a, b) => {
      if (groupRank(a.category) !== groupRank(b.category)) {
        return groupRank(a.category) - groupRank(b.category);
      }
      const ao = a.entry_action_order;
      const bo = b.entry_action_order;
      if (ao != null && bo != null && ao !== bo) return ao - bo;
      if (ao != null && bo == null) return -1;
      if (ao == null && bo != null) return 1;
      return a.display_name.localeCompare(b.display_name);
    });
}

function actionUsesTask(action: Record<string, unknown>, taskName: string): boolean {
  if (action.type === "run_ai_task") {
    const cfg = (action.config ?? {}) as Record<string, unknown>;
    if (cfg.task_id === taskName) return true;
  }
  for (const key of ["then_actions", "else_actions"]) {
    const sub = action[key];
    if (Array.isArray(sub) && sub.some((a) => actionUsesTask(a as Record<string, unknown>, taskName))) {
      return true;
    }
  }
  return false;
}

function rulesUsingTask(rules: AutomationRule[] | undefined, taskName: string): AutomationRule[] {
  return (rules ?? []).filter((r) => r.actions.some((a) => actionUsesTask(a, taskName)));
}

type DiffLine = { type: "ctx" | "add" | "del" | "gap"; text: string };

/** Simple LCS line diff — prompts are small, so O(n·m) is fine. */
function diffLines(a: string, b: string): DiffLine[] {
  const A = a.split("\n");
  const B = b.split("\n");
  const m = A.length;
  const n = B.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const raw: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < m && j < n) {
    if (A[i] === B[j]) {
      raw.push({ type: "ctx", text: A[i] });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      raw.push({ type: "del", text: A[i] });
      i++;
    } else {
      raw.push({ type: "add", text: B[j] });
      j++;
    }
  }
  while (i < m) raw.push({ type: "del", text: A[i++] });
  while (j < n) raw.push({ type: "add", text: B[j++] });

  // Collapse long unchanged runs so the changes stay visible.
  const out: DiffLine[] = [];
  let run: DiffLine[] = [];
  const flushRun = (isEdge: boolean) => {
    if (run.length > (isEdge ? 3 : 6)) {
      const head = run.slice(0, isEdge ? 0 : 3);
      const tail = run.slice(run.length - 3);
      out.push(...head, { type: "gap", text: `⋯ ${run.length - head.length - tail.length} unchanged lines` }, ...tail);
    } else {
      out.push(...run);
    }
    run = [];
  };
  for (const line of raw) {
    if (line.type === "ctx") {
      run.push(line);
    } else {
      flushRun(out.length === 0);
      out.push(line);
    }
  }
  flushRun(true);
  return out;
}

/** Rough token estimate (~4 chars/token) for the rendered prompt. */
function estimateTokens(text: string): number {
  return Math.max(1, Math.round(text.length / 4));
}

/** Context window for an assignment when the provider config declares one. */
function contextWindowFor(
  assignment: AITaskAssignment | undefined,
  providers: AIProvider[] | undefined
): number | null {
  if (!assignment) return null;
  const provider = providers?.find((p) => p.id === assignment.provider_id);
  if (!provider || provider.provider_type !== "ollama") return null;
  const cfg = (provider.config ?? {}) as Record<string, unknown>;
  const overrides = ((cfg.model_overrides ?? {}) as Record<string, Record<string, unknown>>)[
    assignment.model_name
  ];
  const ctx = overrides?.num_ctx_max ?? overrides?.num_ctx ?? cfg.num_ctx_max ?? cfg.num_ctx;
  return typeof ctx === "number" ? ctx : null;
}

interface CreateSeed {
  name: string;
  display_name: string;
  description: string;
  category: string;
  template: string;
  system: string;
  output_schema?: Record<string, unknown> | null;
}

const EMPTY_SEED: CreateSeed = {
  name: "",
  display_name: "",
  description: "",
  category: "custom",
  template: "",
  system: "",
  output_schema: null,
};

/* ─── Workspace root: rail + detail ─────────────────────────────── */

export default function PromptWorkspace() {
  const { data: tasks, isLoading } = useAITasks();
  const { data: providers } = useAIProviders();
  const { data: assignments } = useAllTaskAssignments();
  const { data: rulesPage } = useAutomationRules();
  const upsertAssignment = useUpsertTaskAssignment();

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const rail = useRailWidth("prompt-tasks", { default: 240, min: 180, max: 480 });
  const [search, setSearch] = useState("");
  const [createSeed, setCreateSeed] = useState<CreateSeed | null>(null);
  const [assignAllOpen, setAssignAllOpen] = useState(false);

  const grouped = useMemo(() => {
    const filtered = (tasks ?? []).filter((t) => {
      if (!search.trim()) return true;
      const q = search.toLowerCase();
      return t.display_name.toLowerCase().includes(q) || t.name.toLowerCase().includes(q);
    });
    const byGroup = new Map<string, AITask[]>();
    for (const t of filtered) {
      const g = taskGroup(t);
      const list = byGroup.get(g) ?? [];
      list.push(t);
      byGroup.set(g, list);
    }
    const keys = [...byGroup.keys()].sort((a, b) => {
      const ia = GROUP_ORDER.indexOf(a);
      const ib = GROUP_ORDER.indexOf(b);
      if (ia !== -1 && ib !== -1) return ia - ib;
      if (ia !== -1) return -1;
      if (ib !== -1) return 1;
      return a.localeCompare(b);
    });
    return keys.map((key) => ({
      key,
      label: GROUP_LABELS[key] ?? key.charAt(0).toUpperCase() + key.slice(1),
      tasks: (byGroup.get(key) ?? []).sort((a, b) => {
        if (a.is_deprecated !== b.is_deprecated) return a.is_deprecated ? 1 : -1;
        return a.display_name.localeCompare(b.display_name);
      }),
    }));
  }, [tasks, search]);

  const selected = useMemo(() => {
    if (!tasks || tasks.length === 0) return null;
    return tasks.find((t) => t.id === selectedId) ?? tasks.find((t) => !t.is_deprecated) ?? tasks[0];
  }, [tasks, selectedId]);

  const unassignedCount = useMemo(
    () => (tasks ?? []).filter((t) => !t.is_deprecated && !assignments?.[t.id]).length,
    [tasks, assignments]
  );

  const handleAssignAll = (providerId: string, model: string) => {
    const provider = providers?.find((p) => p.id === providerId);
    for (const task of tasks ?? []) {
      if (task.is_deprecated) continue;
      if (task.requires_tools && provider && !provider.supports_tools) continue;
      upsertAssignment.mutate({
        taskId: task.id,
        provider_id: providerId,
        model_name: model,
        is_enabled: true,
      });
    }
    setAssignAllOpen(false);
  };

  if (isLoading) {
    return <AsyncStateLoading label="Loading tasks…" compact />;
  }

  const modelChip = (task: AITask) => {
    const a = assignments?.[task.id];
    if (!a) return <span className={`${styles.taskRowModel} ${styles.unassigned}`}>not assigned</span>;
    const provider = providers?.find((p) => p.id === a.provider_id);
    return (
      <span className={styles.taskRowModel}>
        {provider ? `${provider.name} / ` : ""}
        {a.model_name}
      </span>
    );
  };

  return (
    <div className={styles.workspace}>
      {/* Narrow-mode fallback when the rail is hidden */}
      <div className={styles.taskPicker}>
        <select
          aria-label="Select task"
          value={selected?.id ?? ""}
          onChange={(e) => {
            setCreateSeed(null);
            setSelectedId(e.target.value);
          }}
        >
          {grouped.map((g) => (
            <optgroup key={g.key} label={g.label}>
              {g.tasks.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.display_name}
                </option>
              ))}
            </optgroup>
          ))}
        </select>
      </div>

      {/* The rail's width rides a custom property: the shell is a grid, and
          below 1160px it drops to a single column that has to be able to take
          the width back. */}
      <div
        className={styles.shell}
        style={{ "--prompt-rail-w": `${rail.width}px` } as React.CSSProperties}
      >
        <aside className={styles.rail}>
          <div className={styles.railTop}>
            <input
              className={styles.railSearch}
              type="text"
              placeholder="Filter tasks…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <button
              className={styles.newTaskBtn}
              onClick={() => setCreateSeed({ ...EMPTY_SEED })}
              title="Create a custom task"
            >
              + New
            </button>
          </div>
          <div className={styles.railList}>
            {grouped.map((g) => (
              <div key={g.key}>
                <div className={styles.railGroup}>{g.label}</div>
                {g.tasks.map((task) => {
                  const visible = isActionEligible(task) && (task.show_in_entry_actions ?? true);
                  const isSelected = !createSeed && selected?.id === task.id;
                  return (
                    <div
                      key={task.id}
                      className={`${styles.taskRow} ${isSelected ? styles.taskRowSelected : ""} ${task.is_deprecated ? styles.taskRowDeprecated : ""}`}
                      role="button"
                      tabIndex={0}
                      onClick={() => {
                        setCreateSeed(null);
                        setSelectedId(task.id);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          setCreateSeed(null);
                          setSelectedId(task.id);
                        }
                      }}
                    >
                      <span
                        className={`${styles.visDot} ${visible ? "" : styles.visDotOff}`}
                        title={visible ? "Shown in article actions" : "Hidden from article actions"}
                      />
                      <span className={styles.taskRowName}>{task.display_name}</span>
                      {task.is_deprecated ? (
                        <Chip size="sm" className={styles.microTag} {...MUTED_OUTLINE}>
                          Deprecated
                        </Chip>
                      ) : !task.is_system ? (
                        <Chip size="sm" className={styles.microTag} {...ACCENT_OUTLINE}>
                          Custom
                        </Chip>
                      ) : (
                        <span />
                      )}
                      {modelChip(task)}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
          <div className={styles.railFoot}>
            {(tasks ?? []).length} tasks · {unassignedCount} unassigned ·{" "}
            <button className={styles.assignAllLink} onClick={() => setAssignAllOpen((v) => !v)}>
              Assign all…
            </button>
            {assignAllOpen && (
              <div className={styles.assignAllRow}>
                <AssignmentSelect
                  providers={providers}
                  value=""
                  onChange={handleAssignAll}
                  placeholder="Assign every task to…"
                  className={styles.assignAllSelect}
                />
              </div>
            )}
          </div>
        </aside>

        <ResizeHandle label="task list" className={styles.railResizer} {...rail.handleProps} />

        {createSeed ? (
          <CreateTaskPane
            seed={createSeed}
            onCancel={() => setCreateSeed(null)}
            onCreated={(task) => {
              setCreateSeed(null);
              setSelectedId(task.id);
            }}
          />
        ) : selected ? (
          <TaskDetail
            key={selected.id}
            task={selected}
            allTasks={tasks ?? []}
            providers={providers}
            assignment={assignments?.[selected.id]}
            rules={rulesPage?.items}
            onDuplicate={(seed) => setCreateSeed(seed)}
            onDeleted={() => setSelectedId(null)}
          />
        ) : (
          <div className={styles.emptyDetail}>No AI tasks yet — create one to get started.</div>
        )}
      </div>
    </div>
  );
}

/* ─── Create / duplicate pane ───────────────────────────────────── */

function CreateTaskPane({
  seed,
  onCancel,
  onCreated,
}: {
  seed: CreateSeed;
  onCancel: () => void;
  onCreated: (task: AITask) => void;
}) {
  const createTask = useCreateAITask();
  const [form, setForm] = useState<CreateSeed>(seed);

  const handleCreate = async () => {
    const task = await createTask.mutateAsync({
      name: form.name,
      display_name: form.display_name,
      description: form.description || undefined,
      category: form.category,
      default_prompt_template: form.template,
      default_system_template: form.system || undefined,
      output_schema: form.output_schema ?? undefined,
    });
    onCreated(task);
  };

  return (
    <section className={styles.work}>
      <header className={styles.workHead}>
        <div className={styles.workTitleRow}>
          <span className={styles.workTitle}>New custom task</span>
          <Chip pill className={styles.badge}>
            Custom task
          </Chip>
        </div>
        <div className={styles.workDesc}>
          Custom tasks are runnable from article actions, automation rules, and the copilot.
        </div>
      </header>
      <div className={styles.createForm}>
        <label className={styles.fieldLabel}>Machine name</label>
        <input
          className={styles.createInput}
          placeholder="e.g. my_custom_analysis"
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value.replace(/[^a-z0-9_]/g, "") })}
        />
        <label className={styles.fieldLabel}>Display name</label>
        <input
          className={styles.createInput}
          placeholder="e.g. My Custom Analysis"
          value={form.display_name}
          onChange={(e) => setForm({ ...form, display_name: e.target.value })}
        />
        <label className={styles.fieldLabel}>Description</label>
        <input
          className={styles.createInput}
          placeholder="Optional one-line description"
          value={form.description}
          onChange={(e) => setForm({ ...form, description: e.target.value })}
        />
        <label className={styles.fieldLabel}>Category</label>
        <select
          className={styles.createSelect}
          value={form.category}
          onChange={(e) => setForm({ ...form, category: e.target.value })}
        >
          <option value="analysis">Analysis</option>
          <option value="generation">Generation</option>
          <option value="extraction">Extraction</option>
          <option value="custom">Custom</option>
        </select>
        <label className={styles.fieldLabel}>
          System prompt <span className={styles.fieldHint}>— optional, sent once per call</span>
        </label>
        <textarea
          className={styles.createTextarea}
          rows={4}
          spellCheck={false}
          placeholder="No system prompt"
          value={form.system}
          onChange={(e) => setForm({ ...form, system: e.target.value })}
        />
        <label className={styles.fieldLabel}>
          User prompt <span className={styles.fieldHint}>— Jinja2, rendered per call</span>
        </label>
        <textarea
          className={styles.createTextarea}
          rows={10}
          spellCheck={false}
          placeholder={"Reference variables like {{ entry.title }} or {{ entries }}"}
          value={form.template}
          onChange={(e) => setForm({ ...form, template: e.target.value })}
        />
        <div className={styles.createActions}>
          <button
            className={styles.saveBtn}
            onClick={handleCreate}
            disabled={!form.name || !form.display_name || !form.template || createTask.isPending}
          >
            {createTask.isPending ? "Creating…" : "Create task"}
          </button>
          <button className={styles.ghostBtn} onClick={onCancel}>
            Cancel
          </button>
        </div>
      </div>
    </section>
  );
}

/* ─── Task detail: header + tabs ────────────────────────────────── */

type DetailTab = "prompt" | "test" | "routing" | "history";

function TaskDetail({
  task,
  allTasks,
  providers,
  assignment,
  rules,
  onDuplicate,
  onDeleted,
}: {
  task: AITask;
  allTasks: AITask[];
  providers: AIProvider[] | undefined;
  assignment: AITaskAssignment | undefined;
  rules: AutomationRule[] | undefined;
  onDuplicate: (seed: CreateSeed) => void;
  onDeleted: () => void;
}) {
  const [activeTab, setActiveTab] = useState<DetailTab>("prompt");

  const { data: activePrompt, isLoading: promptLoading } = useActivePrompt(task.id);
  const { data: history } = usePromptHistory(task.id);
  const updatePrompt = useUpdatePrompt();
  const resetPrompt = useResetPrompt();
  const updateTask = useUpdateAITask();
  const deleteTask = useDeleteAITask();
  const undoableDelete = useUndoableDelete();

  const [editText, setEditText] = useState("");
  const [editSystemText, setEditSystemText] = useState("");
  const [editName, setEditName] = useState("");
  const [isDirty, setIsDirty] = useState(false);
  const [saveMessage, setSaveMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const loadedVersionRef = useRef<string | null>(null);
  const userEditorRef = useRef<PromptEditorHandle>(null);

  // Output schema: system tasks keep their shipped default and edit a
  // separate override (the seeder re-syncs the default on deploy); custom
  // tasks own their schema outright and edit it in place.
  const isCustomTask = !task.is_system;
  const effectiveSchemaText = useMemo(() => {
    const schema = task.output_schema_override ?? task.output_schema;
    return schema ? JSON.stringify(schema, null, 2) : "";
  }, [task.output_schema_override, task.output_schema]);
  const [schemaText, setSchemaText] = useState(effectiveSchemaText);
  const [schemaMessage, setSchemaMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const schemaDirty = schemaText !== effectiveSchemaText;
  // Top-level required fields in the shipped default mark tasks whose output
  // is parsed by pipeline code (one-pass extraction, link validation, …).
  const pipelineFields = useMemo(
    () => (Array.isArray(task.output_schema?.required) ? (task.output_schema.required as string[]) : []),
    [task.output_schema]
  );

  useEffect(() => {
    setSchemaText(effectiveSchemaText);
    setSchemaMessage(null);
  }, [task.id, effectiveSchemaText]);

  useEffect(() => {
    if (activePrompt) {
      const versionKey = `${activePrompt.id}-${activePrompt.version}`;
      if (loadedVersionRef.current !== versionKey) {
        loadedVersionRef.current = versionKey;
        setEditText(activePrompt.template_text);
        setEditSystemText(activePrompt.system_text ?? "");
        setEditName(activePrompt.name);
        setIsDirty(false);
        setSaveMessage(null);
      }
    }
  }, [activePrompt]);

  const computeDirty = useCallback(
    (text: string, name: string, systemText: string) =>
      text !== activePrompt?.template_text ||
      name !== activePrompt?.name ||
      systemText !== (activePrompt?.system_text ?? ""),
    [activePrompt]
  );

  const handleTextChange = (text: string) => {
    setEditText(text);
    setIsDirty(computeDirty(text, editName, editSystemText));
    setSaveMessage(null);
  };
  const handleSystemTextChange = (text: string) => {
    setEditSystemText(text);
    setIsDirty(computeDirty(editText, editName, text));
    setSaveMessage(null);
  };
  const handleNameChange = (name: string) => {
    setEditName(name);
    setIsDirty(computeDirty(editText, name, editSystemText));
    setSaveMessage(null);
  };

  const handleSave = () => {
    setSaveMessage(null);
    updatePrompt.mutate(
      { taskId: task.id, template_text: editText, system_text: editSystemText, name: editName },
      {
        onSuccess: () => {
          setIsDirty(false);
          loadedVersionRef.current = null;
          setSaveMessage({ type: "success", text: "Saved as new version" });
          setTimeout(() => setSaveMessage(null), 3000);
        },
        onError: (err) => {
          setSaveMessage({
            type: "error",
            text: `Save failed: ${err instanceof Error ? err.message : "Unknown error"}`,
          });
        },
      }
    );
  };

  const handleReset = () => {
    if (confirm("Reset this prompt to the system default? Your customizations will be deactivated.")) {
      loadedVersionRef.current = null;
      resetPrompt.mutate(task.id, {
        onSuccess: () => {
          setIsDirty(false);
          setSaveMessage({ type: "success", text: "Reset to system default" });
          setTimeout(() => setSaveMessage(null), 3000);
        },
      });
    }
  };

  const handleSchemaSave = () => {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(schemaText);
    } catch (e) {
      setSchemaMessage({
        type: "error",
        text: `Invalid JSON: ${e instanceof Error ? e.message : "parse error"}`,
      });
      return;
    }
    setSchemaMessage(null);
    updateTask.mutate(
      {
        taskId: task.id,
        ...(isCustomTask ? { output_schema: parsed } : { output_schema_override: parsed }),
      },
      {
        onSuccess: () => {
          setSchemaMessage({
            type: "success",
            text: isCustomTask ? "Schema saved" : "Schema override saved",
          });
          setTimeout(() => setSchemaMessage(null), 3000);
        },
        onError: (err) => setSchemaMessage({ type: "error", text: apiErrorMessage(err) }),
      }
    );
  };

  const handleSchemaReset = () => {
    const prompt = isCustomTask
      ? "Remove the output schema? The task will return free-form text."
      : "Remove the schema override and return to the shipped default?";
    if (!confirm(prompt)) return;
    updateTask.mutate(
      {
        taskId: task.id,
        ...(isCustomTask ? { output_schema: null } : { output_schema_override: null }),
      },
      {
        onSuccess: () => {
          setSchemaMessage({
            type: "success",
            text: isCustomTask ? "Schema removed" : "Reset to default schema",
          });
          setTimeout(() => setSchemaMessage(null), 3000);
        },
        onError: (err) => setSchemaMessage({ type: "error", text: apiErrorMessage(err) }),
      }
    );
  };

  const handleRestoreVersion = (template: AIPromptTemplate) => {
    setEditText(template.template_text);
    setEditSystemText(template.system_text ?? "");
    setEditName(template.name);
    setIsDirty(true);
    setActiveTab("prompt");
  };

  const handleDelete = () => {
    undoableDelete({
      label: `Task "${task.display_name}"`,
      key: `ai-task-${task.id}`,
      onDelete: () => {
        deleteTask.mutate(task.id);
        onDeleted();
      },
    });
  };

  const handleDuplicate = () => {
    onDuplicate({
      name: `${task.name}_custom`,
      display_name: `${task.display_name} (Custom)`,
      description: task.description ?? "",
      category: task.category ?? "custom",
      template: editText,
      system: editSystemText,
      output_schema: task.output_schema_override ?? task.output_schema,
    });
  };

  // "Used by" line
  const usedByRules = useMemo(() => rulesUsingTask(rules, task.name), [rules, task.name]);
  const actionTasks = useMemo(() => orderedActionTasks(allTasks), [allTasks]);
  const visibleActionTasks = useMemo(
    () => actionTasks.filter((t) => t.show_in_entry_actions ?? true),
    [actionTasks]
  );
  const actionPosition = visibleActionTasks.findIndex((t) => t.id === task.id);

  const version = activePrompt?.version ?? 0;
  const isCustomPrompt = !!activePrompt?.created_by;

  return (
    <section className={styles.work}>
      <header className={styles.workHead}>
        <div className={styles.workTitleRow}>
          <span className={styles.workTitle}>{task.display_name}</span>
          <Chip pill className={styles.badge}>
            {task.is_system ? "System task" : "Custom task"}
          </Chip>
          <Chip pill className={styles.badge} {...(isCustomPrompt ? ACCENT_OUTLINE : {})}>
            {isCustomPrompt ? "Custom prompt" : "Default prompt"} · v{version}
          </Chip>
          {task.output_schema_override != null && (
            <Chip pill className={styles.badge} {...ACCENT_OUTLINE}>
              Custom schema
            </Chip>
          )}
          {task.is_deprecated && (
            <Chip pill className={styles.badge}>
              Deprecated
            </Chip>
          )}
          <span className={styles.spacer} />
          <button className={styles.ghostBtn} onClick={handleDuplicate}>
            Duplicate as custom
          </button>
          {!task.is_system && (
            <button className={`${styles.ghostBtn} ${styles.dangerBtn}`} onClick={handleDelete}>
              Delete
            </button>
          )}
        </div>
        {task.description && <div className={styles.workDesc}>{task.description}</div>}
        <div className={styles.usedBy}>
          <b>Used by:</b>{" "}
          {usedByRules.length > 0 ? (
            usedByRules.map((r, i) => (
              <span key={r.id}>
                {i > 0 && ", "}
                <Link to="/automation" className={styles.usedByLink}>
                  {r.name}
                </Link>
              </span>
            ))
          ) : (
            <span>no automation rules</span>
          )}
          {isActionEligible(task) && (
            <span>
              {" · "}
              {actionPosition >= 0
                ? `Article actions #${actionPosition + 1}`
                : "Hidden from article actions"}
            </span>
          )}
          {task.name === "entry_qa" && <span> · Copilot</span>}
        </div>
      </header>

      <nav className={styles.tabBar} role="tablist">
        {(
          [
            ["prompt", "Prompt"],
            ["test", "Preview & Test"],
            ["routing", "Routing & Visibility"],
            ["history", "History"],
          ] as Array<[DetailTab, string]>
        ).map(([key, label]) => (
          <button
            key={key}
            role="tab"
            aria-selected={activeTab === key}
            className={`${styles.tab} ${activeTab === key ? styles.tabActive : ""}`}
            onClick={() => setActiveTab(key)}
          >
            {label}
            {key === "history" && history && history.length > 0 && (
              <span className={styles.tabCount}>{history.length}</span>
            )}
          </button>
        ))}
      </nav>

      {activeTab === "prompt" && (
        <section className={styles.panel}>
          {promptLoading ? (
            <AsyncStateLoading label="Loading prompt…" compact />
          ) : (
            <>
              <div className={styles.promptToolbar}>
                <input
                  className={styles.promptNameInput}
                  value={editName}
                  onChange={(e) => handleNameChange(e.target.value)}
                  placeholder="Prompt name"
                />
                <span className={styles.verChip}>v{version}</span>
                {isDirty && <span className={styles.unsaved}>● Unsaved</span>}
                {saveMessage && (
                  <span className={saveMessage.type === "success" ? styles.saveBadge : styles.errorBadge}>
                    {saveMessage.text}
                  </span>
                )}
                <span className={styles.spacer} />
                <button
                  className={styles.ghostBtn}
                  onClick={handleReset}
                  disabled={resetPrompt.isPending || !isCustomPrompt}
                  title={isCustomPrompt ? "Reset to system default" : "Already using system default"}
                >
                  {resetPrompt.isPending ? "Resetting…" : "Reset to default"}
                </button>
                <button
                  className={styles.saveBtn}
                  onClick={handleSave}
                  disabled={!isDirty || updatePrompt.isPending}
                >
                  {updatePrompt.isPending ? "Saving…" : `Save as v${version + 1}`}
                </button>
              </div>

              <div className={styles.promptLayout}>
                <div className={styles.promptEditors}>
                  <div className={styles.fieldLabel}>
                    System prompt{" "}
                    <span className={styles.fieldHint}>— sent once per call, cacheable</span>
                  </div>
                  <PromptCodeEditor
                    value={editSystemText}
                    onChange={handleSystemTextChange}
                    placeholder="No system prompt for this task"
                    minHeight="5rem"
                  />
                  <div className={styles.fieldLabel}>
                    User prompt <span className={styles.fieldHint}>— Jinja2, rendered per call</span>
                  </div>
                  <PromptCodeEditor
                    ref={userEditorRef}
                    value={editText}
                    onChange={handleTextChange}
                    minHeight="14rem"
                  />
                </div>

                <aside className={styles.varsBox}>
                  <h4>Variables</h4>
                  <p className={styles.varsHint}>
                    Click to insert at the cursor. Availability depends on how the task is invoked —
                    per-entry contexts expose <code>{"{{ entry.* }}"}</code>; batch automation
                    populates <code>entries</code>, <code>entry_count</code>, <code>entry</code>.
                  </p>
                  {AI_VARIABLE_GROUPS.map((group) => (
                    <div key={group.group}>
                      <div className={styles.varGroupLabel}>{group.group}</div>
                      <div className={styles.varList}>
                        {group.vars.map((v) => (
                          <Chip
                            key={v}
                            className={styles.varChip}
                            title={`Insert {{ ${v} }}`}
                            onClick={() => userEditorRef.current?.insert(`{{ ${v} }}`)}
                          >
                            {v}
                          </Chip>
                        ))}
                      </div>
                    </div>
                  ))}
                </aside>
              </div>

              <div className={styles.schemaSection}>
                <div className={styles.promptToolbar}>
                  <div className={styles.fieldLabel}>
                    Output schema{" "}
                    <span className={styles.fieldHint}>
                      — JSON Schema the model's reply must follow
                    </span>
                  </div>
                  {schemaDirty && <span className={styles.unsaved}>● Unsaved</span>}
                  {schemaMessage && (
                    <span
                      className={schemaMessage.type === "success" ? styles.saveBadge : styles.errorBadge}
                    >
                      {schemaMessage.text}
                    </span>
                  )}
                  <span className={styles.spacer} />
                  {(isCustomTask || task.output_schema != null) && (
                    <>
                      <button
                        className={styles.ghostBtn}
                        onClick={handleSchemaReset}
                        disabled={
                          updateTask.isPending ||
                          (isCustomTask
                            ? task.output_schema == null
                            : task.output_schema_override == null)
                        }
                        title={
                          isCustomTask
                            ? "Remove the schema — the task returns free-form text"
                            : task.output_schema_override != null
                              ? "Remove the override and return to the shipped default"
                              : "Already using the shipped default schema"
                        }
                      >
                        {isCustomTask ? "Remove schema" : "Reset schema to default"}
                      </button>
                      <button
                        className={styles.saveBtn}
                        onClick={handleSchemaSave}
                        disabled={!schemaDirty || !schemaText.trim() || updateTask.isPending}
                      >
                        {updateTask.isPending ? "Saving…" : "Save schema"}
                      </button>
                    </>
                  )}
                </div>
                {!isCustomTask && task.output_schema == null ? (
                  <p className={styles.varsHint}>
                    This task returns free-form text — there is no structured output schema.
                  </p>
                ) : (
                  <>
                    {pipelineFields.length > 0 && (
                      <p className={styles.schemaWarning}>
                        This task's output is parsed by pipeline code — keep{" "}
                        {pipelineFields.map((f, i) => (
                          <span key={f}>
                            {i > 0 && ", "}
                            <code>{f}</code>
                          </span>
                        ))}{" "}
                        in <code>required</code> or the worker consuming it will break.
                      </p>
                    )}
                    <PromptCodeEditor
                      value={schemaText}
                      onChange={(text) => {
                        setSchemaText(text);
                        setSchemaMessage(null);
                      }}
                      language="json"
                      minHeight="10rem"
                      placeholder={
                        isCustomTask
                          ? 'No schema — the model replies with free-form text. Add one to force JSON, e.g. {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]}'
                          : undefined
                      }
                    />
                  </>
                )}
              </div>
            </>
          )}
        </section>
      )}

      {activeTab === "test" && (
        <TestBench
          task={task}
          assignment={assignment}
          providers={providers}
          systemText={editSystemText}
          templateText={editText}
          isDirty={isDirty}
        />
      )}

      {activeTab === "routing" && (
        <RoutingPanel task={task} allTasks={allTasks} providers={providers} assignment={assignment} />
      )}

      {activeTab === "history" && (
        <HistoryPanel history={history} activePrompt={activePrompt} onRestore={handleRestoreVersion} />
      )}
    </section>
  );
}

/* ─── Preview & Test ────────────────────────────────────────────── */

function TestBench({
  task,
  assignment,
  providers,
  systemText,
  templateText,
  isDirty,
}: {
  task: AITask;
  assignment: AITaskAssignment | undefined;
  providers: AIProvider[] | undefined;
  systemText: string;
  templateText: string;
  isDirty: boolean;
}) {
  const { data: entries } = usePromptBenchEntries(true);
  const preview = usePromptPreview();
  const runOnce = useRunAIOnEntry();
  const [entrySel, setEntrySel] = useState<string>("latest");
  const [runInfo, setRunInfo] = useState<{
    result: Record<string, unknown>;
    model: string | null;
    cost: string | null;
    ms: number;
  } | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  const runnableEntryId =
    entrySel === "latest" ? entries?.[0]?.id : entrySel !== "sample" ? entrySel : undefined;

  const handleRender = () => {
    preview.mutate({
      taskId: task.id,
      systemText: systemText || undefined,
      templateText: templateText || undefined,
      entryId: entrySel !== "latest" && entrySel !== "sample" ? entrySel : undefined,
      useSample: entrySel === "sample",
    });
  };

  const handleRun = async () => {
    if (!runnableEntryId) return;
    setRunError(null);
    setRunInfo(null);
    const t0 = performance.now();
    try {
      const data = await runOnce.mutateAsync({ entryId: runnableEntryId, taskName: task.name });
      setRunInfo({
        result: data.result,
        model: data.model_name,
        cost: data.cost_estimate,
        ms: performance.now() - t0,
      });
    } catch (err) {
      setRunError(err instanceof Error ? err.message : "Run failed");
    }
  };

  const rendered = preview.data;
  const renderedText = rendered
    ? `${rendered.rendered_system ?? ""}${rendered.rendered_system ? "\n\n" : ""}${rendered.rendered_user ?? ""}`
    : "";
  const tokenEstimate = rendered && !rendered.error ? estimateTokens(renderedText) : null;
  const ctxWindow = contextWindowFor(assignment, providers);
  const providerName = providers?.find((p) => p.id === assignment?.provider_id)?.name;

  return (
    <section className={styles.panel}>
      <div className={styles.testBar}>
        <label htmlFor="bench-entry">Render against</label>
        <select
          id="bench-entry"
          className={styles.benchSelect}
          value={entrySel}
          onChange={(e) => setEntrySel(e.target.value)}
        >
          <option value="latest">
            {entries?.[0] ? `Latest entry — "${entries[0].title.slice(0, 60)}"` : "Latest entry"}
          </option>
          {(entries ?? []).slice(1).map((entry) => (
            <option key={entry.id} value={entry.id}>
              {entry.title.slice(0, 70)}
            </option>
          ))}
          <option value="sample">Built-in sample entry</option>
        </select>
        <button className={styles.ghostBtn} onClick={handleRender} disabled={preview.isPending}>
          {preview.isPending ? "Rendering…" : "Render preview"}
        </button>
        <button
          className={styles.runBtn}
          onClick={handleRun}
          disabled={!runnableEntryId || !assignment || runOnce.isPending}
          title={
            !assignment
              ? "Assign a model first"
              : !runnableEntryId
                ? "Pick a real entry to run against"
                : "Run the saved prompt against this entry"
          }
        >
          {runOnce.isPending ? "Running…" : "▶ Run once"}
        </button>
        {tokenEstimate != null && (
          <Chip pill className={styles.tokenChip}>
            ~{tokenEstimate.toLocaleString()} tokens
            {ctxWindow != null && (
              <>
                {" · "}
                <b className={tokenEstimate <= ctxWindow ? styles.fits : styles.exceeds}>
                  {tokenEstimate <= ctxWindow ? "fits" : "exceeds"}
                </b>{" "}
                {assignment?.model_name} ctx {ctxWindow.toLocaleString()}
              </>
            )}
          </Chip>
        )}
      </div>
      {isDirty && (
        <div className={styles.benchNote}>
          Render preview uses your unsaved edits; <b>Run once uses the last saved version</b> — save
          first to test edits end-to-end.
        </div>
      )}

      <div className={styles.twoCol}>
        <div>
          <p className={styles.paneTitle}>Rendered prompt (exactly what the model receives)</p>
          {rendered?.error ? (
            <div className={styles.renderError}>
              Jinja error{rendered.line != null ? ` on line ${rendered.line}` : ""}: {rendered.error}
            </div>
          ) : rendered ? (
            <>
              {rendered.rendered_system && (
                <>
                  <p className={styles.subPaneTitle}>System</p>
                  <pre className={styles.renderedPre}>{rendered.rendered_system}</pre>
                </>
              )}
              {rendered.rendered_system && <p className={styles.subPaneTitle}>User</p>}
              <pre className={styles.renderedPre}>{rendered.rendered_user ?? ""}</pre>
              <p className={styles.sampleSourceNote}>
                {rendered.sample_source === "entry"
                  ? "Rendered against a real entry."
                  : "Rendered against the built-in sample entry."}
              </p>
            </>
          ) : (
            <div className={styles.benchEmpty}>
              Render the preview to see the exact prompt with variables resolved.
            </div>
          )}
        </div>
        <div>
          <p className={styles.paneTitle}>
            Response{assignment ? ` — ${providerName ?? ""} / ${assignment.model_name}` : ""}
          </p>
          {runError ? (
            <div className={styles.renderError}>{runError}</div>
          ) : runInfo ? (
            <>
              <div className={styles.respBody}>
                <ResultContent taskName={task.name} result={runInfo.result} />
              </div>
              <div className={styles.respMeta}>
                <span>latency {(runInfo.ms / 1000).toFixed(1)}s</span>
                {runInfo.model && <span>{runInfo.model}</span>}
                {runInfo.cost && <span>cost {runInfo.cost}</span>}
              </div>
            </>
          ) : (
            <div className={styles.benchEmpty}>
              {assignment
                ? "Run once to see the model's real response to this prompt."
                : "Assign a model in Routing & Visibility to run this task."}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

/* ─── Ollama agent tools ────────────────────────────────────────── */

/**
 * Per-task tool allowlist for agentic tasks running on an Ollama provider.
 * Stored as the assignment config's `ollama_tools` key; when unset, the
 * copilot uses the backend's curated default and other agentic tasks get the
 * full read-only registry. Mutating tools are never offered here.
 */
function OllamaToolsRow({
  task,
  assignment,
  providers,
}: {
  task: AITask;
  assignment: AITaskAssignment | undefined;
  providers: AIProvider[] | undefined;
}) {
  const upsertAssignment = useUpsertTaskAssignment();
  const provider = providers?.find((p) => p.id === assignment?.provider_id);
  const isOllama = !!assignment && provider?.provider_type === "ollama";
  const relevant = isOllama && !!task.requires_tools;

  const { data: toolDefs } = useAgentTools({ enabled: relevant });
  const { data: copilotCfg } = useCopilotConfig();

  const readOnlyTools = useMemo(
    () => (toolDefs ?? []).filter((t) => !t.mutating).sort((a, b) => a.name.localeCompare(b.name)),
    [toolDefs]
  );
  const defaultNames = useMemo(() => {
    if (task.name === "copilot") return copilotCfg?.default_ollama_tools ?? [];
    return readOnlyTools.map((t) => t.name); // non-copilot agentic tasks default to all read-only
  }, [task.name, copilotCfg, readOnlyTools]);

  const override = assignment?.config?.ollama_tools as string[] | undefined;
  const effective = override && override.length > 0 ? override : defaultNames;

  const [expanded, setExpanded] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(() => new Set(effective));
  // Re-sync local selection when the stored config (or default) changes.
  const effectiveKey = effective.join(",");
  useEffect(() => {
    setSelected(new Set(effectiveKey ? effectiveKey.split(",") : []));
  }, [effectiveKey]);

  if (!relevant) return null;

  const isDefault = !override || override.length === 0;
  const summary = isDefault
    ? task.name === "copilot"
      ? `Curated default (${defaultNames.length})`
      : `All read-only (${defaultNames.length})`
    : `Custom (${override.length})`;

  const saveConfig = (cfg: Record<string, unknown>) => {
    if (!assignment) return;
    upsertAssignment.mutate({
      taskId: task.id,
      provider_id: assignment.provider_id,
      model_name: assignment.model_name,
      is_enabled: assignment.is_enabled,
      config: cfg,
    });
  };

  return (
    <div className={styles.settingRow}>
      <div className={styles.settingInfo}>
        <div className={styles.settingLabel}>Agent tools (Ollama)</div>
        <div className={styles.settingHint}>
          IntelFeed tools this task may call. Fewer tools = smaller context and better tool
          selection on local models. Read-only tools only.
        </div>
        {expanded && (
          <div className={styles.toolsGrid}>
            {readOnlyTools.map((t) => (
              <label key={t.name} className={styles.toolChk} title={t.description}>
                <input
                  type="checkbox"
                  checked={selected.has(t.name)}
                  onChange={(e) => {
                    setSelected((prev) => {
                      const next = new Set(prev);
                      if (e.target.checked) next.add(t.name);
                      else next.delete(t.name);
                      return next;
                    });
                  }}
                />
                <span>{t.name}</span>
              </label>
            ))}
          </div>
        )}
      </div>
      <div className={styles.settingCtl}>
        <span className={styles.settingHint}>{summary}</span>
        {expanded ? (
          <>
            <button
              className={styles.toolsBtn}
              disabled={selected.size === 0 || upsertAssignment.isPending}
              title={selected.size === 0 ? "Select at least one tool" : undefined}
              onClick={() => {
                const cfg = { ...assignment!.config, ollama_tools: [...selected].sort() };
                saveConfig(cfg);
                setExpanded(false);
              }}
            >
              Save
            </button>
            <button
              className={styles.toolsBtn}
              disabled={upsertAssignment.isPending}
              onClick={() => {
                const cfg = { ...assignment!.config };
                delete cfg.ollama_tools;
                saveConfig(cfg);
                setExpanded(false);
              }}
            >
              Use default
            </button>
            <button className={styles.toolsBtn} onClick={() => setExpanded(false)}>
              Cancel
            </button>
          </>
        ) : (
          <button className={styles.toolsBtn} onClick={() => setExpanded(true)}>
            Edit
          </button>
        )}
      </div>
    </div>
  );
}

/* ─── Routing & Visibility ──────────────────────────────────────── */

function RoutingPanel({
  task,
  allTasks,
  providers,
  assignment,
}: {
  task: AITask;
  allTasks: AITask[];
  providers: AIProvider[] | undefined;
  assignment: AITaskAssignment | undefined;
}) {
  const upsertAssignment = useUpsertTaskAssignment();
  const updateTask = useUpdateAITask();

  const eligible = isActionEligible(task);
  const actionTasks = useMemo(() => orderedActionTasks(allTasks), [allTasks]);
  const visibleActionTasks = useMemo(
    () => actionTasks.filter((t) => t.show_in_entry_actions ?? true),
    [actionTasks]
  );
  const visiblePosition = visibleActionTasks.findIndex((t) => t.id === task.id);

  const move = (dir: -1 | 1) => {
    const group = actionTasks.filter((t) => groupRank(t.category) === groupRank(task.category));
    const idx = group.findIndex((t) => t.id === task.id);
    const swapIdx = idx + dir;
    if (idx === -1 || swapIdx < 0 || swapIdx >= group.length) return;
    const reordered = [...group];
    [reordered[idx], reordered[swapIdx]] = [reordered[swapIdx], reordered[idx]];
    // Normalize the whole group to sequential orders so future sorts are stable.
    reordered.forEach((t, i) => {
      if (t.entry_action_order !== i) updateTask.mutate({ taskId: t.id, entry_action_order: i });
    });
  };

  return (
    <section className={styles.panel}>
      <div className={styles.settingRow}>
        <div className={styles.settingInfo}>
          <div className={styles.settingLabel}>Model assignment</div>
          <div className={styles.settingHint}>
            Provider and model used whenever this task runs — reader panel, automation, or copilot.
          </div>
        </div>
        <div className={styles.settingCtl}>
          <AssignmentSelect
            providers={providers}
            value={assignment ? `${assignment.provider_id}|${assignment.model_name}` : ""}
            onChange={(providerId, model) =>
              upsertAssignment.mutate({
                taskId: task.id,
                provider_id: providerId,
                model_name: model,
                is_enabled: true,
              })
            }
            requiresTools={task.requires_tools}
            className={styles.benchSelect}
          />
        </div>
      </div>

      <div className={styles.settingRow}>
        <div className={styles.settingInfo}>
          <div className={styles.settingLabel}>Max output tokens</div>
          <div className={styles.settingHint}>
            Response budget for this task&apos;s calls. Too low truncates structured output
            mid-JSON (trailing keys are lost). Blank = provider config, else 4096.
          </div>
        </div>
        <div className={styles.settingCtl}>
          <input
            type="number"
            className={styles.numberInput}
            min={256}
            step={256}
            placeholder="4096"
            disabled={!assignment}
            defaultValue={assignment?.config?.max_tokens as number | undefined}
            key={`${task.id}-${assignment?.config?.max_tokens ?? ""}`}
            aria-label="Max output tokens"
            onBlur={(e) => {
              if (!assignment) return;
              const cfg = { ...assignment.config };
              const raw = e.target.value.trim();
              const parsed = raw === "" ? undefined : Number(raw);
              const current = cfg.max_tokens as number | undefined;
              const next = parsed !== undefined && Number.isFinite(parsed) && parsed > 0 ? Math.round(parsed) : undefined;
              if (next === current) return;
              if (next === undefined) delete cfg.max_tokens;
              else cfg.max_tokens = next;
              upsertAssignment.mutate({
                taskId: task.id,
                provider_id: assignment.provider_id,
                model_name: assignment.model_name,
                is_enabled: assignment.is_enabled,
                config: cfg,
              });
            }}
          />
        </div>
      </div>

      <OllamaToolsRow task={task} assignment={assignment} providers={providers} />

      <div className={styles.settingRow}>
        <div className={styles.settingInfo}>
          <div className={styles.settingLabel}>Task enabled</div>
          <div className={styles.settingHint}>
            Disabled tasks are skipped everywhere and their action button is hidden.
          </div>
        </div>
        <div className={styles.settingCtl}>
          <label className={styles.switch}>
            <input
              type="checkbox"
              checked={assignment?.is_enabled ?? false}
              disabled={!assignment}
              aria-label="Task enabled"
              onChange={(e) =>
                assignment &&
                upsertAssignment.mutate({
                  taskId: task.id,
                  provider_id: assignment.provider_id,
                  model_name: assignment.model_name,
                  is_enabled: e.target.checked,
                })
              }
            />
            <span className={styles.slider} />
          </label>
          {!assignment && <span className={styles.settingHint}>Assign a model first</span>}
        </div>
      </div>

      <div className={styles.settingRow}>
        <div className={styles.settingInfo}>
          <div className={styles.settingLabel}>Show in article actions</div>
          <div className={styles.settingHint}>
            Renders a button in the reader&apos;s AI panel. Hidden tasks stay runnable from
            automation and the copilot.
          </div>
        </div>
        <div className={styles.settingCtl}>
          {eligible ? (
            <>
              <div className={styles.orderCtl}>
                <button aria-label={`Move ${task.display_name} up`} onClick={() => move(-1)}>
                  ▲
                </button>
                <button aria-label={`Move ${task.display_name} down`} onClick={() => move(1)}>
                  ▼
                </button>
                <span className={styles.orderPos}>
                  {visiblePosition >= 0
                    ? `#${visiblePosition + 1} of ${visibleActionTasks.length}`
                    : "hidden"}
                </span>
              </div>
              <label className={styles.switch}>
                <input
                  type="checkbox"
                  checked={task.show_in_entry_actions ?? true}
                  aria-label="Show in article actions"
                  onChange={(e) =>
                    updateTask.mutate({ taskId: task.id, show_in_entry_actions: e.target.checked })
                  }
                />
                <span className={styles.slider} />
              </label>
            </>
          ) : (
            <span className={styles.settingHint}>
              Not available for {task.category ?? "this"} tasks
            </span>
          )}
        </div>
      </div>

      <div className={styles.settingRow}>
        <div className={styles.settingInfo}>
          <div className={styles.settingLabel}>Show in entity profiles</div>
          <div className={styles.settingHint}>
            Renders a button on the AI tab of entity profiles (actors, malware, CVEs, …).
            Uses the same order as article actions.
          </div>
        </div>
        <div className={styles.settingCtl}>
          {eligible ? (
            <label className={styles.switch}>
              <input
                type="checkbox"
                checked={task.show_in_entity_actions ?? true}
                aria-label="Show in entity profiles"
                onChange={(e) =>
                  updateTask.mutate({ taskId: task.id, show_in_entity_actions: e.target.checked })
                }
              />
              <span className={styles.slider} />
            </label>
          ) : (
            <span className={styles.settingHint}>
              Not available for {task.category ?? "this"} tasks
            </span>
          )}
        </div>
      </div>

      <div className={styles.settingRow}>
        <div className={styles.settingInfo}>
          <div className={styles.settingLabel}>Category</div>
          <div className={styles.settingHint}>
            Groups the task in lists and orders the reader panel (analysis before generation).
          </div>
        </div>
        <div className={styles.settingCtl}>
          {task.is_system ? (
            <span className={styles.settingHint}>
              {GROUP_LABELS[task.category ?? ""] ?? task.category ?? "—"} (fixed for system tasks)
            </span>
          ) : (
            <select
              className={styles.benchSelect}
              value={task.category ?? "custom"}
              onChange={(e) => updateTask.mutate({ taskId: task.id, category: e.target.value })}
            >
              <option value="analysis">Analysis</option>
              <option value="generation">Generation</option>
              <option value="extraction">Extraction</option>
              <option value="custom">Custom</option>
            </select>
          )}
        </div>
      </div>
    </section>
  );
}

/* ─── History ───────────────────────────────────────────────────── */

function HistoryPanel({
  history,
  activePrompt,
  onRestore,
}: {
  history: AIPromptTemplate[] | undefined;
  activePrompt: AIPromptTemplate | undefined;
  onRestore: (template: AIPromptTemplate) => void;
}) {
  const [selectedVersionId, setSelectedVersionId] = useState<string | null>(null);
  const selected =
    history?.find((h) => h.id === selectedVersionId) ??
    history?.find((h) => h.is_active) ??
    history?.[0];

  const diff = useMemo(() => {
    if (!selected || !activePrompt || selected.id === activePrompt.id) return null;
    return diffLines(selected.template_text, activePrompt.template_text);
  }, [selected, activePrompt]);

  if (!history || history.length === 0) {
    return (
      <section className={styles.panel}>
        <div className={styles.benchEmpty}>No saved versions yet — edits create version history.</div>
      </section>
    );
  }

  return (
    <section className={styles.panel}>
      <div className={styles.histLayout}>
        <div>
          {history.map((h) => (
            <div
              key={h.id}
              className={`${styles.histItem} ${selected?.id === h.id ? styles.histItemSel : ""}`}
              role="button"
              tabIndex={0}
              onClick={() => setSelectedVersionId(h.id)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  setSelectedVersionId(h.id);
                }
              }}
            >
              <div className={styles.histItemTop}>
                <span className={styles.histVer}>v{h.version}</span>
                <span className={styles.histDate}>{h.created_by ? formatDate(h.created_at) : "—"}</span>
              </div>
              <div className={styles.histName}>{h.name}</div>
              <div className={styles.histTags}>
                {h.is_active && (
                  <Chip
                    size="sm"
                    className={styles.microTag}
                    tone="outline"
                    tint="color-mix(in srgb, var(--success) 50%, transparent)"
                    fg="var(--success)"
                  >
                    Active
                  </Chip>
                )}
                <Chip size="sm" className={styles.microTag} {...MUTED_OUTLINE}>
                  {h.created_by ? "Custom" : "System"}
                </Chip>
              </div>
            </div>
          ))}
        </div>
        <div>
          {selected && activePrompt && selected.id !== activePrompt.id && diff ? (
            <div className={styles.diffBox}>
              <div className={styles.diffHead}>
                <span>
                  Comparing <b>v{selected.version}</b> → <b>v{activePrompt.version} (active)</b>
                </span>
                <button className={styles.restoreBtn} onClick={() => onRestore(selected)}>
                  Restore v{selected.version} as new version
                </button>
              </div>
              <pre className={styles.diffPre}>
                {diff.map((line, i) => (
                  <span
                    key={i}
                    className={`${styles.diffLine} ${
                      line.type === "add"
                        ? styles.diffAdd
                        : line.type === "del"
                          ? styles.diffDel
                          : line.type === "gap"
                            ? styles.diffGap
                            : styles.diffCtx
                    }`}
                  >
                    {line.type === "add" ? "+ " : line.type === "del" ? "- " : "  "}
                    {line.text}
                  </span>
                ))}
              </pre>
            </div>
          ) : (
            <div className={styles.benchEmpty}>
              {history.length > 1
                ? "This is the active version — select an older version to compare."
                : "Only one version exists."}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
