import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { AIProvider } from "@/api/types";
import {
  useAIProviders,
  useCreateAIProvider,
  useUpdateAIProvider,
  useTestAIProvider,
  useResumeAIProvider,
  useDeleteAIProvider,
  useAICostSummary,
  useAICostBreakdown,
  type AICostBreakdownRow,
  type AICallerCostRow,
  type AICostBreakdown,
} from "@/hooks/useAI";
import { formatDate } from "@/utils/formatDate";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import ClaudeCodeConfigEditor from "./ClaudeCodeConfigEditor";
import PromptWorkspace from "./PromptWorkspace";
import { Chip, Segmented } from "./primitives";
import { UserKeysSection } from "./UserKeysSection";
import { compactCount, formatUsd } from "@/utils/format";
import styles from "./AISettings.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";

type AISection = "providers" | "prompts" | "keys" | "cost";
const SECTIONS: readonly AISection[] = ["providers", "prompts", "keys", "cost"];

export default function AISettings() {
  // `?tab=` is how the Engine's settings search deep-links a key that lives
  // here (the personal-key policy on User keys).
  const [searchParams] = useSearchParams();
  const requested = searchParams.get("tab");
  const [activeSection, setActiveSection] = useState<AISection>(
    SECTIONS.find((s) => s === requested) ?? "providers",
  );

  return (
    <div className={styles.container}>
      <ProviderHealthBanner
        onGoToProviders={
          activeSection === "providers"
            ? undefined
            : () => setActiveSection("providers")
        }
      />
      <div className={styles.engineNote}>
        Extraction model, budget, and batching are configured in{" "}
        <Link to="/settings?section=engine&tab=pipeline&stage=extract">Engine → extract stage</Link>.
      </div>
      <div className={styles.tabs}>
        <button
          className={
            activeSection === "providers" ? styles.tabActive : styles.tab
          }
          onClick={() => setActiveSection("providers")}
        >
          Providers
        </button>
        <button
          className={
            activeSection === "prompts" ? styles.tabActive : styles.tab
          }
          onClick={() => setActiveSection("prompts")}
        >
          Prompts
        </button>
        <button
          className={activeSection === "keys" ? styles.tabActive : styles.tab}
          onClick={() => setActiveSection("keys")}
        >
          User keys
        </button>
        <button
          className={activeSection === "cost" ? styles.tabActive : styles.tab}
          onClick={() => setActiveSection("cost")}
        >
          Cost Dashboard
        </button>
      </div>

      {activeSection === "providers" && (
        <div className={styles.panelCard}>
          <ProvidersSection />
        </div>
      )}
      {activeSection === "prompts" && <PromptWorkspace />}
      {activeSection === "keys" && (
        <div className={styles.panelCard}>
          <UserKeysSection />
        </div>
      )}
      {activeSection === "cost" && (
        <div className={styles.panelCard}>
          <CostSection />
        </div>
      )}
    </div>
  );
}

/**
 * Cross-tab health banner: auto-pause on quota exhaustion is easy to miss when
 * you're on the Prompts or Cost tab. Surface paused/unavailable providers at the
 * top of AI Configuration regardless of the active tab, with a one-click Resume.
 */
function ProviderHealthBanner({ onGoToProviders }: { onGoToProviders?: () => void }) {
  const { data: allProviders } = useAIProviders();
  // The admin's own personal key is listed alongside; it is not the instance's.
  const providers = allProviders?.filter((p) => !p.user_id);
  const resumeProvider = useResumeAIProvider();

  if (!providers?.length) return null;

  const now = new Date();
  const paused = providers.filter(
    (p) => !!p.paused_until && new Date(p.paused_until) > now
  );
  const hasUsable = providers.some(
    (p) => p.is_active && !(p.paused_until && new Date(p.paused_until) > now)
  );

  if (!paused.length && hasUsable) return null;

  return (
    <div className={styles.healthBanner} role="alert">
      <div className={styles.healthBannerBody}>
        <span className={styles.healthBannerIcon}>⚠</span>
        <div className={styles.healthBannerText}>
          {!hasUsable && (
            <strong>No AI provider is currently available.</strong>
          )}
          {paused.length > 0 && (
            <span>
              {paused.length === 1
                ? `${paused[0].name} is auto-paused`
                : `${paused.length} providers are auto-paused`}
              {paused[0]?.paused_reason ? ` — ${paused[0].paused_reason}` : ""}
              {paused.length === 1 && paused[0].paused_until
                ? ` (until ${formatDate(paused[0].paused_until)})`
                : ""}
              . Tasks routed here fail until resumed.
            </span>
          )}
          {!hasUsable && !paused.length && (
            <span> Enable a provider under Providers to use AI features.</span>
          )}
        </div>
      </div>
      <div className={styles.healthBannerActions}>
        {onGoToProviders && (
          <button
            className={styles.healthBannerLink}
            onClick={onGoToProviders}
            title="Open the Providers tab"
          >
            Manage providers
          </button>
        )}
        {paused.length === 1 && (
          <button
            className={styles.resumeBtn}
            onClick={() => resumeProvider.mutate(paused[0].id)}
            disabled={resumeProvider.isPending}
            title="Clear the auto-pause and let the engine route tasks here again"
          >
            Resume now
          </button>
        )}
      </div>
    </div>
  );
}

// Per-model knobs the Ollama provider reads from config / config.model_overrides.
// All values are kept as strings while editing; empty string = inherit/unset.
type OllamaKnobs = {
  think: string; // "" inherit | "on" | "off"
  num_ctx_max: string;
  num_ctx: string;
  timeout_seconds: string;
  keep_alive: string; // Ollama duration ("30m", "1h") or seconds; -1 = never unload
};

function knobsFrom(cfg: Record<string, unknown> | undefined): OllamaKnobs {
  const c = cfg || {};
  return {
    think: c.think === undefined ? "" : c.think ? "on" : "off",
    num_ctx_max: c.num_ctx_max != null ? String(c.num_ctx_max) : "",
    num_ctx: c.num_ctx != null ? String(c.num_ctx) : "",
    timeout_seconds: c.timeout_seconds != null ? String(c.timeout_seconds) : "",
    keep_alive: c.keep_alive != null ? String(c.keep_alive) : "",
  };
}

function knobsToConfig(k: OllamaKnobs): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (k.think === "on") out.think = true;
  if (k.think === "off") out.think = false;
  if (k.num_ctx_max.trim()) out.num_ctx_max = parseInt(k.num_ctx_max, 10);
  if (k.num_ctx.trim()) out.num_ctx = parseInt(k.num_ctx, 10);
  if (k.timeout_seconds.trim()) out.timeout_seconds = parseInt(k.timeout_seconds, 10);
  const ka = k.keep_alive.trim();
  if (ka) out.keep_alive = /^-?\d+$/.test(ka) ? parseInt(ka, 10) : ka;
  return out;
}

function OllamaConfigEditor({ provider, onClose }: { provider: AIProvider; onClose: () => void }) {
  const updateProvider = useUpdateAIProvider();
  const cfg = (provider.config || {}) as Record<string, unknown>;
  const savedOverrides = (cfg.model_overrides || {}) as Record<string, Record<string, unknown>>;
  const [defaults, setDefaults] = useState<OllamaKnobs>(() => knobsFrom(cfg));
  const [models, setModels] = useState<Record<string, OllamaKnobs>>(() =>
    Object.fromEntries(provider.models.map((m) => [m, knobsFrom(savedOverrides[m])]))
  );

  const setModelKnob = (model: string, key: keyof OllamaKnobs, value: string) =>
    setModels((prev) => ({ ...prev, [model]: { ...prev[model], [key]: value } }));

  const handleSave = () => {
    const next: Record<string, unknown> = { ...cfg };
    delete next.think;
    delete next.num_ctx;
    delete next.num_ctx_max;
    delete next.timeout_seconds;
    delete next.model_overrides;
    Object.assign(next, knobsToConfig(defaults));
    const overrides: Record<string, unknown> = {};
    for (const [m, k] of Object.entries(models)) {
      const o = knobsToConfig(k);
      if (Object.keys(o).length) overrides[m] = o;
    }
    if (Object.keys(overrides).length) next.model_overrides = overrides;
    updateProvider.mutate({ id: provider.id, config: next }, { onSuccess: onClose });
  };

  const knobRow = (label: string, k: OllamaKnobs, set: (key: keyof OllamaKnobs, v: string) => void, isDefault: boolean) => (
    <tr key={label}>
      <td className={styles.configModelName}>{label}</td>
      <td>
        <select value={k.think} onChange={(e) => set("think", e.target.value)}>
          {isDefault ? <option value="">off (default)</option> : <option value="">inherit</option>}
          <option value="on">on</option>
          <option value="off">off</option>
        </select>
      </td>
      <td>
        <input
          type="number"
          placeholder={isDefault ? "32768" : "inherit"}
          value={k.num_ctx_max}
          onChange={(e) => set("num_ctx_max", e.target.value)}
        />
      </td>
      <td>
        <input
          type="number"
          placeholder={isDefault ? "auto" : "inherit"}
          value={k.num_ctx}
          onChange={(e) => set("num_ctx", e.target.value)}
        />
      </td>
      <td>
        <input
          type="number"
          placeholder={isDefault ? "300" : "inherit"}
          value={k.timeout_seconds}
          onChange={(e) => set("timeout_seconds", e.target.value)}
        />
      </td>
      <td>
        <input
          placeholder={isDefault ? "5m" : "inherit"}
          value={k.keep_alive}
          onChange={(e) => set("keep_alive", e.target.value)}
        />
      </td>
    </tr>
  );

  return (
    <div className={styles.configPanel}>
      <table className={styles.configTable}>
        <thead>
          <tr>
            <th>Model</th>
            <th title="Reasoning models (qwen, deepseek-r1) think before answering — better judgment, much slower, and the thinking eats the output budget. Off by default.">
              Thinking
            </th>
            <th title="Cap for the auto-sized context window. Prompts are fitted automatically; this bounds how large a window can be requested. Bigger = more RAM.">
              Context cap
            </th>
            <th title="Pin an exact context window and disable auto-sizing. Usually leave empty.">
              Fixed context
            </th>
            <th title="Per-request timeout in seconds.">Timeout (s)</th>
            <th title="How long the model stays loaded in memory after a request — e.g. 30m, 1h, or -1 to never unload. Avoids the cold-load penalty on the first request after idle. Ollama's server default is 5m.">
              Keep alive
            </th>
          </tr>
        </thead>
        <tbody>
          {knobRow("All models", defaults, (key, v) => setDefaults((prev) => ({ ...prev, [key]: v })), true)}
          {provider.models.map((m) =>
            knobRow(m, models[m], (key, v) => setModelKnob(m, key, v), false)
          )}
        </tbody>
      </table>
      {!provider.models.length && (
        <p className={styles.hint}>No models cached yet — run Test on this provider to load them.</p>
      )}
      <details className={styles.serverTuning}>
        <summary>Server-side tuning (set on the Ollama host, not here)</summary>
        <p>
          These are environment variables on the Ollama server process itself — IntelFeed cannot set
          them over the API. Add them to the Ollama container/service env and restart it:
        </p>
        <ul>
          <li>
            <code>OLLAMA_FLASH_ATTENTION=1</code> — enables flash attention; prerequisite for KV cache
            quantization and faster long-context prompts.
          </li>
          <li>
            <code>OLLAMA_KV_CACHE_TYPE=q8_0</code> — halves context-window memory with negligible
            quality loss, so large context caps fit on the GPU instead of spilling to CPU.
          </li>
          <li>
            <code>OLLAMA_KEEP_ALIVE=1h</code> — server-wide default for the Keep alive column (a value
            set here in the panel overrides it per request).
          </li>
          <li>
            <code>OLLAMA_NUM_PARALLEL=1</code> — concurrent requests per model. Leave at 1 on small
            GPUs: each parallel slot multiplies context-window memory.
          </li>
        </ul>
      </details>
      <div className={styles.formActions}>
        <button className={styles.saveBtn} onClick={handleSave} disabled={updateProvider.isPending}>
          {updateProvider.isPending ? "Saving..." : "Save"}
        </button>
        <button className={styles.cancelBtn} onClick={onClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}

type OpenAICompatKnobs = {
  default_model: string;
  structured_output: string; // "" (json_schema default) | json_schema_strict | json_object | prompt
  system_role: string; // "" (system default) | developer
  max_tokens_param: string; // "" (max_tokens default) | max_completion_tokens
  send_temperature: string; // "" (true default) | false
  min_temperature: string;
  timeout_seconds: string;
  input_per_mtok: string;
  output_per_mtok: string;
  report_cost: string; // "" (false default) | true
  extra_body: string;
};

function openAIKnobsFrom(cfg: Record<string, unknown>): OpenAICompatKnobs {
  const pricing = (cfg.pricing || {}) as Record<string, unknown>;
  return {
    default_model: cfg.default_model != null ? String(cfg.default_model) : "",
    structured_output: cfg.structured_output != null ? String(cfg.structured_output) : "",
    system_role: cfg.system_role != null ? String(cfg.system_role) : "",
    max_tokens_param: cfg.max_tokens_param != null ? String(cfg.max_tokens_param) : "",
    send_temperature: cfg.send_temperature === false ? "false" : "",
    min_temperature: cfg.min_temperature != null ? String(cfg.min_temperature) : "",
    timeout_seconds: cfg.timeout_seconds != null ? String(cfg.timeout_seconds) : "",
    input_per_mtok: pricing.input_per_mtok != null ? String(pricing.input_per_mtok) : "",
    output_per_mtok: pricing.output_per_mtok != null ? String(pricing.output_per_mtok) : "",
    report_cost: cfg.report_cost ? "true" : "",
    extra_body: cfg.extra_body != null ? JSON.stringify(cfg.extra_body, null, 2) : "",
  };
}

function openAIKnobsToConfig(k: OpenAICompatKnobs): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (k.default_model.trim()) out.default_model = k.default_model.trim();
  if (k.structured_output) out.structured_output = k.structured_output;
  if (k.system_role) out.system_role = k.system_role;
  if (k.max_tokens_param) out.max_tokens_param = k.max_tokens_param;
  if (k.send_temperature === "false") out.send_temperature = false;
  if (k.min_temperature.trim()) out.min_temperature = parseFloat(k.min_temperature);
  if (k.timeout_seconds.trim()) out.timeout_seconds = parseInt(k.timeout_seconds, 10);
  if (k.input_per_mtok.trim() || k.output_per_mtok.trim()) {
    out.pricing = {
      input_per_mtok: parseFloat(k.input_per_mtok || "0"),
      output_per_mtok: parseFloat(k.output_per_mtok || "0"),
    };
  }
  if (k.report_cost === "true") out.report_cost = true;
  if (k.extra_body.trim()) out.extra_body = parseExtraBody(k.extra_body);
  return out;
}

/** extra_body is merged into every request payload, so anything but a plain
 *  object (an array, a string, a number) breaks every call on the provider. */
function parseExtraBody(text: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Invalid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Must be a JSON object, e.g. { \"key\": \"value\" }");
  }
  return parsed as Record<string, unknown>;
}

function OpenAICompatConfigEditor({ provider, onClose }: { provider: AIProvider; onClose: () => void }) {
  const updateProvider = useUpdateAIProvider();
  const cfg = (provider.config || {}) as Record<string, unknown>;
  const [knobs, setKnobs] = useState<OpenAICompatKnobs>(() => openAIKnobsFrom(cfg));
  const [toolsEnabled, setToolsEnabled] = useState(cfg.tools_enabled !== false);
  const [extraBodyError, setExtraBodyError] = useState<string | null>(null);
  const set = (key: keyof OpenAICompatKnobs, value: string) =>
    setKnobs((prev) => ({ ...prev, [key]: value }));

  const handleSave = () => {
    let knobConfig: Record<string, unknown>;
    try {
      knobConfig = openAIKnobsToConfig(knobs);
    } catch (e) {
      setExtraBodyError(e instanceof Error ? e.message : "Invalid JSON");
      return;
    }
    setExtraBodyError(null);
    const next: Record<string, unknown> = { ...cfg };
    delete next.default_model;
    delete next.structured_output;
    delete next.system_role;
    delete next.max_tokens_param;
    delete next.send_temperature;
    delete next.min_temperature;
    delete next.timeout_seconds;
    delete next.pricing;
    delete next.report_cost;
    delete next.extra_body;
    delete next.tools_enabled;
    Object.assign(next, knobConfig);
    if (!toolsEnabled) next.tools_enabled = false;
    updateProvider.mutate({ id: provider.id, config: next }, { onSuccess: onClose });
  };

  return (
    <div className={styles.configPanel}>
      <div className={styles.formActions} style={{ flexWrap: "wrap", gap: "0.75rem" }}>
        <label title="The model used when a task assignment doesn't name one, and the one onboarding routes every task at. Must be an id the server lists.">
          Default model
          <input
            type="text"
            placeholder="gpt-4o-mini"
            value={knobs.default_model}
            onChange={(e) => set("default_model", e.target.value)}
          />
        </label>
        <label title="How the structured-output schema is sent. json_schema works on nearly every server; json_schema_strict (OpenAI only) guarantees every field is present but turns optional fields into null; json_object and prompt are fallbacks for servers with weaker support.">
          Structured output
          <select value={knobs.structured_output} onChange={(e) => set("structured_output", e.target.value)}>
            <option value="">json_schema (default)</option>
            <option value="json_schema_strict">json_schema_strict (OpenAI only)</option>
            <option value="json_object">json_object</option>
            <option value="prompt">prompt only</option>
          </select>
        </label>
        <label title="OpenAI's reasoning models (o1, o3, gpt-5) use 'developer' instead of 'system' for the system prompt role.">
          System role
          <select value={knobs.system_role} onChange={(e) => set("system_role", e.target.value)}>
            <option value="">system (default)</option>
            <option value="developer">developer</option>
          </select>
        </label>
        <label title="OpenAI's reasoning models reject max_tokens and require max_completion_tokens instead.">
          Max tokens param
          <select value={knobs.max_tokens_param} onChange={(e) => set("max_tokens_param", e.target.value)}>
            <option value="">max_tokens (default)</option>
            <option value="max_completion_tokens">max_completion_tokens</option>
          </select>
        </label>
        <label title="Reasoning models reject a non-default temperature. Turn this off for them.">
          Send temperature
          <select value={knobs.send_temperature} onChange={(e) => set("send_temperature", e.target.value)}>
            <option value="">yes (default)</option>
            <option value="false">no</option>
          </select>
        </label>
        <label title="Lets the copilot and agentic tasks call IntelFeed tools on this server. Hosted APIs (OpenAI, OpenRouter, Groq) handle this well. Turn it off for a local server that doesn't; a server that refuses tools also gets a text-only answer on its own.">
          Tool calling
          <select value={toolsEnabled ? "" : "false"} onChange={(e) => setToolsEnabled(e.target.value !== "false")}>
            <option value="">on (default)</option>
            <option value="false">off</option>
          </select>
        </label>
        <label title="Per-request timeout in seconds.">
          Timeout (s)
          <input
            type="number"
            placeholder="300"
            value={knobs.timeout_seconds}
            onChange={(e) => set("timeout_seconds", e.target.value)}
          />
        </label>
        <label title="Floor applied to the engine's temperature. Local grammar-constrained decoding at 0.0 can loop on long extraction prompts — try 0.2 if a task hangs or returns truncated JSON. Hosted APIs don't usually need this.">
          Min temperature
          <input
            type="number"
            step="0.1"
            placeholder="0.0"
            value={knobs.min_temperature}
            onChange={(e) => set("min_temperature", e.target.value)}
          />
        </label>
      </div>
      <div className={styles.formActions} style={{ flexWrap: "wrap", gap: "0.75rem" }}>
        <label title="Dollar rate per 1M input tokens — used to compute cost on the Cost Dashboard. Leave both blank for a free/local endpoint.">
          Input $/1M tok
          <input
            type="number"
            step="0.01"
            placeholder="0.00"
            value={knobs.input_per_mtok}
            onChange={(e) => set("input_per_mtok", e.target.value)}
          />
        </label>
        <label title="Dollar rate per 1M output tokens.">
          Output $/1M tok
          <input
            type="number"
            step="0.01"
            placeholder="0.00"
            value={knobs.output_per_mtok}
            onChange={(e) => set("output_per_mtok", e.target.value)}
          />
        </label>
        <label title="Prefer a cost figure the provider itself reports (OpenRouter's usage.cost, or a LiteLLM proxy's response header) over the rates above, when available.">
          Use provider-reported cost
          <select value={knobs.report_cost} onChange={(e) => set("report_cost", e.target.value)}>
            <option value="">no (use rates above)</option>
            <option value="true">yes, when available</option>
          </select>
        </label>
      </div>
      <label title="Merged into the request payload last — the escape hatch for vendor options such as chat_template_kwargs (Qwen3 thinking toggle on vLLM/llama.cpp) or OpenRouter's provider routing block. Must be a JSON object.">
        Extra body (JSON)
        <textarea
          rows={4}
          placeholder={'{\n  "chat_template_kwargs": { "enable_thinking": false }\n}'}
          value={knobs.extra_body}
          onChange={(e) => {
            setExtraBodyError(null);
            set("extra_body", e.target.value);
          }}
        />
      </label>
      {extraBodyError && <p className={styles.hint}>{extraBodyError}</p>}
      <p className={styles.hint}>
        Per-model overrides, extra headers, and a model-id filter can be set via the API's{" "}
        <code>config.model_overrides</code> / <code>config.extra_headers</code> /{" "}
        <code>config.model_filter</code> keys.
      </p>
      <div className={styles.formActions}>
        <button className={styles.saveBtn} onClick={handleSave} disabled={updateProvider.isPending}>
          {updateProvider.isPending ? "Saving..." : "Save"}
        </button>
        <button className={styles.cancelBtn} onClick={onClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}

function ProvidersSection() {
  const { data: allProviders, isLoading } = useAIProviders();
  // GET /ai/providers also returns the caller's personal keys; those live on
  // My AI, and the instance's assignments can't point at them.
  const providers = allProviders?.filter((p) => !p.user_id);
  const createProvider = useCreateAIProvider();
  const updateProvider = useUpdateAIProvider();
  const testProvider = useTestAIProvider();
  const resumeProvider = useResumeAIProvider();
  const deleteProvider = useDeleteAIProvider();
  const undoableDeleteProvider = useUndoableDelete();
  const [showAdd, setShowAdd] = useState(false);
  const [configureId, setConfigureId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; success: boolean; message: string } | null>(null);
  const [newProvider, setNewProvider] = useState({
    name: "",
    provider_type: "claude" as "claude" | "ollama" | "openai_compatible",
    base_url: "",
    api_key: "",
  });
  const isOllama = newProvider.provider_type === "ollama";
  const isOpenAICompatible = newProvider.provider_type === "openai_compatible";
  const requiresBaseUrl = isOllama || isOpenAICompatible;
  const canSave =
    !!newProvider.name && (requiresBaseUrl ? !!newProvider.base_url : !!newProvider.api_key);

  const baseUrlPlaceholder = isOllama
    ? "Base URL (e.g. https://ollama.example.com)"
    : "Base URL (e.g. http://localhost:1234/v1, https://api.openai.com/v1)";

  const handleAdd = async () => {
    await createProvider.mutateAsync({
      name: newProvider.name,
      provider_type: newProvider.provider_type,
      // ClaudeProvider forwards base_url straight to the Anthropic SDK, so a
      // stale value from another type must never reach it.
      base_url: requiresBaseUrl ? newProvider.base_url || undefined : undefined,
      api_key: newProvider.api_key || undefined,
    });
    setShowAdd(false);
    setNewProvider({ name: "", provider_type: "claude", base_url: "", api_key: "" });
  };

  if (isLoading) return <AsyncStateLoading label="Loading providers…" />;

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader}>
        <h3>Providers</h3>
      </div>

      <p className={styles.hint}>
        Add a provider to enable AI features — an API key provider (Claude), a self-hosted
        server (Ollama), or any OpenAI-compatible endpoint (OpenAI, LM Studio, vLLM, llama.cpp,
        OpenRouter, LiteLLM, Groq).
      </p>

      <div className={styles.sectionHeader} style={{ marginTop: "1rem" }}>
        <button className={styles.addBtn} onClick={() => setShowAdd(!showAdd)}>
          + Add
        </button>
      </div>

      {showAdd && (
        <div className={styles.addForm}>
          <select
            value={newProvider.provider_type}
            onChange={(e) => {
              const nextType = e.target.value as "claude" | "ollama" | "openai_compatible";
              setNewProvider({
                ...newProvider,
                provider_type: nextType,
                base_url: nextType === "ollama" || nextType === "openai_compatible" ? newProvider.base_url : "",
              });
            }}
          >
            <option value="claude">Claude (Anthropic API)</option>
            <option value="ollama">Ollama (self-hosted)</option>
            <option value="openai_compatible">
              OpenAI-compatible (OpenAI, LM Studio, vLLM, llama.cpp, OpenRouter, LiteLLM, Groq)
            </option>
          </select>
          <input
            placeholder={requiresBaseUrl ? "Name (e.g. LM Studio)" : "Name (e.g. Claude Production)"}
            value={newProvider.name}
            onChange={(e) =>
              setNewProvider({ ...newProvider, name: e.target.value })
            }
          />
          {requiresBaseUrl && (
            <input
              placeholder={baseUrlPlaceholder}
              value={newProvider.base_url}
              onChange={(e) =>
                setNewProvider({ ...newProvider, base_url: e.target.value })
              }
            />
          )}
          <input
            type="password"
            placeholder={
              isOllama
                ? "Bearer token (optional, for proxied instances)"
                : isOpenAICompatible
                  ? "API key (optional for local servers)"
                  : "Anthropic API Key"
            }
            value={newProvider.api_key}
            onChange={(e) =>
              setNewProvider({ ...newProvider, api_key: e.target.value })
            }
          />
          <div className={styles.formActions}>
            <button
              className={styles.saveBtn}
              onClick={handleAdd}
              disabled={!canSave || createProvider.isPending}
            >
              Save
            </button>
            <button className={styles.cancelBtn} onClick={() => setShowAdd(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className={styles.providerList}>
        {providers?.map((p) => {
          const isPaused = !!p.paused_until && new Date(p.paused_until) > new Date();
          return (
          <div key={p.id}>
          <div
            className={`${styles.providerCard} ${!p.is_active ? styles.providerCardDisabled : ""} ${isPaused ? styles.providerCardPaused : ""}`}
          >
            <div className={styles.providerInfo}>
              <label className={styles.toggleSwitch} title={p.is_active ? "Enabled" : "Disabled"}>
                <input
                  type="checkbox"
                  checked={p.is_active}
                  onChange={() => updateProvider.mutate({ id: p.id, is_active: !p.is_active })}
                />
                <span className={styles.toggleSlider} />
              </label>
              <span className={styles.providerName}>{p.name}</span>
              <Chip className={styles.providerType}>{p.provider_type}</Chip>
              {p.base_url && (
                <span className={styles.providerUrl}>{p.base_url}</span>
              )}
              {p.models.length > 0 && (
                <span className={styles.modelCount}>
                  {p.models.length} models
                </span>
              )}
              {isPaused && (
                <Chip
                  pill
                  tone="toned"
                  tint="var(--warning)"
                  truncate
                  className={styles.pausedBadge}
                  title={p.paused_reason || undefined}
                >
                  Paused until {formatDate(p.paused_until!)}
                </Chip>
              )}
              {isPaused && p.paused_reason && (
                <span className={styles.pausedReason} title={p.paused_reason}>
                  {p.paused_reason}
                </span>
              )}
              {testResult?.id === p.id && (
                <Chip
                  tone="toned"
                  tint={testResult.success ? "var(--success)" : "var(--danger)"}
                  truncate
                  title={testResult.message}
                >
                  {testResult.message}
                </Chip>
              )}
            </div>
            <div className={styles.providerActions}>
              {(p.provider_type === "ollama" ||
                p.provider_type === "claude_code" ||
                p.provider_type === "openai_compatible") && (
                <button
                  className={styles.testBtn}
                  onClick={() => setConfigureId(configureId === p.id ? null : p.id)}
                  title={
                    p.provider_type === "ollama"
                      ? "Per-model settings: thinking, context window, timeout"
                      : p.provider_type === "openai_compatible"
                        ? "Structured output mode, token/temperature params, pricing"
                        : "Copilot authentication and CLI settings"
                  }
                >
                  Configure
                </button>
              )}
              {isPaused && (
                <button
                  className={styles.resumeBtn}
                  onClick={() => resumeProvider.mutate(p.id)}
                  disabled={resumeProvider.isPending}
                  title="Clear the auto-pause and let the engine route tasks here again"
                >
                  Resume now
                </button>
              )}
              <button
                className={styles.testBtn}
                onClick={() => {
                  setTestResult(null);
                  testProvider.mutate(p.id, {
                    onSuccess: (result) => {
                      setTestResult({ id: p.id, success: result.success, message: result.message });
                      setTimeout(() => setTestResult((prev) => prev?.id === p.id ? null : prev), 5000);
                    },
                    onError: (err) => {
                      setTestResult({ id: p.id, success: false, message: err instanceof Error ? err.message : "Connection failed" });
                      setTimeout(() => setTestResult((prev) => prev?.id === p.id ? null : prev), 5000);
                    },
                  });
                }}
                disabled={testProvider.isPending}
              >
                {testProvider.isPending ? "Testing..." : "Test"}
              </button>
              <button
                className={styles.deleteBtn}
                onClick={() => undoableDeleteProvider({
                  label: `AI provider "${p.name}"`,
                  key: `ai-provider-${p.id}`,
                  onDelete: () => deleteProvider.mutate(p.id),
                })}
              >
                Delete
              </button>
            </div>
          </div>
          {configureId === p.id && p.provider_type === "ollama" && (
            <OllamaConfigEditor provider={p} onClose={() => setConfigureId(null)} />
          )}
          {configureId === p.id && p.provider_type === "claude_code" && (
            <ClaudeCodeConfigEditor provider={p} onClose={() => setConfigureId(null)} />
          )}
          {configureId === p.id && p.provider_type === "openai_compatible" && (
            <OpenAICompatConfigEditor provider={p} onClose={() => setConfigureId(null)} />
          )}
          </div>
          );
        })}
        {!providers?.length && (
          <div className={styles.empty}>
            No providers configured. Add one to get started.
          </div>
        )}
      </div>
    </div>
  );
}

function BreakdownTable({ title, rows }: { title: string; rows: AICostBreakdownRow[] }) {
  return (
    <div>
      <h4 style={{ margin: "0 0 8px" }}>{title}</h4>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ textAlign: "left", color: "var(--text-muted)" }}>
              <th style={{ padding: "4px 8px" }}>Name</th>
              <th style={{ padding: "4px 8px", textAlign: "right" }}>Reqs</th>
              <th style={{ padding: "4px 8px", textAlign: "right" }}>Cost</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.label} style={{ borderTop: "1px solid var(--border)" }}>
                <td style={{ padding: "4px 8px" }}>{r.label}</td>
                <td style={{ padding: "4px 8px", textAlign: "right" }}>{r.requests}</td>
                <td style={{ padding: "4px 8px", textAlign: "right" }}>
                  ${Number(r.cost).toFixed(2)}
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={3} style={{ padding: 8, color: "var(--text-muted)" }}>
                  No spend yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const CALLER_LABELS: Record<AICallerCostRow["caller_kind"], string> = {
  system: "Pipeline",
  automation: "Automation",
  share: "Share links",
  user: "",
  unattributed: "Unattributed (before Oct 2026)",
};

/**
 * Spend by who asked, with each person's day against the site allowance. The
 * headline splits instance spend (the admin's) from user-key spend (theirs);
 * one total would mix money paid by different people.
 */
function ByUserTable({ breakdown }: { breakdown: AICostBreakdown }) {
  const [filter, setFilter] = useState<"all" | "instance" | "user">("all");
  const allowance = breakdown.site_allowance_per_user;
  // Filter on requests, not dollars: on an Ollama instance almost every call is $0.
  const rows = breakdown.by_caller.filter((r) => {
    if (filter === "instance") return r.caller_kind !== "user" || r.requests - r.own_key_requests > 0;
    if (filter === "user") return r.own_key_requests > 0;
    return true;
  });
  const nearLimit = allowance > 0 ? breakdown.by_caller.filter((r) => r.caller_kind === "user" && r.requests_today >= allowance * 0.9) : [];
  const name = (r: AICallerCostRow) => (r.caller_kind === "user" ? r.username ?? "(deleted user)" : CALLER_LABELS[r.caller_kind]);
  const note = (r: AICallerCostRow) => {
    if (r.caller_kind === "system") return "pipeline work";
    if (r.caller_kind === "automation") return "counted as pipeline";
    if (r.caller_kind === "share") return "always instance";
    if (r.caller_kind === "unattributed") return "history can't be rebuilt";
    return null;
  };

  return (
    <div style={{ marginTop: 20 }}>
      <div className={styles.sectionHeader}>
        <h4 style={{ margin: 0 }}>By user</h4>
        <Segmented<"all" | "instance" | "user">
          label="By user filter"
          size="sm"
          value={filter}
          onChange={setFilter}
          options={[
            { value: "all", label: "All" },
            { value: "instance", label: "Instance keys" },
            { value: "user", label: "User keys" },
          ]}
        />
      </div>
      <div style={{ overflowX: "auto" }}>
        <table className={styles.byUserTable}>
          <thead>
            <tr>
              <th>Who</th>
              <th className={styles.num}>Reqs</th>
              <th className={styles.num}>Instance $</th>
              <th className={styles.num}>Own key $</th>
              <th>Today vs allowance</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const pct = allowance > 0 ? Math.min(100, (r.requests_today / allowance) * 100) : 0;
              return (
                <tr key={`${r.caller_kind}-${r.user_id ?? ""}`}>
                  <td>
                    {name(r)}{" "}
                    {r.caller_kind !== "user" && <Chip size="sm" tone="quiet">{r.caller_kind}</Chip>}
                  </td>
                  <td className={styles.num}>{r.requests.toLocaleString()}</td>
                  <td className={styles.num}>{formatUsd(r.instance_cost)}</td>
                  <td className={styles.num}>{Number(r.own_key_cost) > 0 ? formatUsd(r.own_key_cost) : "—"}</td>
                  <td>
                    {r.caller_kind === "user" ? (
                      allowance > 0 ? (
                        <span className={styles.allowance} title={`${r.requests_today} of ${allowance} today`}>
                          <span className={styles.meter}>
                            <i style={{ width: `${pct}%`, background: pct >= 90 ? "var(--warning)" : "var(--success)" }} />
                          </span>
                          <span className={styles.meterLabel}>
                            {r.requests_today}/{allowance}
                          </span>
                        </span>
                      ) : (
                        <span className={styles.muted}>{r.requests_today} today · no allowance</span>
                      )
                    ) : (
                      <span className={styles.muted}>{note(r)}</span>
                    )}
                  </td>
                </tr>
              );
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={5} className={styles.muted} style={{ padding: 8 }}>
                  No spend yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {nearLimit.map((r) => (
        <div key={r.user_id ?? r.caller_kind} className={styles.allowanceNote}>
          <b>{name(r)}</b> has used {r.requests_today} of {allowance} instance requests today. Prompts they run
          themselves will stop at the limit. Pipeline work isn't affected.
        </div>
      ))}
    </div>
  );
}

function CostSection() {
  const { data: cost, isLoading } = useAICostSummary();
  const { data: breakdown } = useAICostBreakdown();

  if (isLoading) return <AsyncStateLoading label="Loading cost data…" compact />;

  const alerts = (breakdown?.budgets ?? []).filter(
    (b) => b.percent_of_budget != null && b.percent_of_budget >= 0.8,
  );
  const byCaller = breakdown?.by_caller ?? [];
  const interactive = byCaller.filter((r) => r.caller_kind === "user").reduce((s, r) => s + Number(r.instance_cost), 0);
  const pipeline = byCaller.filter((r) => r.caller_kind !== "user").reduce((s, r) => s + Number(r.instance_cost), 0);
  const people = byCaller.filter((r) => r.caller_kind === "user" && r.own_key_requests > 0).length;
  const totalReqs = breakdown?.total_requests_30d ?? cost?.total_requests_30d ?? 0;
  const pipelineReqs = byCaller.filter((r) => r.caller_kind !== "user").reduce((s, r) => s + r.requests, 0);

  return (
    <div className={styles.section}>
      <h3>Cost Dashboard (Last 30 Days)</h3>
      {cost && (
        <div className={styles.costGrid}>
          <div className={styles.costCard}>
            <span className={styles.costLabel}>Instance keys</span>
            <span className={styles.costValue}>
              {breakdown ? formatUsd(breakdown.instance_cost_30d) : `$${cost.total_cost_30d.toFixed(2)}`}
            </span>
            {breakdown && (
              <span className={styles.costSub}>
                pipeline {formatUsd(pipeline)} · interactive {formatUsd(interactive)}
              </span>
            )}
          </div>
          <div className={styles.costCard}>
            <span className={styles.costLabel}>User keys</span>
            <span className={styles.costValue}>{breakdown ? formatUsd(breakdown.user_key_cost_30d) : "—"}</span>
            <span className={styles.costSub}>
              {people} {people === 1 ? "person" : "people"} · not billed to you
            </span>
          </div>
          <div className={styles.costCard}>
            <span className={styles.costLabel}>Total Requests</span>
            <span className={styles.costValue}>{compactCount(totalReqs)}</span>
            <span className={styles.costSub}>
              {totalReqs > 0 ? `${Math.round((pipelineReqs / totalReqs) * 100)}% pipeline` : "no requests yet"} ·{" "}
              {compactCount(cost.total_tokens_30d.input)} tokens in / {compactCount(cost.total_tokens_30d.output)} out
            </span>
          </div>
          <div className={styles.costCard}>
            <span className={styles.costLabel}>Unpriced</span>
            <span className={styles.costValue}>{breakdown ? compactCount(breakdown.unpriced_requests_30d) : "—"}</span>
            <span className={styles.costSub}>requests at $0 (Ollama, unpriced models)</span>
          </div>
        </div>
      )}

      {alerts.length > 0 && (
        <div style={{ marginTop: 20 }}>
          <h4 style={{ margin: "0 0 8px" }}>Budget alerts</h4>
          {alerts.map((b) => {
            const pct = Math.round((b.percent_of_budget ?? 0) * 100);
            const over = (b.percent_of_budget ?? 0) >= 1;
            return (
              <div
                key={b.task_id}
                style={{
                  padding: "8px 12px",
                  marginBottom: 6,
                  borderRadius: 6,
                  fontSize: 13,
                  border: `1px solid ${over ? "var(--danger)" : "var(--warning)"}`,
                  background: "var(--bg-secondary)",
                }}
              >
                <strong>{b.display_name}</strong> — ${Number(b.spend_30d).toFixed(2)}
                {b.max_budget_usd != null && (
                  <> of ${Number(b.max_budget_usd).toFixed(2)} ({pct}%)</>
                )}
                {over && " — over budget"}
              </div>
            );
          })}
        </div>
      )}

      {breakdown && <ByUserTable breakdown={breakdown} />}

      {breakdown && (
        <div
          style={{
            marginTop: 20,
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 20,
          }}
        >
          <BreakdownTable title="By prompt" rows={breakdown.by_task} />
          <BreakdownTable title="By model" rows={breakdown.by_model} />
        </div>
      )}
    </div>
  );
}
