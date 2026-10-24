import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useAuthStore } from "@/stores/authStore";
import type { AIProvider, UserAIRoute, UserAIPromptRow } from "@/api/types";
import {
  useAIProviders,
  useCreateAIProvider,
  useDeleteAIProvider,
  useDeleteMyRoute,
  useMyAI,
  useResumeAIProvider,
  useTestAIProvider,
  useUpdateAIProvider,
  useUpdateMyAIPreferences,
  useUpsertMyRoute,
} from "@/hooks/useAI";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { apiErrorInfo } from "@/api/errors";
import { formatCapInput, formatUsd } from "@/utils/format";
import { formatDate, formatRelative } from "@/utils/formatDate";
import { Chip } from "@/components/primitives";
import { AsyncStateError, AsyncStateLoading } from "@/components/AsyncState";
import page from "@/pages/SettingsPage.module.css";
import styles from "./MyAISection.module.css";

type PersonalType = "openai_compatible" | "claude" | "ollama" | "claude_code";

const TYPE_LABELS: Record<PersonalType, string> = {
  openai_compatible: "OpenAI-compatible (OpenAI, OpenRouter, Groq, LM Studio…)",
  claude: "Claude (Anthropic API)",
  ollama: "Ollama",
  claude_code: "Claude Code (CLI)",
};

const DEFAULT_MODELS: Partial<Record<string, string>> = {
  claude: "claude-sonnet-4-6",
};

/** The first model a key can be routed to without the person typing one. */
function firstModel(provider: AIProvider): string {
  return provider.models[0] ?? DEFAULT_MODELS[provider.provider_type] ?? "";
}

/** The last test's error, short enough for a chip; the full text sits in the title. */
function shortError(message: string, max = 40): string {
  const one = message.replace(/\s+/g, " ").trim();
  return one.length > max ? `${one.slice(0, max - 1)}…` : one;
}

function monthResetLabel(iso: string): string {
  const d = new Date(iso);
  // The cap resets at midnight UTC; a local-time render showed "Oct 31" the evening before.
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
}

/**
 * Settings → My AI: one person's keys, which prompts use them, what they've
 * spent, and what happens when a key can't answer. Every number here is the
 * caller's own; the admin's instance-wide view is the Cost Dashboard.
 */
export function MyAISection() {
  const me = useAuthStore((s) => s.user);
  const { data: overview, isLoading, isError, error, refetch } = useMyAI();
  const { data: providers, isLoading: providersLoading } = useAIProviders();
  const myKeys = useMemo(
    () => (providers ?? []).filter((p) => !!p.user_id && p.user_id === me?.id),
    [providers, me?.id],
  );

  if (isError) {
    return (
      <div className={page.sectionContent}>
        <h2 className={page.sectionTitle}>My AI</h2>
        <AsyncStateError title="Couldn't load your AI settings" description={apiErrorInfo(error).message} onRetry={() => void refetch()} />
      </div>
    );
  }
  // The key list is empty until the providers query answers; without this
  // gate "No keys yet" flashes before the person's keys arrive.
  if (isLoading || !overview || providersLoading) return <AsyncStateLoading label="Loading your AI settings…" />;

  const { policy, usage } = overview;
  const enabled = policy.allow_user_ai_providers;
  const defaultRoute = overview.default_route;
  const defaultKey = defaultRoute ? myKeys.find((k) => k.id === defaultRoute.provider_id) ?? null : null;

  return (
    <div className={page.sectionContent}>
      <h2 className={page.sectionTitle}>My AI</h2>
      <p className={page.sectionDesc}>
        Use your own AI key for the prompts you run.
      </p>

      {!enabled && (
        <div className={`${styles.note} ${styles.noteInfo}`}>
          <b>Personal keys are off on this instance.</b> Your admin hasn't enabled them, so every prompt you run runs
          on the instance's providers.
        </div>
      )}

      <UsageCard overview={overview} myKeys={myKeys} />

      <KeysCard overview={overview} myKeys={myKeys} defaultRoute={defaultKey ? defaultRoute : null} />

      {enabled && (
        <RoutesCard overview={overview} myKeys={myKeys} defaultKey={defaultKey} defaultRouteModel={defaultRoute?.model_name ?? null} />
      )}

      {enabled && <FallbackCard overview={overview} />}

      {usage.site_allowance_per_user > 0 && (
        <div className={styles.note}>
          On the instance's providers you may make {usage.site_allowance_per_user} requests a day. Your own key is not
          counted against that.
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- usage

function UsageCard({ overview, myKeys }: { overview: NonNullable<ReturnType<typeof useMyAI>["data"]>; myKeys: AIProvider[] }) {
  const { usage } = overview;
  const cap = Number(usage.monthly_cap_usd);
  const spent = Number(usage.month_cost);
  const palette = ["var(--accent)", "var(--warning)", "var(--success)", "var(--text-muted)"];
  const segments = usage.by_key.map((k, i) => ({
    ...k,
    color: palette[i % palette.length],
    // Against the cap when there is one; otherwise each key's share of the
    // month's spend, so the bar still says something with no cap set.
    width: cap > 0 ? Math.min(100, (Number(k.month_cost) / cap) * 100) : spent > 0 ? (Number(k.month_cost) / spent) * 100 : 0,
  }));

  return (
    <div className={page.card}>
      <div className={styles.cardHead}>
        <h3 className={styles.cardTitle}>This month</h3>
        {usage.month_resets_at && <span className={styles.muted}>Resets {monthResetLabel(usage.month_resets_at)}</span>}
      </div>
      <div className={styles.tiles}>
        <div className={styles.tile}>
          <span className={styles.tileLabel}>My key spend</span>
          <span className={styles.tileValue}>{formatUsd(spent)}</span>
          <span className={styles.tileSub}>{cap > 0 ? `of ${formatUsd(cap)} cap` : "no cap"}</span>
        </div>
        <div className={styles.tile}>
          <span className={styles.tileLabel}>Requests today</span>
          <span className={styles.tileValue}>{usage.requests_today}</span>
          <span className={styles.tileSub}>{usage.daily_request_cap > 0 ? `of ${usage.daily_request_cap}` : "no cap"}</span>
        </div>
        <div className={styles.tile}>
          <span className={styles.tileLabel}>On site providers</span>
          <span className={styles.tileValue}>{usage.site_requests_today}</span>
          <span className={styles.tileSub}>
            {usage.site_allowance_per_user > 0 ? `of ${usage.site_allowance_per_user} today` : "requests today"} · fallback + locked
          </span>
        </div>
      </div>
      {myKeys.length > 0 && (
        <div className={styles.meterWrap}>
          <div className={styles.meter} role="img" aria-label={cap > 0 ? "Spend by key against the monthly cap" : "Spend by key"}>
            {segments.map((s) => (
              <i key={s.provider_id} style={{ width: `${s.width}%`, background: s.color }} />
            ))}
          </div>
          <div className={styles.legend}>
            {segments.map((s) => (
              <span key={s.provider_id}>
                <i style={{ background: s.color }} />
                {s.provider_name}{" "}
                {s.provider_type === "ollama" || (Number(s.month_cost) === 0 && s.month_requests > 0)
                  ? `${s.month_requests} requests`
                  : formatUsd(s.month_cost)}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- keys

function KeysCard({
  overview,
  myKeys,
  defaultRoute,
}: {
  overview: NonNullable<ReturnType<typeof useMyAI>["data"]>;
  myKeys: AIProvider[];
  /** The default-key route, when it points at one of my keys. */
  defaultRoute: UserAIRoute | null;
}) {
  const { policy } = overview;
  const defaultKeyId = defaultRoute?.provider_id ?? null;
  const updateProvider = useUpdateAIProvider();
  const testProvider = useTestAIProvider();
  const deleteProvider = useDeleteAIProvider();
  const resumeProvider = useResumeAIProvider();
  const undoableDelete = useUndoableDelete();
  const upsertRoute = useUpsertMyRoute();
  const deleteRoute = useDeleteMyRoute();
  const [showAdd, setShowAdd] = useState(false);
  // The add form closes on success, so its "Connected · saved" line lives here, above the list.
  const [added, setAdded] = useState<string | null>(null);
  const [editId, setEditId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; success: boolean; message: string } | null>(null);

  const makeDefault = (key: AIProvider) => {
    const model = firstModel(key);
    if (!model) {
      setTestResult({ id: key.id, success: false, message: "Test the key first so its models are known." });
      return;
    }
    upsertRoute.mutate({ task_id: null, provider_id: key.id, model_name: model });
  };

  return (
    <div className={page.card}>
      <div className={styles.cardHead}>
        <h3 className={styles.cardTitle}>My keys</h3>
        {policy.allow_user_ai_providers && (
          <button
            className={page.btnPrimary}
            onClick={() => {
              setAdded(null);
              setShowAdd((v) => !v);
            }}
          >
            + Add key
          </button>
        )}
      </div>

      {showAdd && (
        <AddKeyForm
          overview={overview}
          onClose={() => setShowAdd(false)}
          onAdded={(key, asDefault, keepOpen) => {
            if (!keepOpen) {
              setShowAdd(false);
              setAdded(`${key.name}: connected · ${key.models.length} models · saved`);
            }
            if (asDefault) makeDefault(key);
          }}
        />
      )}
      {added && !showAdd && (
        <div className={styles.ok} role="status">
          {added}
        </div>
      )}

      <div className={styles.keyList}>
        {myKeys.map((k) => {
          const isPaused = !!k.paused_until && new Date(k.paused_until) > new Date();
          const typeAllowed = policy.provider_types.includes(k.provider_type);
          const status = testResult?.id === k.id ? testResult : null;
          // This session's test result wins; otherwise what the server remembers.
          const lastFailed = !status && !!k.last_test_error;
          const warn = (status && !status.success) || lastFailed;
          return (
            <div key={k.id}>
              <div className={`${styles.key} ${!k.is_active ? styles.keyOff : ""} ${warn ? styles.keyWarn : ""}`}>
                <div className={styles.keyLeft}>
                  <label className={page.toggle} title={k.is_active ? "Enabled" : "Disabled"}>
                    <input
                      type="checkbox"
                      checked={k.is_active}
                      aria-label={`${k.name} ${k.is_active ? "on" : "off"}`}
                      onChange={() => updateProvider.mutate({ id: k.id, is_active: !k.is_active })}
                    />
                    <span className={page.toggleSlider} />
                  </label>
                  <span className={styles.keyName}>{k.name}</span>
                  <Chip size="sm">{k.provider_type}</Chip>
                  {k.base_url && <span className={styles.keyUrl}>{k.base_url.replace(/^https?:\/\//, "")}</span>}
                  {defaultRoute && defaultKeyId === k.id && (
                    <>
                      <Chip size="sm" tone="toned" tint="var(--success)">
                        Default
                      </Chip>
                      <DefaultModelPicker
                        provider={k}
                        model={defaultRoute.model_name}
                        disabled={upsertRoute.isPending}
                        onChange={(model) => upsertRoute.mutate({ task_id: null, provider_id: k.id, model_name: model })}
                      />
                    </>
                  )}
                  {!typeAllowed && (
                    <Chip size="sm" tone="toned" tint="var(--warning)" title="Your admin no longer allows this provider type">
                      type not allowed
                    </Chip>
                  )}
                  {isPaused && (
                    <>
                      <Chip size="sm" tone="toned" tint="var(--warning)" title={k.paused_reason ?? undefined}>
                        Paused
                      </Chip>
                      <button
                        className={page.btnSmall}
                        onClick={() => resumeProvider.mutate(k.id)}
                        disabled={resumeProvider.isPending}
                        title="Clear the pause and let this key answer again"
                      >
                        Resume
                      </button>
                    </>
                  )}
                  {status ? (
                    <Chip size="sm" tone="toned" tint={status.success ? "var(--success)" : "var(--warning)"} title={status.message} truncate>
                      {status.success ? `Connected · ${k.models.length || "?"} models` : status.message}
                    </Chip>
                  ) : k.last_test_error ? (
                    <Chip size="sm" tone="toned" tint="var(--warning)" title={k.last_test_error} truncate>
                      Last test failed · {shortError(k.last_test_error)}
                    </Chip>
                  ) : k.last_tested_at ? (
                    <Chip size="sm" tone="toned" tint="var(--success)" title={`Last tested ${formatDate(k.last_tested_at)}`}>
                      Tested {formatRelative(k.last_tested_at)}
                    </Chip>
                  ) : null}
                </div>
                <div className={styles.keyActions}>
                  {defaultKeyId !== k.id && policy.allow_user_ai_providers && (
                    <button className={page.btnSmall} onClick={() => makeDefault(k)} disabled={upsertRoute.isPending}>
                      Set as default
                    </button>
                  )}
                  {defaultRoute && defaultKeyId === k.id && (
                    <button
                      className={page.btnSmall}
                      onClick={() => deleteRoute.mutate(defaultRoute.id)}
                      disabled={deleteRoute.isPending}
                      title="Prompts without a route of their own go back to the instance's providers"
                    >
                      Clear default
                    </button>
                  )}
                  <button
                    className={page.btnSmall}
                    disabled={testProvider.isPending}
                    onClick={() => {
                      setTestResult(null);
                      testProvider.mutate(k.id, {
                        onSuccess: (r) => setTestResult({ id: k.id, success: r.success, message: r.message }),
                        onError: (err) => setTestResult({ id: k.id, success: false, message: apiErrorInfo(err).message }),
                      });
                    }}
                  >
                    {testProvider.isPending && testProvider.variables === k.id ? "Testing…" : "Test"}
                  </button>
                  <button className={page.btnSmall} onClick={() => setEditId(editId === k.id ? null : k.id)}>
                    Edit
                  </button>
                  <button
                    className={page.btnDangerSmall}
                    onClick={() =>
                      undoableDelete({
                        label: `key "${k.name}"`,
                        key: `ai-provider-${k.id}`,
                        onDelete: () => deleteProvider.mutate(k.id),
                      })
                    }
                  >
                    Delete
                  </button>
                </div>
              </div>
              {editId === k.id && <EditKeyForm provider={k} onClose={() => setEditId(null)} />}
            </div>
          );
        })}
        {myKeys.length === 0 && (
          <div className={styles.empty}>
            {policy.allow_user_ai_providers
              ? "No keys yet. Add one and the prompts you run can use it."
              : "No keys."}
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * The model the default key answers with. A select when the key's models are
 * known, else a text field committed on Enter or blur; "Make default" picks
 * the first model, and this is where the person changes it.
 */
function DefaultModelPicker({
  provider,
  model,
  disabled,
  onChange,
}: {
  provider: AIProvider;
  model: string | null;
  disabled?: boolean;
  onChange: (model: string) => void;
}) {
  const [text, setText] = useState(model ?? "");
  useEffect(() => setText(model ?? ""), [model]);
  const commit = () => {
    const next = text.trim();
    if (next && next !== (model ?? "")) onChange(next);
  };
  if (provider.models.length > 0) {
    return (
      <select
        className={`${page.select} ${styles.selectSm} ${styles.mono}`}
        value={model ?? ""}
        disabled={disabled}
        aria-label="Default model"
        title="The model the default key answers with"
        onChange={(e) => onChange(e.target.value)}
      >
        {!model && <option value="">Pick a model…</option>}
        {model && !provider.models.includes(model) && <option value={model}>{model}</option>}
        {provider.models.map((m) => (
          <option key={m} value={m}>
            {m}
          </option>
        ))}
      </select>
    );
  }
  return (
    <input
      className={`${page.input} ${styles.mono} ${styles.modelInput}`}
      value={text}
      disabled={disabled}
      aria-label="Default model"
      placeholder="Model name, then Enter"
      onChange={(e) => setText(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => {
        if (e.key === "Enter") (e.target as HTMLInputElement).blur();
      }}
    />
  );
}

function AddKeyForm({
  overview,
  onClose,
  onAdded,
}: {
  overview: NonNullable<ReturnType<typeof useMyAI>["data"]>;
  onClose: () => void;
  /** keepOpen: the key was saved but something after it failed, and the form shows why. */
  onAdded: (key: AIProvider, asDefault: boolean, keepOpen: boolean) => void;
}) {
  const { policy } = overview;
  const createProvider = useCreateAIProvider();
  const [type, setType] = useState<PersonalType>(
    (policy.provider_types[0] as PersonalType | undefined) ?? "openai_compatible",
  );
  const [name, setName] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [asDefault, setAsDefault] = useState(true);
  const [cap, setCap] = useState(formatCapInput(overview.monthly_cap_usd));
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const updatePrefs = useUpdateMyAIPreferences();
  const isCli = type === "claude_code";
  const needsUrl = type === "ollama" || type === "openai_compatible";
  const typeAllowed = policy.provider_types.includes(type);
  const canSave = !isCli && typeAllowed && !!name.trim() && (needsUrl ? !!baseUrl.trim() : !!apiKey.trim());

  const submit = async () => {
    setError(null);
    try {
      const key = await createProvider.mutateAsync({
        name: name.trim(),
        provider_type: type,
        base_url: needsUrl ? baseUrl.trim() : undefined,
        api_key: apiKey || undefined,
        personal: true,
        test: true,
      });
      setSaved(`Connected · ${key.models.length} models · saved`);
      // The cap is the person's, not the key's; the form offers it here
      // because this is where someone first thinks about it. A refused cap
      // keeps the form open so the refusal is seen: the key itself is saved.
      const capInput = cap.trim();
      if (capInput && capInput !== formatCapInput(overview.monthly_cap_usd)) {
        try {
          await updatePrefs.mutateAsync({ monthly_cap_usd: capInput });
        } catch (err) {
          setError(`Key saved, but the cap was not: ${apiErrorInfo(err).message}`);
          onAdded(key, asDefault, true);
          return;
        }
      }
      onAdded(key, asDefault, false);
    } catch (err) {
      setError(apiErrorInfo(err).message);
    }
  };

  return (
    <div className={styles.form}>
      <h4 className={styles.formTitle}>Add a key</h4>
      <label className={styles.field}>
        <span>Type</span>
        <select className={page.select} value={type} onChange={(e) => setType(e.target.value as PersonalType)} aria-label="Provider type">
          {(Object.keys(TYPE_LABELS) as PersonalType[]).map((t) => (
            <option key={t} value={t}>
              {TYPE_LABELS[t]}
            </option>
          ))}
        </select>
      </label>
      {isCli && (
        <div className={`${styles.note} ${styles.noteBad}`}>
          <b>Claude Code can't be a personal key.</b> It runs one CLI sign-in shared by the whole instance, so it
          can't be yours alone. Use a Claude API key instead.
        </div>
      )}
      {!isCli && !typeAllowed && (
        <div className={`${styles.note} ${styles.noteBad}`}>
          This instance allows personal keys of type {policy.provider_types.join(" and ") || "none"} only.
        </div>
      )}
      {!isCli && (
        <>
          <label className={styles.field}>
            <span>Name</span>
            <input className={page.input} value={name} onChange={(e) => setName(e.target.value)} placeholder="OpenRouter personal" aria-label="Name" />
          </label>
          {needsUrl && (
            <label className={styles.field}>
              <span>Base URL</span>
              <input
                className={`${page.input} ${styles.mono}`}
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder={type === "ollama" ? "https://ollama.example.com" : "https://openrouter.ai/api/v1"}
                aria-label="Base URL"
              />
              {!policy.allow_private_endpoints && (
                <span className={styles.fieldHint}>A public address. This instance doesn't allow private endpoints for personal keys.</span>
              )}
            </label>
          )}
          <label className={styles.field}>
            <span>{type === "ollama" ? "Bearer token (optional)" : type === "openai_compatible" ? "API key" : "API key"}</span>
            <input
              className={`${page.input} ${styles.mono}`}
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              aria-label="API key"
              autoComplete="off"
            />
          </label>
          <label className={styles.field}>
            <span>Monthly cap on your keys' spend (optional)</span>
            <input
              className={`${page.input} ${styles.mono} ${styles.capField}`}
              value={cap}
              onChange={(e) => setCap(e.target.value)}
              placeholder="none"
              aria-label="Monthly cap"
            />
          </label>
          <label className={styles.check}>
            <input type="checkbox" checked={asDefault} onChange={(e) => setAsDefault(e.target.checked)} /> Make this my
            default key for all allowed prompts
          </label>
        </>
      )}
      {error && <div className={styles.formError}>{error}</div>}
      <div className={styles.formActions}>
        <button className={page.btnPrimary} onClick={submit} disabled={!canSave || createProvider.isPending}>
          {createProvider.isPending ? "Testing…" : "Test and save"}
        </button>
        <button className={page.btnSecondary} onClick={onClose}>
          Cancel
        </button>
        {saved && <span className={styles.ok}>{saved}</span>}
      </div>
    </div>
  );
}

function EditKeyForm({ provider, onClose }: { provider: AIProvider; onClose: () => void }) {
  const updateProvider = useUpdateAIProvider();
  const [name, setName] = useState(provider.name);
  const [baseUrl, setBaseUrl] = useState(provider.base_url ?? "");
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const needsUrl = provider.provider_type === "ollama" || provider.provider_type === "openai_compatible";

  const submit = async () => {
    setError(null);
    try {
      await updateProvider.mutateAsync({
        id: provider.id,
        name: name.trim() || undefined,
        ...(needsUrl ? { base_url: baseUrl.trim() } : {}),
        ...(apiKey ? { api_key: apiKey } : {}),
      });
      onClose();
    } catch (err) {
      setError(apiErrorInfo(err).message);
    }
  };

  return (
    <div className={styles.form}>
      <label className={styles.field}>
        <span>Name</span>
        <input className={page.input} value={name} onChange={(e) => setName(e.target.value)} aria-label="Name" />
      </label>
      {needsUrl && (
        <label className={styles.field}>
          <span>Base URL</span>
          <input className={`${page.input} ${styles.mono}`} value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} aria-label="Base URL" />
        </label>
      )}
      <label className={styles.field}>
        <span>New API key (leave blank to keep)</span>
        <input className={`${page.input} ${styles.mono}`} type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} aria-label="New API key" autoComplete="off" />
      </label>
      {error && <div className={styles.formError}>{error}</div>}
      <div className={styles.formActions}>
        <button className={page.btnPrimary} onClick={submit} disabled={updateProvider.isPending}>
          Save
        </button>
        <button className={page.btnSecondary} onClick={onClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- routes

function RoutesCard({
  overview,
  myKeys,
  defaultKey,
  defaultRouteModel,
}: {
  overview: NonNullable<ReturnType<typeof useMyAI>["data"]>;
  myKeys: AIProvider[];
  defaultKey: AIProvider | null;
  defaultRouteModel: string | null;
}) {
  const upsertRoute = useUpsertMyRoute();
  const deleteRoute = useDeleteMyRoute();
  // A key picked for a prompt whose model is not yet known: the row asks for one.
  const [pending, setPending] = useState<Record<string, { providerId: string; model: string }>>({});

  const commit = (prompt: UserAIPromptRow, providerId: string, model: string) => {
    if (!model.trim()) return;
    upsertRoute.mutate({ task_id: prompt.task_id, provider_id: providerId, model_name: model.trim() });
    setPending((p) => {
      const next = { ...p };
      delete next[prompt.task_id];
      return next;
    });
  };

  const onPick = (prompt: UserAIPromptRow, value: string) => {
    if (value === "") {
      if (prompt.route && prompt.route.task_id !== null) deleteRoute.mutate(prompt.route.id);
      setPending((p) => {
        const next = { ...p };
        delete next[prompt.task_id];
        return next;
      });
      return;
    }
    if (value === "instance") {
      // A per-prompt route with no key: this prompt goes to the instance's
      // provider even though a default key exists.
      upsertRoute.mutate({ task_id: prompt.task_id, provider_id: null });
      return;
    }
    const key = myKeys.find((k) => k.id === value);
    if (!key) return;
    const model = firstModel(key);
    if (model) commit(prompt, key.id, model);
    else setPending((p) => ({ ...p, [prompt.task_id]: { providerId: key.id, model: "" } }));
  };

  return (
    <div className={page.card}>
      <div className={styles.cardHead}>
        <h3 className={styles.cardTitle}>Which key each prompt uses</h3>
        <span className={styles.muted}>Only prompts your admin allows</span>
      </div>
      {overview.tasks.length === 0 ? (
        <div className={styles.empty}>Your admin hasn't opened any prompt to personal keys.</div>
      ) : (
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Prompt</th>
                <th>Runs on</th>
                <th>Model</th>
                <th className={styles.num}>This month</th>
              </tr>
            </thead>
            <tbody>
              {overview.tasks.map((prompt) => {
                const own = prompt.route && prompt.route.task_id !== null ? prompt.route : null;
                const optedOut = !!own && own.provider_id === null;
                const p = pending[prompt.task_id];
                const selected = p?.providerId ?? (optedOut ? "instance" : (own?.provider_id ?? ""));
                const key = myKeys.find((k) => k.id === selected) ?? null;
                const effectiveKey = key ?? (own ? null : defaultKey);
                const noTools = prompt.requires_tools && effectiveKey && !effectiveKey.supports_tools;
                return (
                  <tr key={prompt.task_id}>
                    <td>{prompt.display_name}</td>
                    <td>
                      <select
                        className={`${page.select} ${styles.selectSm}`}
                        value={selected}
                        onChange={(e) => onPick(prompt, e.target.value)}
                        aria-label={`${prompt.display_name} route`}
                      >
                        <option value="">{defaultKey ? `Default key (${defaultKey.name})` : "Instance default"}</option>
                        {defaultKey && <option value="instance">Instance default</option>}
                        {myKeys.map((k) => (
                          <option key={k.id} value={k.id}>
                            {k.name}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      {p ? (
                        <input
                          className={`${page.input} ${styles.mono} ${styles.modelInput}`}
                          placeholder="Model name, then Enter"
                          value={p.model}
                          aria-label={`${prompt.display_name} model`}
                          onChange={(e) => setPending((prev) => ({ ...prev, [prompt.task_id]: { ...p, model: e.target.value } }))}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") commit(prompt, p.providerId, p.model);
                          }}
                          autoFocus
                        />
                      ) : optedOut ? (
                        <span className={`${styles.muted} ${styles.mono}`}>
                          {prompt.site_provider_name ? `${prompt.site_provider_name} / ${prompt.site_model_name}` : "not set"}
                        </span>
                      ) : own && key ? (
                        key.models.length > 0 ? (
                          <select
                            className={`${page.select} ${styles.selectSm} ${styles.mono}`}
                            value={own.model_name ?? ""}
                            onChange={(e) => commit(prompt, key.id, e.target.value)}
                            aria-label={`${prompt.display_name} model`}
                          >
                            {own.model_name && !key.models.includes(own.model_name) && (
                              <option value={own.model_name}>{own.model_name}</option>
                            )}
                            {key.models.map((m) => (
                              <option key={m} value={m}>
                                {m}
                              </option>
                            ))}
                          </select>
                        ) : (
                          <span className={styles.mono}>{own.model_name}</span>
                        )
                      ) : defaultKey ? (
                        <span className={`${styles.muted} ${styles.mono}`}>follows default · {defaultRouteModel}</span>
                      ) : (
                        <span className={`${styles.muted} ${styles.mono}`}>
                          {prompt.site_provider_name ? `${prompt.site_provider_name} / ${prompt.site_model_name}` : "not set"}
                        </span>
                      )}
                      {noTools && (
                        <Chip size="sm" tone="toned" tint="var(--warning)" title="This provider type has no tool calling" className={styles.toolsChip}>
                          no tools
                        </Chip>
                      )}
                    </td>
                    <td className={styles.num}>{Number(prompt.month_cost) > 0 ? formatUsd(prompt.month_cost) : "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- fallback + cap

function FallbackCard({ overview }: { overview: NonNullable<ReturnType<typeof useMyAI>["data"]> }) {
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  const update = useUpdateMyAIPreferences();
  const { policy } = overview;
  const stored = formatCapInput(overview.monthly_cap_usd);
  const [cap, setCap] = useState(stored);
  const [error, setError] = useState<string | null>(null);
  // The add-key form can set the cap too: follow the server's value.
  useEffect(() => setCap(stored), [stored]);

  const saveCap = async () => {
    setError(null);
    const trimmed = cap.trim();
    if (trimmed === stored || (trimmed === "" && stored === "")) return;
    try {
      await update.mutateAsync({ monthly_cap_usd: trimmed === "" ? null : trimmed });
    } catch (err) {
      setError(apiErrorInfo(err).message);
    }
  };

  return (
    <div className={page.card}>
      <h3 className={styles.cardTitle}>When my key can't answer</h3>
      {!policy.require_user_ai_provider && (
        <div className={page.settingRow}>
          <div className={page.settingInfo}>
            <span className={page.settingLabel}>Fall back to the instance's providers</span>
            <span className={page.settingHint}>
              If your key fails or reaches a cap, the prompt runs on the instance's provider and the result is labelled.
              If this is off, the prompt stops with an error instead.
            </span>
          </div>
          <label className={page.toggle}>
            <input
              type="checkbox"
              checked={overview.fallback_to_site}
              aria-label="Fall back to the instance's providers"
              onChange={(e) => update.mutate({ fallback_to_site: e.target.checked })}
            />
            <span className={page.toggleSlider} />
          </label>
        </div>
      )}
      {policy.require_user_ai_provider && (
        <p className={page.settingHint}>
          This instance requires your own key for the prompts you run yourself: there is no fallback to its providers.
        </p>
      )}
      <div className={page.settingRow}>
        <div className={page.settingInfo}>
          <span className={page.settingLabel}>My monthly cap</span>
          <span className={page.settingHint}>
            Leave it empty for no limit.
            {isAdmin && (
              <>
                {" "}
                Everyone's spend is on the <Link to="/settings?section=ai&tab=cost">Cost Dashboard</Link>.
              </>
            )}
            {error && <span className={styles.formError}> {error}</span>}
          </span>
        </div>
        <span className={styles.capInput}>
          <span className={styles.muted}>$</span>
          <input
            className={`${page.input} ${styles.mono}`}
            value={cap}
            placeholder="none"
            aria-label="My monthly cap"
            onChange={(e) => setCap(e.target.value)}
            onBlur={saveCap}
            onKeyDown={(e) => {
              if (e.key === "Enter") (e.target as HTMLInputElement).blur();
            }}
          />
        </span>
      </div>
    </div>
  );
}

export default MyAISection;
