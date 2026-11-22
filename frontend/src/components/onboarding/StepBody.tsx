import { useRef, useState, type ComponentType } from "react";
import { Link } from "react-router-dom";
import api from "@/api/client";
import { useQueryClient } from "@tanstack/react-query";
import { useAddFeed, useImportStarterPacks, useStarterPacks } from "@/hooks/useFeeds";
import {
  useAIProviders,
  useCommissionAIProvider,
  useCreateAIProvider,
  useUpdateAIProvider,
} from "@/hooks/useAI";
import { useOnboardingStatus } from "@/hooks/useOnboarding";
import type {
  AIProviderCommissionResult,
  OnboardingStatus,
  StarterPackImportResult,
  Theme,
} from "@/api/types";
import { KEY_GROUPS, type StepId } from "./steps";
import { PivotSchematic, QueueSchematic, ReaderSchematic } from "./visuals";
import styles from "./OnboardingWizard.module.css";

interface ThemeControl {
  list: Theme[];
  current: string | undefined;
  apply: (id: string) => void;
}

interface Props {
  step: StepId;
  status: OnboardingStatus | undefined;
  refetchStatus: () => void;
  isAdmin: boolean;
  username: string | undefined;
  Logo: ComponentType<{ className?: string }>;
  themes: ThemeControl;
}

export function StepBody(props: Props) {
  switch (props.step) {
    case "welcome":
      return <Welcome Logo={props.Logo} isAdmin={props.isAdmin} />;
    case "readiness":
      return <Readiness status={props.status} refetchStatus={props.refetchStatus} />;
    case "feeds":
      return <Feeds />;
    case "ai":
      return <AIStep />;
    case "extras":
      return <Extras />;
    case "verify":
      return <Verify />;
    case "reader":
      return <Reader />;
    case "queue":
      return <Queue />;
    case "entities":
      return <Entities />;
    case "search":
      return <Search />;
    case "workbench":
      return <Workbench />;
    case "intel":
      return <Intel />;
    case "theme":
      return <ThemeStep themes={props.themes} />;
    case "shortcuts":
      return <Shortcuts />;
    case "help":
      return <Help username={props.username} />;
  }
}

/* ------------------------------------------------------------- helpers --- */

function Title({ children }: { children: React.ReactNode }) {
  return (
    <h2 id="onb-title" className={styles.stepTitle}>
      {children}
    </h2>
  );
}

function Lead({ children }: { children: React.ReactNode }) {
  return <p className={styles.stepDesc}>{children}</p>;
}

function Facts({ rows }: { rows: [React.ReactNode, React.ReactNode][] }) {
  return (
    <dl className={styles.facts}>
      {rows.map(([k, v], i) => (
        <div key={i}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function Chips({ items, lit }: { items: string[]; lit?: boolean }) {
  return (
    <div className={styles.chips}>
      {items.map((t) => (
        <span key={t} className={`${styles.chip} ${lit ? styles.chipLit : ""}`}>
          {t}
        </span>
      ))}
    </div>
  );
}

/* --------------------------------------------------------------- steps --- */

function Welcome({ Logo, isAdmin }: { Logo: ComponentType<{ className?: string }>; isAdmin: boolean }) {
  return (
    <>
      <div className={styles.welcomeHead}>
        <Logo className={styles.logo} />
        <Title>Welcome to IntelFeed</Title>
      </div>
      <Lead>
        IntelFeed reads security sources, extracts the actors, malware, CVEs and techniques they
        mention, and links them across articles.
      </Lead>
      <Lead>
        {isAdmin
          ? "This walks you through setting up the instance, then how to use it. Every step can be skipped. Closing this box saves your place."
          : "This walks you through reading, triage, entities, search and the workbench. Every step can be skipped. Closing this box saves your place."}
      </Lead>
    </>
  );
}

function Readiness({
  status,
  refetchStatus,
}: {
  status: OnboardingStatus | undefined;
  refetchStatus: () => void;
}) {
  const ref = status?.reference_data;
  return (
    <>
      <Title>Reference data</Title>
      <Lead>
        The autolinker needs reference data (the entity vocabulary) before it can link articles to
        entities. Without it, a fresh install ingests articles and extracts nothing.
      </Lead>
      <ul className={styles.checks}>
        {(ref?.checks ?? []).map((c) => (
          <li key={c.key} className={`${styles.check} ${c.ok ? styles.checkOk : styles.checkBad}`}>
            <span className={styles.checkMark} aria-hidden="true">
              {c.ok ? "✓" : "✕"}
            </span>
            {c.label}
            <span className={styles.checkCount}>{c.count.toLocaleString()}</span>
          </li>
        ))}
      </ul>
      {ref && !ref.ok && (
        <div className={`${styles.callout} ${styles.calloutWarn}`}>
          <b>Reference data is not seeded.</b> {ref.consequence} Run this once, then re-check:
          {/* The whole line comes from the server, compose file included — the UI
              has no way to know which compose file this instance runs under. */}
          <pre className={styles.code}>{ref.remedy}</pre>
        </div>
      )}
      {ref?.ok && (
        <div className={`${styles.callout} ${styles.calloutOk}`}>
          <b>Reference data is in place.</b> The autolinker has a vocabulary to match articles
          against.
        </div>
      )}
      <button type="button" className={styles.btn} onClick={() => refetchStatus()}>
        Re-check
      </button>
    </>
  );
}

function Feeds() {
  const { data: packs } = useStarterPacks();
  const importPacks = useImportStarterPacks();
  const addFeed = useAddFeed();
  const queryClient = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);

  const [picked, setPicked] = useState<string[] | null>(null);
  const [result, setResult] = useState<StarterPackImportResult | null>(null);
  const [error, setError] = useState("");
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);

  const selected = picked ?? packs?.filter((p) => p.recommended).map((p) => p.id) ?? [];
  const count = (packs ?? []).filter((p) => selected.includes(p.id)).reduce((n, p) => n + p.feed_count, 0);

  const toggle = (id: string) =>
    setPicked(selected.includes(id) ? selected.filter((x) => x !== id) : [...selected, id]);

  const importSelected = async () => {
    if (!selected.length) return;
    setError("");
    try {
      setResult(await importPacks.mutateAsync(selected));
    } catch {
      setError("Could not add those feeds. Try again, or add one by URL below.");
    }
  };

  const uploadOpml = async (file: File) => {
    setBusy(true);
    setError("");
    const form = new FormData();
    form.append("file", file);
    try {
      const res = await api.post("/opml/import", form, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setResult(res.data);
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
      queryClient.invalidateQueries({ queryKey: ["categories"] });
    } catch {
      setError("Could not import that file. Check that it is a valid OPML export.");
    } finally {
      setBusy(false);
    }
  };

  const addOne = async () => {
    if (!url.trim()) return;
    setBusy(true);
    setError("");
    try {
      await addFeed.mutateAsync({ url: url.trim() });
      setUrl("");
    } catch {
      setError("Could not add that URL. Check it and try again.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Title>Add feeds</Title>
      <Lead>
        IntelFeed ships with packs of reviewed security sources. Core is a good first choice. Nothing
        is added until you choose.
      </Lead>

      <div className={styles.cards}>
        {(packs ?? []).map((p) => {
          const on = selected.includes(p.id);
          return (
            <button
              key={p.id}
              type="button"
              className={`${styles.card} ${on ? styles.cardOn : ""}`}
              aria-pressed={on}
              disabled={importPacks.isSuccess}
              onClick={() => toggle(p.id)}
            >
              <span className={styles.cardTitle}>
                {p.title}
                <span className={styles.cardMeta}>{p.feed_count} feeds</span>
                {p.recommended && <span className={styles.badge}>Recommended</span>}
              </span>
              <span className={styles.cardDesc}>{p.description}</span>
              {p.requires && on && <span className={styles.cardWarn}>Needs: {p.requires}</span>}
            </button>
          );
        })}
      </div>

      {!importPacks.isSuccess && (
        <button
          type="button"
          className={`${styles.btn} ${styles.btnPrimary}`}
          onClick={importSelected}
          disabled={!selected.length || importPacks.isPending}
        >
          {importPacks.isPending
            ? "Adding feeds…"
            : selected.length
              ? `Add ${count} feed${count !== 1 ? "s" : ""}`
              : "Select a pack to continue"}
        </button>
      )}

      <div className={styles.orRow}>
        <input
          ref={fileRef}
          type="file"
          accept=".opml,.xml"
          id="onb-opml"
          className={styles.fileInput}
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) uploadOpml(f);
          }}
        />
        <button type="button" className={styles.btn} onClick={() => fileRef.current?.click()} disabled={busy}>
          Import an OPML file
        </button>
        <input
          type="url"
          id="onb-feed-url"
          className={styles.urlInput}
          placeholder="or paste a feed, YouTube or subreddit URL"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && addOne()}
        />
        <button type="button" className={styles.btn} onClick={addOne} disabled={busy || !url.trim()}>
          Add
        </button>
      </div>

      {result && (
        <div className={`${styles.callout} ${styles.calloutOk}`}>
          Added {result.feeds_added} feed{result.feeds_added !== 1 ? "s" : ""}
          {result.categories_created > 0 &&
            ` in ${result.categories_created} categor${result.categories_created !== 1 ? "ies" : "y"}`}
          {result.feeds_skipped > 0 && ` (${result.feeds_skipped} already existed)`}.
          {result.feeds_added > 0 && " They are fetching now."}
        </div>
      )}
      {error && <div className={`${styles.callout} ${styles.calloutBad}`}>{error}</div>}
    </>
  );
}

const AI_CHOICES = [
  {
    id: "ollama",
    title: "Ollama",
    tag: "Local & free",
    desc: "Point at your own Ollama host. An 8 to 14B instruct model is enough for summaries and extraction.",
    needsUrl: true,
  },
  {
    id: "claude",
    title: "Claude",
    tag: "API key",
    desc: "Anthropic's API. Strongest extraction quality, billed per token, with a spend ceiling you set under Settings → AI Configuration.",
    needsKey: true,
  },
  {
    id: "openai_compatible",
    title: "OpenAI-compatible",
    tag: "Any endpoint",
    desc: "OpenAI, LM Studio, vLLM, llama.cpp, LiteLLM, OpenRouter, Groq, or any endpoint that implements /v1/chat/completions.",
    needsUrl: true,
    optionalKey: true,
  },
  {
    id: "none",
    title: "Skip: run without AI",
    desc: "You keep ingest, autolinking, search, dedup and regex detection-rule extraction. You lose summaries, the one-pass entry analysis and AI entity assessments. Add a provider any time.",
  },
] as const;

function AIStep() {
  const createProvider = useCreateAIProvider();
  const updateProvider = useUpdateAIProvider();
  const commission = useCommissionAIProvider();
  const { data: providers } = useAIProviders();
  const [choice, setChoice] = useState<string>("ollama");
  const [baseUrl, setBaseUrl] = useState("http://ollama:11434");
  const [apiKey, setApiKey] = useState("");
  // openai_compatible only: its /models catalog mixes chat models with tts,
  // whisper, dall-e and embeddings, so the admin names the one to use.
  const [model, setModel] = useState("");
  const [result, setResult] = useState<AIProviderCommissionResult | null>(null);
  const [error, setError] = useState("");

  const current = AI_CHOICES.find((c) => c.id === choice)!;
  const busy = createProvider.isPending || updateProvider.isPending || commission.isPending;

  const save = async () => {
    setError("");
    setResult(null);
    try {
      // Reuse a provider of this type if one is already registered, rather than
      // minting a duplicate every time the step is revisited or the tour replayed.
      // GET /ai/providers also lists the caller's personal keys (user_id set);
      // one of those is never the instance's provider.
      const existing = providers?.find((p) => !p.user_id && p.provider_type === choice);
      const fields =
        choice === "ollama"
          ? { name: "Ollama", provider_type: "ollama", base_url: baseUrl.trim() }
          : choice === "openai_compatible"
            ? {
                name: "OpenAI-compatible",
                provider_type: "openai_compatible",
                base_url: baseUrl.trim(),
                api_key: apiKey.trim() || undefined,
                config: { ...(existing?.config || {}), default_model: model.trim() },
              }
            : { name: "Anthropic Claude", provider_type: "claude", api_key: apiKey.trim() };
      const provider = existing
        ? await updateProvider.mutateAsync({ id: existing.id, ...fields, is_active: true })
        : await createProvider.mutateAsync(fields);

      // Registering is not configuring: commission tests the provider for real and
      // routes the AI tasks at it. take_over moves tasks the startup seeder parked
      // on the CLI provider, which is the whole reason first-run AI never ran.
      const outcome = await commission.mutateAsync({ id: provider.id, takeOver: true });
      if (!outcome.success) {
        setError(
          choice === "openai_compatible"
            ? `Could not set up that endpoint: ${outcome.message}.`
            : choice === "ollama"
              ? `Could not reach that host: ${outcome.message}.`
              : `That key was rejected: ${outcome.message}.`,
        );
        return;
      }
      setResult(outcome);
    } catch {
      setError("Could not save that provider. Check the details and try again.");
    }
  };

  const saved = !!result;

  return (
    <>
      <Title>Choose an AI provider</Title>
      <Lead>
        AI handles summaries, the one-pass analysis of each entry, and entity assessments. Ingest,
        autolinking, search and detection-rule extraction run without it.
      </Lead>

      <div className={styles.cards}>
        {AI_CHOICES.map((c) => (
          <button
            key={c.id}
            type="button"
            className={`${styles.card} ${choice === c.id ? styles.cardOn : ""}`}
            aria-pressed={choice === c.id}
            onClick={() => {
              setChoice(c.id);
              setBaseUrl(c.id === "openai_compatible" ? "" : "http://ollama:11434");
              setApiKey("");
              setModel("");
              setResult(null);
              setError("");
            }}
          >
            <span className={styles.cardTitle}>
              {c.title}
              {"tag" in c && c.tag && <span className={styles.badge}>{c.tag}</span>}
            </span>
            <span className={styles.cardDesc}>{c.desc}</span>
          </button>
        ))}
      </div>

      {!saved && "needsUrl" in current && current.needsUrl && (
        <div className={styles.orRow}>
          <label htmlFor="onb-provider-url" className={styles.srOnly}>
            Base URL
          </label>
          <input
            id="onb-provider-url"
            type="url"
            className={styles.urlInput}
            placeholder={choice === "openai_compatible" ? "http://localhost:1234/v1" : undefined}
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
          />
          {"optionalKey" in current && current.optionalKey && (
            <>
              <label htmlFor="onb-provider-key" className={styles.srOnly}>
                API key (optional)
              </label>
              <input
                id="onb-provider-key"
                type="password"
                className={styles.urlInput}
                placeholder="API key (optional)"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
              />
            </>
          )}
          {choice === "openai_compatible" && (
            <>
              <label htmlFor="onb-provider-model" className={styles.srOnly}>
                Model
              </label>
              <input
                id="onb-provider-model"
                type="text"
                className={styles.urlInput}
                placeholder="Model, e.g. gpt-4o-mini"
                value={model}
                onChange={(e) => setModel(e.target.value)}
              />
            </>
          )}
          <button
            type="button"
            className={`${styles.btn} ${styles.btnPrimary}`}
            onClick={save}
            disabled={busy || !baseUrl.trim() || (choice === "openai_compatible" && !model.trim())}
          >
            {busy ? "Connecting…" : "Connect"}
          </button>
        </div>
      )}

      {!saved && "needsKey" in current && current.needsKey && (
        <div className={styles.orRow}>
          <label htmlFor="onb-claude-key" className={styles.srOnly}>
            Anthropic API key
          </label>
          <input
            id="onb-claude-key"
            type="password"
            className={styles.urlInput}
            placeholder="sk-ant-..."
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
          />
          <button
            type="button"
            className={`${styles.btn} ${styles.btnPrimary}`}
            onClick={save}
            disabled={busy || !apiKey.trim()}
          >
            {busy ? "Checking the key…" : "Save key"}
          </button>
        </div>
      )}

      {choice === "none" && (
        <div className={styles.callout}>
          Nothing to configure. Add a provider later under <b>Settings → AI Configuration</b>.
        </div>
      )}
      {result && (
        <div className={`${styles.callout} ${styles.calloutOk}`}>
          <b>Connected. AI tasks are assigned.</b> {result.tasks_assigned + result.tasks_reassigned} task
          {result.tasks_assigned + result.tasks_reassigned !== 1 ? "s" : ""} now run on{" "}
          <code>{result.model}</code>
          {result.models.length > 1 && ` (${result.models.length} models available)`}. Change any of
          them under <b>Settings → AI Configuration</b>.
          {result.tasks_skipped_agentic.length > 0 && (
            <>
              {" "}
              {result.tasks_skipped_agentic.length} agentic task
              {result.tasks_skipped_agentic.length !== 1 ? "s" : ""} stayed where they were: they need
              tool calling or web search, which this provider does not have enabled.
            </>
          )}
        </div>
      )}
      {error && <div className={`${styles.callout} ${styles.calloutBad}`}>{error}</div>}
    </>
  );
}

function Extras() {
  return (
    <>
      <Title>Optional services, and your team</Title>
      <Lead>
        All optional. Each is a container that is either running or not. Nothing here blocks setup.
      </Lead>
      <Facts
        rows={[
          ["Search", "Meilisearch backs full-text search and the facet rail. Without it, search falls back to the database."],
          ["Translation", "LibreTranslate translates foreign-language articles in place. Useful once you add non-English sources."],
          ["Read-aloud", "Piper synthesises article audio server-side, cached per entry, playable in the reader."],
        ]}
      />
      <Lead>
        <b>Your team.</b> The first account is admin. Admins manage feeds, AI and the engine;
        everyone else reads, tags, pivots and writes detection rules.
      </Lead>
      <Facts
        rows={[
          ["Invites", <>Registration requires an invite code now that the first account exists. Find the code, change it, or reopen registration under <b>Settings → Users</b>.</>],
          ["Roles", <>Promote or demote accounts under <b>Settings → Users</b>.</>],
        ]}
      />
    </>
  );
}

function Verify() {
  // Poll while this step is on screen: the whole point is watching a real fetch
  // land rather than being told the configuration was saved.
  const { data: status } = useOnboardingStatus({ pollMs: 5000 });
  const feeds = status?.feeds;
  const entries = status?.entries;
  const links = status?.autolink.entity_links ?? 0;
  const working = !!status?.ready;

  return (
    <>
      <Title>{working ? "It works" : "Waiting for the first poll"}</Title>
      <Lead>
        This step waits for the first feed poll to complete and the first entries to be linked.
      </Lead>
      <ul className={styles.checks}>
        <li className={`${styles.check} ${feeds && feeds.polled_ok > 0 ? styles.checkOk : styles.checkWait}`}>
          <span className={styles.checkMark} aria-hidden="true">
            {feeds && feeds.polled_ok > 0 ? "✓" : "○"}
          </span>
          Feeds polled successfully
          <span className={styles.checkCount}>
            {feeds ? `${feeds.polled_ok} / ${feeds.total}` : "…"}
          </span>
        </li>
        <li className={`${styles.check} ${entries && entries.total > 0 ? styles.checkOk : styles.checkWait}`}>
          <span className={styles.checkMark} aria-hidden="true">
            {entries && entries.total > 0 ? "✓" : "○"}
          </span>
          Entries ingested
          <span className={styles.checkCount}>{entries ? entries.total.toLocaleString() : "…"}</span>
        </li>
        <li className={`${styles.check} ${links > 0 ? styles.checkOk : styles.checkWait}`}>
          <span className={styles.checkMark} aria-hidden="true">
            {links > 0 ? "✓" : "○"}
          </span>
          Entities autolinked
          <span className={styles.checkCount}>{links.toLocaleString()}</span>
        </li>
        {!!feeds?.errored && (
          <li className={`${styles.check} ${styles.checkBad}`}>
            <span className={styles.checkMark} aria-hidden="true">
              {"✕"}
            </span>
            Feeds erroring
            <span className={styles.checkCount}>{feeds.errored}</span>
          </li>
        )}
        {/* Only shown once a provider exists: an instance deliberately running
            without AI shouldn't be told it's missing something. */}
        {!!status?.ai.active && status.ai.active !== "claude_code" && (
          <li
            className={`${styles.check} ${status.ai.tasks_assigned > 0 ? styles.checkOk : styles.checkBad}`}
          >
            <span className={styles.checkMark} aria-hidden="true">
              {status.ai.tasks_assigned > 0 ? "✓" : "✕"}
            </span>
            AI tasks running on {status.ai.active}
            <span className={styles.checkCount}>{status.ai.tasks_assigned}</span>
          </li>
        )}
      </ul>
      {working ? (
        <div className={`${styles.callout} ${styles.calloutOk}`}>
          <b>Your instance is working.</b> Articles are arriving and being linked to entities. The
          remaining steps cover using it.
        </div>
      ) : (
        <div className={styles.callout}>
          Feeds poll on their own schedule, so the first articles can take a few minutes. You can
          move on. Polling continues in the background.
          {!!feeds?.errored && (
            <>
              {" "}
              {feeds.errored} feed{feeds.errored !== 1 ? "s" : ""} reported an error; check them
              under <b>Settings → Feeds</b>.
            </>
          )}
        </div>
      )}
    </>
  );
}

function Reader() {
  return (
    <>
      <Title>The reading loop</Title>
      <ReaderSchematic />
      <Lead>
        Three panels: your feeds, the entries in the selected feed, and the article. Entities are
        linked when each article is ingested.
      </Lead>
      <Facts
        rows={[
          ["Read state", "Entries mark themselves read as you move through them. Unread is the default view."],
          ["Keep things", "Star what matters, bookmark what you'll come back to, tag to group across feeds."],
          ["Notes", "Write a note on any entry; it travels with the entry and shows up in search."],
        ]}
      />
      <Chips items={["j / k  move", "m  read", "s  star", "b  bookmark", "t  tag", "o  original"]} />
    </>
  );
}

function Queue() {
  return (
    <>
      <Title>The Priority Queue</Title>
      <QueueSchematic />
      <Lead>
        The queue ranks new entries by signal: how many independent sources reported it, whether it
        mentions an entity you watch, and whether a CVE is being exploited. Each entry shows why it
        ranked where it did.
      </Lead>
      <Chips items={["multi-source", "watched entity", "known exploited", "vendor you track", "first report"]} lit />
      <Lead>
        Ranking is system-wide. Your own reading adds a small per-analyst lift that does not change
        the score for other users.
      </Lead>
    </>
  );
}

function Entities() {
  return (
    <>
      <Title>Entities, and pivoting between them</Title>
      <PivotSchematic />
      <Lead>
        Every article is scanned against the entity catalog as it arrives. Each match links to an
        entity profile that lists every other article that named it. That is a pivot.
      </Lead>
      <Chips
        items={[
          "threat actors",
          "malware",
          "CVEs",
          "ATT&CK techniques",
          "CWEs",
          "vendors",
          "products",
          "sectors",
          "tools",
          "observables",
        ]}
      />
      <Lead>
        Every link has a <b>Wrong?</b> control that tells the engine to stop making that match.
      </Lead>
    </>
  );
}

function Search() {
  return (
    <>
      <Title>Search</Title>
      <Lead>
        One search bar, one results page with a facet rail. Press <kbd className={styles.kbd}>⌘K</kbd>{" "}
        anywhere for the command palette, which jumps to entities and pages as well as searching.
      </Lead>
      <Facts
        rows={[
          [<code key="a">ransomware AND healthcare</code>, "Both terms"],
          [<code key="b">"initial access broker"</code>, "Exact phrase"],
          [<code key="c">actor:APT29</code>, "Scope to an entity"],
          [<code key="d">after:2026-09-01</code>, "Date bounds"],
          [<code key="e">netscal*</code>, "Wildcards"],
        ]}
      />
      <Lead>Save any search and it becomes a feed of its own in the sidebar.</Lead>
    </>
  );
}

function Workbench() {
  return (
    <>
      <Title>The workbench</Title>
      <Lead>The reader is for triage. The workbench is where you investigate what you triaged.</Lead>
      <Facts
        rows={[
          ["Threats", "Current activity, ranked by story rather than by outlet"],
          ["Entities", "Every actor, malware family, CVE and technique you've seen"],
          ["Detection", "Your rule library, and coverage against ATT&CK"],
          ["Campaigns", "Group related activity into one tracked campaign"],
          ["Reports", "Generate and export from what you've gathered"],
          ["Engine", "Admin only: what the pipeline is doing to every entry"],
        ]}
      />
      <Lead>
        Switch between Reading and Workbench modes from the sidebar. Both use the same data.
      </Lead>
    </>
  );
}

function Intel() {
  return (
    <>
      <Title>Detection rules and intel products</Title>
      <Lead>
        Rules are extracted from articles automatically and syntax-checked. Six formats:
      </Lead>
      <Chips items={["Sigma", "Splunk SPL", "CrowdStrike QL", "Elastic QL", "KQL", "YARA"]} lit />
      <Facts
        rows={[
          [
            "Story threads",
            "Articles about the same event, grouped into one thread with a timeline",
          ],
          [
            "Observables",
            "The IOC list. Regex scanning never creates an observable; they come from AI or analyst confirmation, and known values are then matched exactly",
          ],
          ["Reports", "Markdown or HTML, with CSV and ATT&CK Navigator export"],
        ]}
      />
    </>
  );
}

function ThemeStep({ themes }: { themes: ThemeControl }) {
  return (
    <>
      <Title>Appearance</Title>
      <Lead>
        {themes.list.length} themes are included. Switch any time from <b>Settings → Appearance</b>.
        Text contrast is computed per theme.
      </Lead>
      <div className={styles.themeGrid}>
        {themes.list.map((t) => (
          <button
            key={t.id}
            type="button"
            className={`${styles.themeCard} ${themes.current === t.id ? styles.themeCardOn : ""}`}
            aria-pressed={themes.current === t.id}
            onClick={() => themes.apply(t.id)}
            style={{
              background: t.css_variables["bg-primary"] || "var(--bg-primary)",
              borderColor:
                themes.current === t.id
                  ? t.css_variables["accent"] || "var(--accent)"
                  : t.css_variables["border"] || "var(--border)",
            }}
          >
            <span
              className={styles.themeAccent}
              style={{ background: t.css_variables["accent"] || "var(--accent)" }}
            />
            <span
              className={styles.themeName}
              style={{ color: t.css_variables["text-primary"] || "var(--text-primary)" }}
            >
              {t.name}
            </span>
          </button>
        ))}
      </div>
    </>
  );
}

function Shortcuts() {
  return (
    <>
      <Title>Keyboard shortcuts</Title>
      <Lead>
        Press <kbd className={styles.kbd}>?</kbd> anywhere for the full list.
      </Lead>
      <div className={styles.keyGroups}>
        {KEY_GROUPS.map(({ section, items }) => (
          <div key={section}>
            <h3 className={styles.keySection}>{section}</h3>
            <div className={styles.keyGrid}>
              {items.map(([key, label]) => (
                <div key={key} className={styles.keyRow}>
                  <kbd className={styles.kbd}>{key}</kbd>
                  <span>{label}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </>
  );
}

function Help({ username }: { username: string | undefined }) {
  return (
    <>
      <Title>Where to find help</Title>
      <Lead>That is the end of the tour{username ? `, ${username}` : ""}. Three places to find help inside the app:</Lead>
      <Facts
        rows={[
          [
            "Documentation",
            <>
              Thirteen guides, from the reading loop to detection rules.{" "}
              <Link to="/documentation/README">Open the docs</Link>, or use the book icon in the
              header.
            </>,
          ],
          ["Docs copilot", "Ask it a question about IntelFeed and it answers from those guides."],
          ["Glossary", "Hover any term you don't recognise for a definition in place."],
        ]}
      />
      <div className={styles.callout}>
        Replay this tour any time from <b>Settings → Account</b>.
      </div>
      <Lead>
        To use IntelFeed from Claude Code or an MCP client, see{" "}
        <b>Settings → Claude Code Skill</b>.
      </Lead>
    </>
  );
}
