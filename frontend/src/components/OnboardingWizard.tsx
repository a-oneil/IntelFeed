import { useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { useUpdateProfile } from "@/hooks/useAuth";
import { useFeeds, useAddFeed } from "@/hooks/useFeeds";
import { useCreateAIProvider } from "@/hooks/useAI";
import { useThemes, useSetThemePreference } from "@/hooks/useThemes";
import { IntelFeedLogo } from "./IntelFeedLogo";
import styles from "./OnboardingWizard.module.css";

interface AddedFeed {
  title: string;
  url: string;
}

const ALL_STEPS = ["welcome", "import", "feeds", "ai", "theme", "shortcuts", "docs", "skill"] as const;
type Step = (typeof ALL_STEPS)[number];
const SETUP_STEPS: Step[] = ["import", "feeds", "ai"];

export function OnboardingWizard() {
  const user = useAuthStore((s) => s.user);
  const updateProfile = useUpdateProfile();
  const addFeed = useAddFeed();
  const queryClient = useQueryClient();
  const { data: feedsData } = useFeeds();

  // If feeds already exist, another user has set up the instance — skip setup
  // steps. OPML import and AI-provider creation hit admin-only endpoints, so
  // non-admins never see those steps at all.
  const hasExistingFeeds = (feedsData?.total ?? 0) > 0;
  const isAdmin = user?.role === "admin";
  const steps = ALL_STEPS.filter((s) => {
    if (hasExistingFeeds && SETUP_STEPS.includes(s)) return false;
    if (!isAdmin && (s === "import" || s === "ai")) return false;
    return true;
  });

  const [dismissed, setDismissed] = useState(false);
  const [step, setStep] = useState<Step>("welcome");
  const [feedUrl, setFeedUrl] = useState("");
  const [addedFeeds, setAddedFeeds] = useState<AddedFeed[]>([]);
  const [feedError, setFeedError] = useState("");
  const [feedLoading, setFeedLoading] = useState(false);
  const [importResult, setImportResult] = useState<{
    feeds_added: number;
    feeds_skipped: number;
    categories_created: number;
  } | null>(null);
  const [importError, setImportError] = useState("");
  const [importing, setImporting] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  // AI config state
  const [aiProviderType, setAiProviderType] = useState<"claude" | "ollama" | "openai_compatible">("claude");
  const [aiApiKey, setAiApiKey] = useState("");
  const [aiBaseUrl, setAiBaseUrl] = useState("");
  const [aiSaved, setAiSaved] = useState(false);
  const [aiError, setAiError] = useState("");
  const createProvider = useCreateAIProvider();
  const aiRequiresBaseUrl = aiProviderType === "ollama" || aiProviderType === "openai_compatible";
  const aiCanSave = aiRequiresBaseUrl ? !!aiBaseUrl.trim() : !!aiApiKey.trim();

  // Theme state
  const { data: themes } = useThemes();
  const setThemePref = useSetThemePreference();
  const [selectedThemeId, setSelectedThemeId] = useState<string | null>(null);

  if (dismissed) return null;

  const stepIndex = steps.indexOf(step);

  const dismiss = () => {
    setDismissed(true);
    updateProfile.mutate({
      settings: { ...user?.settings, onboarding_completed: true },
    });
  };

  const next = () => {
    const nextIndex = stepIndex + 1;
    if (nextIndex < steps.length) {
      setStep(steps[nextIndex]);
    } else {
      dismiss();
    }
  };

  const prev = () => {
    if (stepIndex > 0) setStep(steps[stepIndex - 1]);
  };

  const handleImport = async (file: File) => {
    setImporting(true);
    setImportError("");
    setImportResult(null);
    const formData = new FormData();
    formData.append("file", file);
    try {
      const res = await api.post("/opml/import", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setImportResult(res.data);
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
      queryClient.invalidateQueries({ queryKey: ["categories"] });
    } catch {
      setImportError("Failed to import OPML file. Please check the format.");
    } finally {
      setImporting(false);
    }
  };

  const handleAddFeed = async () => {
    if (!feedUrl.trim()) return;
    setFeedError("");
    setFeedLoading(true);
    try {
      const res = await addFeed.mutateAsync({ url: feedUrl.trim() });
      setAddedFeeds((prev) => [
        ...prev,
        { title: res.title || feedUrl.trim(), url: feedUrl.trim() },
      ]);
      setFeedUrl("");
    } catch {
      setFeedError("Could not add feed. Check the URL and try again.");
    } finally {
      setFeedLoading(false);
    }
  };

  const renderStep = () => {
    switch (step) {
      case "welcome":
        return (
          <>
            <div className={styles.header}>
              <IntelFeedLogo className={styles.logo} />
              <h2 className={styles.title}>
                Welcome
              </h2>
              <p className={styles.subtitle}>
                Let's get your threat intelligence feed up and running.
              </p>
            </div>
            <div className={styles.body}>
              <p className={styles.stepDesc}>
                IntelFeed is a security-focused RSS aggregator with AI-powered
                threat intelligence extraction, detection engineering, and entity
                correlation. This quick setup will help you import your feeds and
                learn the basics.
              </p>
            </div>
          </>
        );

      case "import":
        return (
          <div className={styles.body}>
            <h3 className={styles.stepTitle}>Import Your Feeds</h3>
            <p className={styles.stepDesc}>
              Have an OPML file from another reader? Import it to bring all your
              feeds and categories over at once.
            </p>
            <input
              ref={fileRef}
              type="file"
              accept=".opml,.xml"
              className={styles.fileInput}
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) handleImport(file);
              }}
            />
            <div
              className={styles.uploadArea}
              onClick={() => fileRef.current?.click()}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") fileRef.current?.click();
              }}
            >
              <div className={styles.uploadIcon}>
                {importing ? "\u23F3" : "\uD83D\uDCC1"}
              </div>
              <div className={styles.uploadLabel}>
                {importing ? (
                  "Importing..."
                ) : (
                  <>
                    <strong>Click to upload</strong> an OPML file
                  </>
                )}
              </div>
            </div>
            {importResult && (
              <div className={`${styles.importResult} ${styles.success}`}>
                Imported {importResult.feeds_added} feed
                {importResult.feeds_added !== 1 ? "s" : ""}
                {importResult.categories_created > 0 &&
                  ` in ${importResult.categories_created} categor${importResult.categories_created !== 1 ? "ies" : "y"}`}
                {importResult.feeds_skipped > 0 &&
                  ` (${importResult.feeds_skipped} already existed)`}
              </div>
            )}
            {importError && (
              <div className={`${styles.importResult} ${styles.error}`}>
                {importError}
              </div>
            )}
          </div>
        );

      case "feeds":
        return (
          <div className={styles.body}>
            <h3 className={styles.stepTitle}>Add Feeds Manually</h3>
            <p className={styles.stepDesc}>
              Paste any RSS, Atom, YouTube channel, or podcast URL. IntelFeed
              will auto-detect the feed type.
            </p>
            <div className={styles.feedInput}>
              <input
                type="url"
                placeholder="https://example.com/feed.xml"
                value={feedUrl}
                onChange={(e) => setFeedUrl(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleAddFeed();
                }}
              />
              <button
                className={styles.btnPrimary}
                onClick={handleAddFeed}
                disabled={feedLoading || !feedUrl.trim()}
              >
                {feedLoading ? "Adding..." : "Add"}
              </button>
            </div>
            {feedError && (
              <div className={`${styles.importResult} ${styles.error}`}>
                {feedError}
              </div>
            )}
            {addedFeeds.length > 0 && (
              <div className={styles.feedsList}>
                {addedFeeds.map((f, i) => (
                  <div key={i} className={styles.feedItem}>
                    <span className={styles.feedItemIcon}>&#10003;</span>
                    <span className={styles.feedItemTitle}>{f.title}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        );

      case "ai":
        return (
          <div className={styles.body}>
            <h3 className={styles.stepTitle}>Configure AI</h3>
            <p className={styles.stepDesc}>
              Optionally connect an AI provider for threat intelligence
              extraction, detection rule generation, and content summarization.
              You can skip this and set it up later in Settings.
            </p>
            {!aiSaved && (
              <div className={styles.feedInput}>
                <select
                  value={aiProviderType}
                  onChange={(e) => {
                    const nextType = e.target.value as "claude" | "ollama" | "openai_compatible";
                    setAiProviderType(nextType);
                    if (nextType !== "ollama" && nextType !== "openai_compatible") {
                      setAiBaseUrl("");
                    }
                  }}
                >
                  <option value="claude">Claude (Anthropic API)</option>
                  <option value="ollama">Ollama (self-hosted)</option>
                  <option value="openai_compatible">OpenAI-compatible</option>
                </select>
              </div>
            )}
            {!aiSaved && aiProviderType === "openai_compatible" && (
              <p className={styles.selectHint}>
                OpenAI, LM Studio, vLLM, llama.cpp, OpenRouter, LiteLLM, or Groq
              </p>
            )}
            {!aiSaved && aiRequiresBaseUrl && (
              <div className={styles.feedInput}>
                <input
                  placeholder={
                    aiProviderType === "ollama"
                      ? "Base URL (e.g. http://localhost:11434)"
                      : "Base URL (e.g. http://localhost:1234/v1, https://api.openai.com/v1)"
                  }
                  value={aiBaseUrl}
                  onChange={(e) => setAiBaseUrl(e.target.value)}
                />
              </div>
            )}
            {!aiSaved && (
              <div className={styles.feedInput}>
                <input
                  type="password"
                  placeholder={
                    aiProviderType === "claude"
                      ? "Anthropic API Key"
                      : aiProviderType === "ollama"
                        ? "Bearer token (optional, for proxied instances)"
                        : "API key (optional for local servers)"
                  }
                  value={aiApiKey}
                  onChange={(e) => setAiApiKey(e.target.value)}
                />
              </div>
            )}
            {!aiSaved && (
              <button
                className={styles.btnPrimary}
                onClick={async () => {
                  setAiError("");
                  try {
                    await createProvider.mutateAsync({
                      name:
                        aiProviderType === "claude"
                          ? "Claude"
                          : aiProviderType === "ollama"
                            ? "Ollama"
                            : "OpenAI-compatible",
                      provider_type: aiProviderType,
                      base_url: aiRequiresBaseUrl ? aiBaseUrl || undefined : undefined,
                      api_key: aiApiKey || undefined,
                    });
                    setAiSaved(true);
                  } catch {
                    setAiError("Failed to save provider. Check your settings.");
                  }
                }}
                disabled={createProvider.isPending || !aiCanSave}
              >
                {createProvider.isPending ? "Saving..." : "Save Provider"}
              </button>
            )}
            {aiSaved && (
              <div className={`${styles.importResult} ${styles.success}`}>
                AI provider configured successfully.
              </div>
            )}
            {aiError && (
              <div className={`${styles.importResult} ${styles.error}`}>
                {aiError}
              </div>
            )}
          </div>
        );

      case "theme":
        return (
          <div className={styles.body}>
            <h3 className={styles.stepTitle}>Choose a Theme</h3>
            <p className={styles.stepDesc}>
              Pick a color theme for IntelFeed. You can customize or create your
              own themes later in Settings.
            </p>
            <div className={styles.themeGrid}>
              {[...(themes || [])].sort((a, b) =>
                a.name.toLowerCase().includes("github dark") ? -1 :
                b.name.toLowerCase().includes("github dark") ? 1 : 0
              ).map((theme) => (
                <button
                  key={theme.id}
                  className={`${styles.themeCard} ${selectedThemeId === theme.id ? styles.themeCardSelected : ""}`}
                  onClick={() => {
                    setSelectedThemeId(theme.id);
                    setThemePref.mutate({ theme_id: theme.id });
                  }}
                  style={{
                    background: theme.css_variables["bg-primary"] || "#1a1a2e",
                    borderColor: selectedThemeId === theme.id
                      ? theme.css_variables["accent"] || "#6c63ff"
                      : theme.css_variables["border"] || "#333",
                  }}
                >
                  <div
                    className={styles.themeAccent}
                    style={{ background: theme.css_variables["accent"] || "#6c63ff" }}
                  />
                  <span
                    className={styles.themeName}
                    style={{ color: theme.css_variables["text-primary"] || "#e0e0e0" }}
                  >
                    {theme.name}
                  </span>
                </button>
              ))}
            </div>
          </div>
        );

      case "shortcuts":
        return (
          <div className={styles.body}>
            <h3 className={styles.stepTitle}>Keyboard Shortcuts</h3>
            <p className={styles.stepDesc}>
              Navigate quickly with these shortcuts. Press{" "}
              <strong>?</strong> anytime to see the full list.
            </p>
            <div className={styles.shortcutSections}>
              {[
                { section: "Navigation", items: [
                  ["j / \u2193", "Next entry"],
                  ["k / \u2191", "Previous entry"],
                  ["o", "Open original article"],
                ]},
                { section: "Actions", items: [
                  ["s", "Star / unstar entry"],
                  ["b", "Bookmark / unbookmark"],
                  ["m", "Toggle read / unread"],
                  ["Shift+M", "Mark all above as read"],
                  ["n", "Create note on entry"],
                  ["t", "Add tag to entry"],
                  ["e", "Export entry as markdown"],
                ]},
                { section: "Panels", items: [
                  ["\u2318+K", "Command palette"],
                  ["/", "Open search"],
                  ["Escape", "Close panel"],
                  ["?", "Show shortcuts help"],
                ]},
                { section: "Note Editor", items: [
                  ["Ctrl+S / \u2318+S", "Save note"],
                  ["Ctrl+B / \u2318+B", "Bold"],
                  ["Ctrl+I / \u2318+I", "Italic"],
                  ["Escape", "Close editor"],
                ]},
              ].map(({ section, items }) => (
                <div key={section} className={styles.shortcutSection}>
                  <h4 className={styles.shortcutSectionTitle}>{section}</h4>
                  <div className={styles.shortcutGrid}>
                    {items.map(([key, label]) => (
                      <div key={key} className={styles.shortcutItem}>
                        <span className={styles.shortcutKey}>{key}</span>
                        <span className={styles.shortcutLabel}>{label}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );

      case "docs":
        return (
          <div className={styles.body}>
            <h3 className={styles.stepTitle}>Help When You Need It</h3>
            <p className={styles.stepDesc}>
              IntelFeed is deep — nobody is expected to hold it all in their head.
              When something is unclear, the answer is one click away.
            </p>

            <div className={styles.skillCard}>
              <h4 className={styles.skillCardTitle}>Built-in documentation</h4>
              <p className={styles.stepDesc}>
                Every feature is covered in the user guide: reading and triage,
                the Workbench, entity profiles, detection rules, automation and
                more. It&rsquo;s always reachable from the book icon in the
                header.
              </p>
              <button
                className={styles.btnSecondary}
                onClick={() => window.open("/documentation", "_blank", "noopener")}
              >
                Open the documentation ↗
              </button>
            </div>

            <div className={styles.skillCard}>
              <h4 className={styles.skillCardTitle}>Ask instead of searching</h4>
              <p className={styles.stepDesc}>
                The documentation page includes an assistant that answers
                questions about IntelFeed in plain English — &ldquo;how do I
                watch a threat actor?&rdquo;, &ldquo;what does the priority
                queue rank on?&rdquo; — with links into the relevant guide
                pages.
              </p>
            </div>

            <div className={styles.skillCard}>
              <h4 className={styles.skillCardTitle}>Quick reference</h4>
              <p className={styles.stepDesc}>
                Press <code className={styles.inlineCode}>?</code> anywhere for
                keyboard shortcuts, and{" "}
                <code className={styles.inlineCode}>⌘K</code> to jump to any
                page, entity or action.
              </p>
            </div>
          </div>
        );

      case "skill":
        return (
          <div className={styles.body}>
            <h3 className={styles.stepTitle}>Claude Code Skill</h3>
            <p className={styles.stepDesc}>
              Query IntelFeed directly from Claude Code using the IntelFeed skill.
              Search entries, extract intelligence, generate detection rules, and more — all through natural language.
            </p>

            <div className={styles.skillCard}>
              <h4 className={styles.skillCardTitle}>1. Install the Skill</h4>
              <p className={styles.stepDesc}>
                Clone the skill into your Claude Code skills directory:
              </p>
              <div className={styles.codeBlock}>
                <code>git clone https://github.com/a-oneil/intelfeed-skill ~/Downloads/intelfeed-skill</code>
              </div>
            </div>

            <div className={styles.skillCard}>
              <h4 className={styles.skillCardTitle}>1a. Select the skill you want to use</h4>
              <p className={styles.stepDesc}>
                Setup the lite skill if you just want the agent to perform searches and retrieve content from intelfeed.
              </p>
              <div className={styles.codeBlock}>
                <code>cp -r ~/Downloads/intelfeed-skill/intelfeed-lite-skill ~/.claude/skills/intelfeed</code>
              </div>
              <p className={styles.stepDesc}>
                Setup the full skill if you need the agent to modify intelfeed configurations.
              </p>
              <div className={styles.codeBlock}>
                <code>cp -r ~/Downloads/intelfeed-skill/intelfeed-full-skill ~/.claude/skills/intelfeed</code>
              </div>
            </div>

            <div className={styles.skillCard}>
              <h4 className={styles.skillCardTitle}>2. Set Environment Variables</h4>
              <p className={styles.stepDesc}>
                Add these to your shell profile (
                <code className={styles.inlineCode}>.bashrc</code>,{" "}
                <code className={styles.inlineCode}>.zshrc</code>, etc.) so the skill can authenticate with your IntelFeed instance:
              </p>
              <div className={styles.codeBlock}>
                <code>export INTELFEED_API_URL={window.location.origin}</code>
                <code>export INTELFEED_USERNAME={user?.username || "your_username"}</code>
                <code>export INTELFEED_PASSWORD=your_password</code>
              </div>
            </div>

            <div className={styles.skillCard}>
              <h4 className={styles.skillCardTitle}>3. Reload Your Shell</h4>
              <p className={styles.stepDesc}>
                After saving the environment variables, reload your shell profile so they take effect:
              </p>
              <div className={styles.codeBlock}>
                <code>source ~/.zshrc  # or source ~/.bashrc</code>
              </div>
            </div>

            <div className={styles.skillCard}>
              <h4 className={styles.skillCardTitle}>4. Start Using It</h4>
              <p className={styles.stepDesc}>
                Once installed, ask Claude Code things like:
              </p>
              <ul className={styles.skillExamples}>
                <li>"Search for recent ransomware articles"</li>
                <li>"What TTPs are associated with APT29?"</li>
                <li>"Generate a Sigma rule for the latest CVE"</li>
                <li>"Show me the threat actor profile for Lazarus Group"</li>
                <li>"What campaigns are linked to Cobalt Strike?"</li>
              </ul>
            </div>
          </div>
        );
    }
  };

  return (
    <div className={styles.overlay}>
      <div className={styles.wizard} role="dialog" aria-modal="true" aria-label="Setup wizard">
        {renderStep()}
        <div className={styles.footer}>
          <div className={styles.steps}>
            {steps.map((s, i) => (
              <div
                key={s}
                className={`${styles.stepDot} ${i === stepIndex ? styles.active : ""} ${i < stepIndex ? styles.completed : ""}`}
              />
            ))}
          </div>
          <div className={styles.actions}>
            {step === "welcome" ? (
              <button className={styles.skipLink} onClick={dismiss}>
                Skip setup
              </button>
            ) : (
              <button className={styles.btnSecondary} onClick={prev}>
                Back
              </button>
            )}
            <button className={styles.btnPrimary} onClick={next}>
              {stepIndex === steps.length - 1 ? "Get Started" : "Next"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
