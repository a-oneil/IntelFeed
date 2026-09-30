import { useState, useRef, useCallback, useEffect, useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useAuthStore } from "@/stores/authStore";
import { useUIStore, type ReaderFontSize, type ReaderLineHeight, type ReaderMaxWidth, type ReadAloudEngine } from "@/stores/uiStore";
import { useAppSidebarAutoCollapse } from "@/hooks/useAppSidebarAutoCollapse";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { useUpdateProfile, useChangePassword } from "@/hooks/useAuth";
import { useExternalLinkSettings } from "@/hooks/useExternalLinkSettings";
import { BUILT_IN_TRUSTED_DOMAINS, type ExternalLinkMode } from "@/utils/externalLinks";
import { useUsers, useUpdateUser, useDeleteUser } from "@/hooks/useUsers";
import { useAutomationLogs, useClearAutomationLogs } from "@/hooks/useAutomation";
import { formatDate } from "@/utils/formatDate";
import { toast } from "sonner";
import api from "@/api/client";
import AISettings from "@/components/AISettings";
import { TagManager } from "@/components/TagManager";
import SystemSettings from "@/components/SystemSettings";
import { EngineSection } from "@/components/engine/EngineSection";
import ThemeSwitcher from "@/components/ThemeSwitcher";
import { FeedsImportPanel } from "@/components/FeedsImportPanel";
import { MyRadarCard } from "@/components/MyRadarCard";
import type { JobRunRow } from "@/hooks/useEngine";
import styles from "./SettingsPage.module.css";
import { Chip, MobileNavSheet, RailToggle } from "@/components/primitives";
import { ResizeHandle } from "@/components/ResizeHandle";
import { useRailWidth } from "@/hooks/useRailWidth";

/* Chip tints for automation-log statuses — status categories, not entity
   types, so they stay literals (see the --entity-* aliasing rule). */
const AL_STATUS_TINT: Record<string, string | undefined> = {
  success: "#22c55e",
  error: "#ef4444",
};

type SettingsSection =
  | "account"
  | "appearance"
  | "feeds"
  | "reading"
  | "ai"
  | "engine"
  | "system"
  | "logs"
  | "users"
  | "telegram"
  | "tags"
  | "skill";

type NavItem = { key: SettingsSection; label: string; icon: string; adminOnly?: boolean; keywords?: string[] };

// Grouped rather than flat: seven of the twelve sections are admin-only, so a
// flat list showed non-admins five items with unexplained gaps in the order.
// Fencing admin work into its own group means the list still reads as three
// intentional groups when those items are filtered out. Items are alphabetical
// within each group — there is no meaningful priority order between them, so
// the only orders left are "alphabetical" and "whatever was added last".
const NAV_GROUPS: { group: string; items: NavItem[] }[] = [
  {
    group: "You",
    items: [
      { key: "account", keywords: ["password", "username", "profile", "security"],  label: "Account", icon: "M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8z" },
      { key: "appearance", keywords: ["theme", "dark mode", "light mode", "colors", "density", "font"],  label: "Appearance", icon: "M12 2.69l5.66 5.66a8 8 0 1 1-11.31 0L12 2.69z" },
      { key: "reading", keywords: ["typography", "font size", "read aloud", "voice", "tts", "auto-read", "mark read", "view mode", "summaries", "translation"],  label: "Reading", icon: "M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2zM22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" },
      { key: "tags", keywords: ["labels", "organize", "tag colors"],  label: "Tags", icon: "M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82zM7 7h.01" },
    ],
  },
  {
    group: "Connect",
    items: [
      { key: "skill", keywords: ["cli", "api access", "token", "claude"],  label: "Claude Code Skill", icon: "M4 17l6-6-6-6M12 19h8" },
      { key: "feeds", keywords: ["opml", "export", "backup", "add feed", "categories", "fetch", "subscriptions", "ingest"],  label: "Feeds & Export", icon: "M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16M5 20a1 1 0 1 0 0-2 1 1 0 0 0 0 2z", adminOnly: true },
      { key: "telegram", keywords: ["channels", "listener", "session", "api id"],  label: "Telegram", icon: "M21 4L2 11l6 3 2 7 4-5 6 4 1-16z", adminOnly: true },
    ],
  },
  {
    group: "Administration",
    items: [
      { key: "ai", keywords: ["provider", "ollama", "openai", "model", "prompts", "tasks", "copilot", "cost", "budget"],  label: "AI Configuration", icon: "M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1.07A7 7 0 0 1 14 23h-4a7 7 0 0 1-6.93-4H2a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h1a7 7 0 0 1 7-7h1V5.73c-.6-.34-1-.99-1-1.73a2 2 0 0 1 2-2zM9 17a1 1 0 1 0 0-2 1 1 0 0 0 0 2zm6 0a1 1 0 1 0 0-2 1 1 0 0 0 0 2z", adminOnly: true },
      { key: "engine", keywords: ["pipeline", "ingest", "stages", "autolinking", "extraction", "enrichment", "feed health", "jobs", "schedules", "plans", "maintenance", "console"],  label: "Engine", icon: "M12 20a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41", adminOnly: true },
      { key: "logs", keywords: ["audit", "errors", "activity", "history"],  label: "Logs", icon: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M16 13H8M16 17H8M10 9H8", adminOnly: true },
      { key: "system", keywords: ["invite", "registration", "rate limit", "retention", "autolinker", "extraction", "thresholds", "signal engine", "embeddings", "ranking", "api keys", "jobs"],  label: "System", icon: "M5 12h14M12 5l7 7-7 7", adminOnly: true },
      { key: "users", keywords: ["accounts", "admin", "roles", "invite", "permissions"],  label: "Users", icon: "M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75", adminOnly: true },
    ],
  },
];

// Flat view of the same items — used to validate the ?section= deep link.
const NAV_ITEMS: NavItem[] = NAV_GROUPS.flatMap((g) => g.items);

export function SettingsPage() {
  const [searchParams] = useSearchParams();
  const [activeSection, setActiveSection] = useState<SettingsSection>("account");
  const user = useAuthStore((s) => s.user);
  const isAdmin = user?.role === "admin";
  const navCollapsed = useUIStore((s) => s.settingsNavCollapsed);
  const toggleSettingsNav = useUIStore((s) => s.toggleSettingsNav);
  const navRail = useRailWidth("settings-nav", { default: 220, min: 170, max: 420 });
  // Settings has its own nav rail; the app sidebar folds away beside it.
  useAppSidebarAutoCollapse();
  const isMobile = useIsMobile();

  useEffect(() => {
    let section = searchParams.get("section");
    // Legacy deep links: these sections were absorbed into Engine — the
    // EngineSection maps the old section id onto the matching console state,
    // so the query string is left untouched here.
    if (
      section === "schedules" ||
      section === "enrichment" ||
      section === "feed-health" ||
      section === "workbench"
    ) {
      section = "engine";
    }
    // Validate against the items this user can actually see, so a deep link to
    // an admin-only section falls back to the default instead of a blank pane.
    const item = section ? NAV_ITEMS.find((n) => n.key === section) : undefined;
    if (item && (!item.adminOnly || isAdmin)) {
      setActiveSection(item.key);
    }
  }, [searchParams, isAdmin]);

  // Drop admin-only items, then drop any group left empty by that filter.
  const visibleGroups = NAV_GROUPS
    .map((g) => ({ ...g, items: g.items.filter((i) => !i.adminOnly || isAdmin) }))
    .filter((g) => g.items.length > 0);

  // "Where do I change X?" has eleven possible answers — a filter box (same
  // pattern as the docs sidebar) narrows the nav by section name or by the
  // setting vocabulary each section covers.
  const [navFilter, setNavFilter] = useState("");
  const q = navFilter.trim().toLowerCase();
  const matchedKeyword = (item: NavItem): string | null => {
    if (!q) return null;
    if (item.label.toLowerCase().includes(q)) return null; // label match needs no hint
    return item.keywords?.find((k) => k.includes(q) || q.includes(k)) ?? null;
  };
  const itemMatches = (item: NavItem) =>
    !q || item.label.toLowerCase().includes(q) || !!matchedKeyword(item);
  const filteredGroups = visibleGroups
    .map((g) => ({ ...g, items: g.items.filter(itemMatches) }))
    .filter((g) => g.items.length > 0);

  // The nav is identical on both breakpoints; only its container differs — a
  // resizable column on desktop, a slide-over sheet behind a one-row trigger on
  // mobile, where laying it out inline cost the entire viewport.
  const activeLabel =
    visibleGroups.flatMap((g) => g.items).find((i) => i.key === activeSection)?.label ?? "Settings";

  // Just the one door out to the docs: the API references (Swagger, ReDoc)
  // moved onto the documentation landing page, which is also reachable from
  // the header on every route.
  const navSearch = (
    <input
      className={styles.navSearch}
      type="search"
      value={navFilter}
      onChange={(e) => setNavFilter(e.target.value)}
      placeholder="Search settings…"
      aria-label="Search settings"
    />
  );

  const navFooter = (
      <div className={styles.navFooter}>
        <Link to="/documentation" className={styles.navFooterLink}>
          <svg className={styles.navIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 7v14" />
            <path d="M3 18a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h5a4 4 0 0 1 4 4 4 4 0 0 1 4-4h5a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1h-6a3 3 0 0 0-3 3 3 3 0 0 0-3-3z" />
          </svg>
          <span>Documentation</span>
        </Link>
      </div>
  );

  const navContent = (
    <>
      {navSearch}
      {filteredGroups.map((group) => (
        <div key={group.group} className={styles.navGroup}>
          <h2 className={styles.navGroupLabel}>{group.group}</h2>
          <ul className={styles.navList}>
            {group.items.map((item) => (
              <li key={item.key}>
                <button
                  className={`${styles.navItem} ${activeSection === item.key ? styles.navItemActive : ""}`}
                  onClick={() => setActiveSection(item.key)}
                >
                  <svg className={styles.navIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                    <path d={item.icon} />
                  </svg>
                  <span>{item.label}</span>
                  {matchedKeyword(item) && (
                    <span className={styles.navMatchHint}>{matchedKeyword(item)}</span>
                  )}
                </button>
              </li>
            ))}
          </ul>
        </div>
      ))}
      {q && filteredGroups.length === 0 && (
        <p className={styles.navNoMatch}>
          No settings match &ldquo;{navFilter.trim()}&rdquo; — the{" "}
          <Link to="/documentation">documentation</Link> may cover it.
        </p>
      )}
      {/* The sheet is the only way to these on a phone — without them,
          Documentation and the API references were unreachable there. */}
      {navFooter}
    </>
  );

  const sectionContent = (
    <>
      {activeSection === "account" && <AccountSection />}
      {activeSection === "appearance" && <AppearanceSection />}
      {activeSection === "feeds" && isAdmin && <FeedsSection />}
      {activeSection === "reading" && <ReadingSection />}
      {activeSection === "tags" && <TagsSection />}
      {activeSection === "ai" && isAdmin && <AISection />}
      {activeSection === "engine" && isAdmin && <EngineHost />}
      {activeSection === "system" && isAdmin && <SystemSection />}
      {activeSection === "logs" && isAdmin && <LogsSection />}
      {activeSection === "users" && isAdmin && <UsersSection />}
      {activeSection === "telegram" && isAdmin && <TelegramSection />}
      {activeSection === "skill" && <SkillSection />}
    </>
  );

  if (isMobile) {
    return (
      <div className={styles.layout}>
        <MobileNavSheet title="Settings" current={activeLabel}>
          {navContent}
        </MobileNavSheet>
        <main className={`${styles.content} ${styles.contentFluid}`}>{sectionContent}</main>
      </div>
    );
  }

  return (
    <div className={styles.layout}>
      <nav
        className={`${styles.nav} ${navCollapsed ? styles.navCollapsed : ""}`}
        style={navCollapsed ? undefined : navRail.style}
      >
        {navSearch}
        {filteredGroups.map((group) => (
          <div key={group.group} className={styles.navGroup}>
            <h2 className={styles.navGroupLabel}>{group.group}</h2>
            <ul className={styles.navList}>
              {group.items.map((item) => (
                <li key={item.key}>
                  <button
                    className={`${styles.navItem} ${activeSection === item.key ? styles.navItemActive : ""}`}
                    onClick={() => setActiveSection(item.key)}
                  >
                    <svg className={styles.navIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                      <path d={item.icon} />
                    </svg>
                    <span>{item.label}</span>
                    {matchedKeyword(item) && (
                      <span className={styles.navMatchHint}>{matchedKeyword(item)}</span>
                    )}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ))}
        {q && filteredGroups.length === 0 && (
          <p className={styles.navNoMatch}>
            No settings match &ldquo;{navFilter.trim()}&rdquo; — the{" "}
            <Link to="/documentation">documentation</Link> may cover it.
          </p>
        )}
        {navFooter}
      </nav>
      {!navCollapsed && (
        <ResizeHandle label="settings menu" {...navRail.handleProps} />
      )}
      <RailToggle
        side="left"
        collapsed={navCollapsed}
        onToggle={toggleSettingsNav}
        label="settings menu"
      />
      <main className={`${styles.content} ${navCollapsed ? styles.contentFluid : ""}`}>
        {sectionContent}
      </main>
    </div>
  );
}

/* ─── Tags ────────────────────────────────────────────── */

function TagsSection() {
  return (
    <div className={styles.sectionContent}>
      <h2 className={styles.sectionTitle}>Tags</h2>
      <p className={styles.sectionDesc}>
        Rename, recolor, merge, or delete tags across every article at once.
      </p>

      <TagManager />
    </div>
  );
}

/* ─── Account ─────────────────────────────────────────── */

function AccountSection() {
  const user = useAuthStore((s) => s.user);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [passwordMsg, setPasswordMsg] = useState<string | null>(null);
  const changePassword = useChangePassword();

  const handlePasswordChange = async () => {
    if (!currentPassword || !newPassword) return;
    try {
      setPasswordMsg(null);
      await changePassword.mutateAsync({
        current_password: currentPassword,
        new_password: newPassword,
      });
      setCurrentPassword("");
      setNewPassword("");
      setPasswordMsg("Password changed successfully");
    } catch (err) {
      setPasswordMsg(extractErrorMsg(err));
    }
  };

  return (
    <div className={styles.sectionContent}>
      <h2 className={styles.sectionTitle}>Account</h2>
      <p className={styles.sectionDesc}>Manage your profile and security settings.</p>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>Profile</h3>
        <div className={styles.fieldGroup}>
          <div className={styles.field}>
            <label className={styles.label}>Username</label>
            <span className={styles.staticValue}>{user?.username}</span>
          </div>
          <div className={styles.field}>
            <label className={styles.label}>Role</label>
            <span className={styles.staticValue}>
              <Chip className={styles.badge}>{user?.role}</Chip>
            </span>
          </div>
          <div className={styles.field}>
            <label className={styles.label}>Member since</label>
            <span className={styles.staticValue}>
              {user?.created_at
                ? new Date(user.created_at).toLocaleDateString(undefined, {
                    year: "numeric",
                    month: "long",
                    day: "numeric",
                  })
                : "—"}
            </span>
          </div>
        </div>
      </div>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>Change Password</h3>
        <div className={styles.fieldGroup}>
          <div className={styles.field}>
            <label className={styles.label}>Current Password</label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className={styles.input}
              placeholder="Enter current password"
            />
          </div>
          <div className={styles.field}>
            <label className={styles.label}>New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className={styles.input}
              placeholder="Enter new password"
            />
          </div>
        </div>
        <div className={styles.cardActions}>
          <button
            onClick={handlePasswordChange}
            disabled={changePassword.isPending || !currentPassword || !newPassword}
            className={styles.btnPrimary}
          >
            {changePassword.isPending ? "Changing..." : "Change Password"}
          </button>
          {passwordMsg && (
            <span className={passwordMsg === "Password changed successfully" ? styles.successMsg : styles.confirmText}>
              {passwordMsg}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

/* ─── Appearance ──────────────────────────────────────── */

function AppearanceSection() {
  return (
    <div className={styles.sectionContent}>
      <h2 className={styles.sectionTitle}>Appearance</h2>
      <p className={styles.sectionDesc}>Customize the look and feel of IntelFeed.</p>

      <div className={styles.card}>
        <ThemeSwitcher />
      </div>
    </div>
  );
}

/* ─── Feeds & Export ──────────────────────────────────── */

/* ─── Reading Preferences ─────────────────────────────── */

function ReadingSection() {
  const user = useAuthStore((s) => s.user);
  const updateProfile = useUpdateProfile();
  const [saveMsg, setSaveMsg] = useState<string | null>(null);

  const getSetting = useCallback(
    (key: string, fallback: unknown) => {
      return (user?.settings as Record<string, unknown>)?.[key] ?? fallback;
    },
    [user?.settings]
  );

  const updateSetting = async (key: string, value: unknown) => {
    try {
      setSaveMsg(null);
      const newSettings = { ...(user?.settings || {}), [key]: value };
      await updateProfile.mutateAsync({ settings: newSettings });
      setSaveMsg("Saved");
      setTimeout(() => setSaveMsg(null), 2000);
    } catch {
      setSaveMsg("Failed to save");
    }
  };

  return (
    <div className={styles.sectionContent}>
      <h2 className={styles.sectionTitle}>Reading</h2>
      <p className={styles.sectionDesc}>
        Customize how you read and interact with feed entries.
        {saveMsg && <span className={styles.autoSaveIndicator}>{saveMsg}</span>}
      </p>

      <MyRadarCard />

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>Display</h3>

        <div className={styles.settingRow}>
          <div className={styles.settingInfo}>
            <span className={styles.settingLabel}>Default view</span>
            <span className={styles.settingHint}>
              Choose which entries to show when opening a feed.
            </span>
          </div>
          <select
            className={styles.select}
            value={getSetting("default_view", "all") as string}
            onChange={(e) => updateSetting("default_view", e.target.value)}
          >
            <option value="all">All entries</option>
            <option value="unread">Unread only</option>
          </select>
        </div>

        <div className={styles.settingRow}>
          <div className={styles.settingInfo}>
            <span className={styles.settingLabel}>Entries per page</span>
            <span className={styles.settingHint}>
              Number of entries to load at a time.
            </span>
          </div>
          <select
            className={styles.select}
            value={getSetting("entries_per_page", 50) as number}
            onChange={(e) => updateSetting("entries_per_page", Number(e.target.value))}
          >
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
        </div>

        <div className={styles.settingRow}>
          <div className={styles.settingInfo}>
            <span className={styles.settingLabel}>Default sort order</span>
            <span className={styles.settingHint}>
              How entries are ordered in the feed list.
            </span>
          </div>
          <select
            className={styles.select}
            value={getSetting("default_sort", "newest") as string}
            onChange={(e) => updateSetting("default_sort", e.target.value)}
          >
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first</option>
          </select>
        </div>

        <div className={styles.settingRow}>
          <div className={styles.settingInfo}>
            <span className={styles.settingLabel}>Date format</span>
            <span className={styles.settingHint}>
              How timestamps are displayed throughout the app.
            </span>
          </div>
          <select
            className={styles.select}
            value={getSetting("date_format", "relative") as string}
            onChange={(e) => updateSetting("date_format", e.target.value)}
          >
            <option value="relative">Relative (2 hours ago)</option>
            <option value="absolute">Absolute (Mar 11, 2026)</option>
            <option value="both">Both</option>
          </select>
        </div>
      </div>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>Behavior</h3>

        <div className={styles.settingRow}>
          <div className={styles.settingInfo}>
            <span className={styles.settingLabel}>Open links in new tab</span>
            <span className={styles.settingHint}>
              Article links open in a new browser tab instead of navigating away.
            </span>
          </div>
          <label className={styles.toggle}>
            <input
              type="checkbox"
              checked={getSetting("open_links_new_tab", true) as boolean}
              onChange={(e) => updateSetting("open_links_new_tab", e.target.checked)}
            />
            <span className={styles.toggleSlider} />
          </label>
        </div>

        <div className={styles.settingRow}>
          <div className={styles.settingInfo}>
            <span className={styles.settingLabel}>Mark read on scroll</span>
            <span className={styles.settingHint}>
              Automatically mark entries as read as you scroll past them.
            </span>
          </div>
          <label className={styles.toggle}>
            <input
              type="checkbox"
              checked={getSetting("mark_read_on_scroll", false) as boolean}
              onChange={(e) => updateSetting("mark_read_on_scroll", e.target.checked)}
            />
            <span className={styles.toggleSlider} />
          </label>
        </div>

        <div className={styles.settingRow}>
          <div className={styles.settingInfo}>
            <span className={styles.settingLabel}>Show entry previews</span>
            <span className={styles.settingHint}>
              Display a content snippet below each entry title in the list.
            </span>
          </div>
          <label className={styles.toggle}>
            <input
              type="checkbox"
              checked={getSetting("show_entry_preview", true) as boolean}
              onChange={(e) => updateSetting("show_entry_preview", e.target.checked)}
            />
            <span className={styles.toggleSlider} />
          </label>
        </div>

        <div className={styles.settingRow}>
          <div className={styles.settingInfo}>
            <span className={styles.settingLabel}>Compact view</span>
            <span className={styles.settingHint}>
              Reduce spacing for a denser entry list.
            </span>
          </div>
          <label className={styles.toggle}>
            <input
              type="checkbox"
              checked={getSetting("compact_view", false) as boolean}
              onChange={(e) => updateSetting("compact_view", e.target.checked)}
            />
            <span className={styles.toggleSlider} />
          </label>
        </div>

      </div>

      <ExternalLinksCard />

      <ReaderTypographySettings />
    </div>
  );
}

function ExternalLinksCard() {
  const { mode, trustedHosts, saving, setMode, untrustHost } = useExternalLinkSettings();

  const run = async (action: () => Promise<unknown>) => {
    try {
      await action();
    } catch {
      toast.error("Couldn't save that setting");
    }
  };

  return (
    <div className={styles.card}>
      <h3 className={styles.cardTitle}>External links</h3>

      <div className={styles.settingRow}>
        <div className={styles.settingInfo}>
          <span className={styles.settingLabel}>Confirm before leaving IntelFeed</span>
          <span className={styles.settingHint}>
            Shows where a link really goes before you follow it, and warns when the link text
            names a different site. Article content comes straight from the feed, so it is the
            default scope.
          </span>
        </div>
        <select
          className={styles.select}
          value={mode}
          disabled={saving}
          aria-label="Confirm before leaving IntelFeed"
          onChange={(e) => run(() => setMode(e.target.value as ExternalLinkMode))}
        >
          <option value="article">Article content</option>
          <option value="all">All external links</option>
          <option value="off">Off</option>
        </select>
      </div>

      <div className={styles.settingRow}>
        <div className={styles.settingInfo}>
          <span className={styles.settingLabel}>Trusted sites</span>
          <span className={styles.settingHint}>
            Never asked about: {BUILT_IN_TRUSTED_DOMAINS.join(", ")} (and their subdomains), the
            sites of your own feeds, and anything you add with &ldquo;Don&apos;t ask again&rdquo;.
            A link whose text names a different site is always confirmed.
          </span>
        </div>
      </div>

      {trustedHosts.length > 0 ? (
        <ul className={styles.trustedList}>
          {trustedHosts.map((host) => (
            <li key={host} className={styles.trustedItem}>
              <code>{host}</code>
              <button
                type="button"
                className={styles.trustedRemove}
                disabled={saving}
                aria-label={`Stop trusting ${host}`}
                onClick={() => run(() => untrustHost(host))}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <span className={styles.settingHint}>You haven&apos;t added any trusted sites yet.</span>
      )}
    </div>
  );
}

function ReaderTypographySettings() {
  const fontSize = useUIStore((s) => s.readerFontSize);
  const lineHeight = useUIStore((s) => s.readerLineHeight);
  const maxWidth = useUIStore((s) => s.readerMaxWidth);
  const setFontSize = useUIStore((s) => s.setReaderFontSize);
  const setLineHeight = useUIStore((s) => s.setReaderLineHeight);
  const setMaxWidth = useUIStore((s) => s.setReaderMaxWidth);
  const readAloudEngine = useUIStore((s) => s.readAloudEngine);
  const setReadAloudEngine = useUIStore((s) => s.setReadAloudEngine);

  return (
    <div className={styles.card}>
      <h3 className={styles.cardTitle}>Reader Typography</h3>

      <div className={styles.settingRow}>
        <div className={styles.settingInfo}>
          <span className={styles.settingLabel}>Font size</span>
          <span className={styles.settingHint}>
            Text size in the article reader panel.
          </span>
        </div>
        <select
          className={styles.select}
          value={fontSize}
          onChange={(e) => setFontSize(Number(e.target.value) as ReaderFontSize)}
        >
          <option value={13}>13px — Small</option>
          <option value={14}>14px</option>
          <option value={15}>15px</option>
          <option value={16}>16px — Default</option>
          <option value={18}>18px</option>
          <option value={20}>20px — Large</option>
        </select>
      </div>

      <div className={styles.settingRow}>
        <div className={styles.settingInfo}>
          <span className={styles.settingLabel}>Line spacing</span>
          <span className={styles.settingHint}>
            Space between lines of text in articles.
          </span>
        </div>
        <select
          className={styles.select}
          value={lineHeight}
          onChange={(e) => setLineHeight(Number(e.target.value) as ReaderLineHeight)}
        >
          <option value={1.4}>Tight (1.4)</option>
          <option value={1.6}>Normal (1.6)</option>
          <option value={1.7}>Relaxed (1.7) — Default</option>
          <option value={1.8}>Loose (1.8)</option>
          <option value={2.0}>Double (2.0)</option>
        </select>
      </div>

      <div className={styles.settingRow}>
        <div className={styles.settingInfo}>
          <span className={styles.settingLabel}>Content width</span>
          <span className={styles.settingHint}>
            Maximum width of article content for readability.
          </span>
        </div>
        <select
          className={styles.select}
          value={maxWidth}
          onChange={(e) => setMaxWidth(Number(e.target.value) as ReaderMaxWidth)}
        >
          <option value={600}>Narrow (600px)</option>
          <option value={720}>Default (720px)</option>
          <option value={860}>Wide (860px)</option>
          <option value={1000}>Extra wide (1000px)</option>
          <option value={0}>Full width</option>
        </select>
      </div>

      <div className={styles.settingRow}>
        <div className={styles.settingInfo}>
          <span className={styles.settingLabel}>Read-aloud voice</span>
          <span className={styles.settingHint}>
            Natural voice synthesizes a consistent voice on the server (first play
            takes a few seconds). Browser voice is instant and works offline, but
            sounds different on each device.
          </span>
        </div>
        <select
          className={styles.select}
          value={readAloudEngine}
          onChange={(e) => setReadAloudEngine(e.target.value as ReadAloudEngine)}
        >
          <option value="piper">Natural voice (server)</option>
          <option value="browser">Browser voice</option>
        </select>
      </div>
    </div>
  );
}

/* ─── AI ──────────────────────────────────────────────── */

function AISection() {
  return (
    <div className={styles.sectionContent}>
      <h2 className={styles.sectionTitle}>AI Configuration</h2>
      <p className={styles.sectionDesc}>
        Manage AI providers, assign models to tasks, edit prompts, and monitor costs.
      </p>

      <AISettings />
    </div>
  );
}

/* ─── Feeds & Export ─────────────────────────────────── */

function FeedsSection() {
  return <FeedsImportPanel />;
}

/* ─── Engine (absorbs Enrichment + Job Schedules + Feed Health) ── */

function EngineHost() {
  return (
    <div className={styles.sectionContent}>
      <h2 className={styles.sectionTitle}>Engine</h2>
      <p className={styles.sectionDesc}>
        The ingestion pipeline: what came in, what was linked, and what each stage decided —
        feed health, stage settings, AI extraction, enrichment, hygiene, scheduled jobs and plans.
      </p>
      <EngineSection />
    </div>
  );
}

/* ─── System ─────────────────────────────────────────── */

function SystemSection() {
  const user = useAuthStore((s) => s.user);
  const [rebuildStatus, setRebuildStatus] = useState<string | null>(null);
  const [rebuilding, setRebuilding] = useState(false);
  const [entitySyncStatus, setEntitySyncStatus] = useState<string | null>(null);
  const [syncingEntities, setSyncingEntities] = useState(false);
  const [revalidateStatus, setRevalidateStatus] = useState<string | null>(null);
  const [revalidating, setRevalidating] = useState(false);
  const isAdmin = user?.role === "admin";

  const handleRevalidateAutolinks = async () => {
    setRevalidating(true);
    setRevalidateStatus(null);
    try {
      const res = await api.post("/autolink/revalidate");
      setRevalidateStatus(`Queued (task ${res.data.task_id?.slice(0, 8)}…) — stale links will be cleaned up in the background.`);
    } catch {
      setRevalidateStatus("Failed to queue revalidation");
    } finally {
      setRevalidating(false);
    }
  };

  const handleRebuildSearch = async () => {
    setRebuilding(true);
    setRebuildStatus(null);
    try {
      const res = await api.post("/search/rebuild");
      setRebuildStatus(`Queued (task ${res.data.task_id?.slice(0, 8)}…) — search index will rebuild in the background.`);
    } catch {
      setRebuildStatus("Failed to queue search index rebuild");
    } finally {
      setRebuilding(false);
    }
  };

  const handleSyncEntities = async () => {
    setSyncingEntities(true);
    setEntitySyncStatus(null);
    try {
      const res = await api.post("/search/entities/sync");
      setEntitySyncStatus(`Queued (task ${res.data.task_id?.slice(0, 8)}…) — entity indexes will sync in the background.`);
    } catch {
      setEntitySyncStatus("Failed to queue entity index sync");
    } finally {
      setSyncingEntities(false);
    }
  };

  return (
    <div className={styles.sectionContent}>
      <h2 className={styles.sectionTitle}>System</h2>
      <p className={styles.sectionDesc}>
        Infrastructure settings and administrative maintenance tools.
      </p>

      <SystemSettings filterGroups={["monitoring", "backup"]} />

      {isAdmin && (
        <>
          <h3 className={styles.cardTitle} style={{ marginTop: "1.5rem" }}>Maintenance</h3>

          <div className={styles.card}>
            <h3 className={styles.cardTitle}>Rebuild Search Index</h3>
            <p className={styles.hint}>
              Clears the search index and re-indexes all entries from the database.
              Use this to fix stale results from deleted feeds or missing entries.
            </p>
            <div className={styles.cardActions}>
              <button
                onClick={handleRebuildSearch}
                disabled={rebuilding}
                className={styles.btnPrimary}
              >
                {rebuilding ? "Rebuilding..." : "Rebuild Entry Index"}
              </button>
              {rebuildStatus && <span className={styles.successMsg}>{rebuildStatus}</span>}
            </div>
          </div>

          <div className={styles.card}>
            <h3 className={styles.cardTitle}>Sync Entity Indexes</h3>
            <p className={styles.hint}>
              Re-syncs all intelligence entities (IOCs, CVEs, TTPs, threat actors, malware,
              countries, mitigations, weaknesses, tools) to the search index.
            </p>
            <div className={styles.cardActions}>
              <button
                onClick={handleSyncEntities}
                disabled={syncingEntities}
                className={styles.btnPrimary}
              >
                {syncingEntities ? "Syncing..." : "Sync Entity Indexes"}
              </button>
              {entitySyncStatus && <span className={styles.successMsg}>{entitySyncStatus}</span>}
            </div>
          </div>

          <div className={styles.card}>
            <h3 className={styles.cardTitle}>Revalidate Autolinks</h3>
            <p className={styles.hint}>
              Scans all auto-linked entries and removes stale links whose entity no longer
              matches the current vocabulary or false-positive rules. Corrects article counts
              on affected entities. Runs as a background Celery task.
            </p>
            <div className={styles.cardActions}>
              <button
                onClick={handleRevalidateAutolinks}
                disabled={revalidating}
                className={styles.btnPrimary}
              >
                {revalidating ? "Queueing..." : "Revalidate Autolinks"}
              </button>
              {revalidateStatus && <span className={styles.successMsg}>{revalidateStatus}</span>}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

/* ─── Logs ───────────────────────────────────────────── */

interface LogFileMeta {
  name: string;
  size: number;
  modified: string;
}

const LOG_FILE_LABELS: Record<string, { label: string; description: string }> = {
  "app.log": { label: "Application", description: "Application logs (worker/task logs live under Tasks)" },
  "error.log": { label: "Errors", description: "Errors and exceptions" },
  "http.log": { label: "HTTP", description: "API request logs" },
  "tasks.log": { label: "Tasks", description: "Scheduled job run history + raw Celery worker/beat logs" },
  "audit.log": { label: "Audit", description: "Mutating API action trail" },
  "update.log": { label: "Updates", description: "Deployment update history" },
};

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

// Fields to omit from the key=value detail section
const LOG_SKIP_FIELDS = new Set([
  "timestamp", "level", "logger", "event", "exc_info",
  "task_id", "task_name",
]);

const LOG_HTTP_FIELDS = new Set(["method", "path", "status", "duration_ms"]);
const LOG_AUDIT_FIELDS = new Set(["action", "path", "status", "user", "client"]);

// Strip celery task UUIDs from event text
const CELERY_TASK_RE = /\[[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}\]/gi;

type LogLevel = "error" | "warning" | "info" | "debug";

interface ParsedLogLine {
  timestamp: string;
  level: LogLevel;
  event: string;
  details: string;
  // Epoch ms for chronological merging of DB-backed lines (job runs) into
  // file lines; continuation lines inherit the previous line's epoch.
  epoch?: number;
}

function formatLogTs(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false,
  });
}

const ALL_LEVELS: LogLevel[] = ["error", "warning", "info", "debug"];

const LEVEL_LABELS: Record<LogLevel, string> = {
  error: "ERR", warning: "WRN", info: "INF", debug: "DBG",
};

/* Chip tints for log levels. These are log SEVERITY CATEGORIES of a
   third-party logger, not the app's entity vocabulary and not the
   --severity-* ramp (which is theme-managed and reserved for CVE/rule
   severity), so they stay literals rather than aliasing either. They are the
   exact colours the old .logLvl_* classes carried. */
const LEVEL_TINT: Record<LogLevel, string> = {
  error: "#ef4444", warning: "#f59e0b", info: "#3b82f6", debug: "#6b7280",
};

function inferLevel(event: string): LogLevel {
  const e = event.toLowerCase();
  if (e.includes("failed") || e.includes("error") || e.includes("exception") || e.includes("rejected") || e.includes("traceback")) return "error";
  if (e.includes("retry") || e.includes("warning") || e.includes("warn")) return "warning";
  if (e.includes("received") || e.includes("scheduler: sending")) return "debug";
  return "info";
}

function parseLogLine(raw: string): ParsedLogLine | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  if (!trimmed.startsWith("{")) {
    return { timestamp: "", level: inferLevel(trimmed), event: trimmed, details: "" };
  }

  try {
    const obj = JSON.parse(trimmed);

    // Filter /api/logs polling noise
    if (typeof obj.path === "string" && obj.path.startsWith("/api/logs")) return null;

    // Celery lifecycle boilerplate: success/received/dispatch chatter is fully
    // covered by the structured views (job_runs rows in this tab, per-entry
    // stage runs in the reader popover). Failures and task log output stay.
    const ev = typeof obj.event === "string" ? obj.event : "";
    if (
      (obj.logger === "celery.app.trace" && ev.includes("succeeded in")) ||
      (obj.logger === "celery.worker.strategy" && ev.endsWith("received")) ||
      (obj.logger === "celery.beat" && ev.startsWith("Scheduler: Sending due task"))
    ) {
      return null;
    }

    const ts = obj.timestamp ? formatLogTs(obj.timestamp) : "";
    const epoch = obj.timestamp ? new Date(obj.timestamp).getTime() : undefined;

    const level: LogLevel =
      obj.level === "error" || obj.level === "critical" ? "error" :
      obj.level === "warning" ? "warning" :
      obj.level === "debug" ? "debug" :
      obj.level === "info" ? "info" :
      inferLevel(obj.event || "");

    let event: string;
    let skipFields: Set<string>;

    if (obj.method && obj.path) {
      // HTTP request log
      const dur = obj.duration_ms != null ? ` (${obj.duration_ms}ms)` : "";
      event = `${obj.method} ${obj.path} → ${obj.status || ""}${dur}`;
      skipFields = new Set([...LOG_SKIP_FIELDS, ...LOG_HTTP_FIELDS]);
    } else if (obj.action && obj.path && obj.user) {
      // Audit log
      event = `${obj.action} ${obj.path} → ${obj.status || ""} by ${obj.user}`;
      skipFields = new Set([...LOG_SKIP_FIELDS, ...LOG_AUDIT_FIELDS]);
    } else {
      event = (obj.event || "").replace(CELERY_TASK_RE, "");
      skipFields = LOG_SKIP_FIELDS;
    }

    const details = Object.entries(obj)
      .filter(([k]) => !skipFields.has(k))
      .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
      .join("  ");

    return { timestamp: ts, level, event, details, epoch };
  } catch {
    return { timestamp: "", level: "info", event: trimmed, details: "" };
  }
}

function parseLogContent(raw: string): ParsedLogLine[] {
  if (!raw) return [];
  const lines = raw.split("\n")
    .map(parseLogLine)
    .filter((line): line is ParsedLogLine => line !== null);
  // Continuation lines (tracebacks, non-JSON) inherit the previous line's
  // epoch so chronological merging keeps them adjacent.
  let lastEpoch = 0;
  for (const line of lines) {
    if (line.epoch != null) {
      lastEpoch = line.epoch;
    } else {
      lastEpoch += 1;
      line.epoch = lastEpoch;
    }
  }
  return lines;
}

const fmtRunValue = (v: unknown): string =>
  v != null && typeof v === "object" ? JSON.stringify(v) : String(v);

/** One-line "what it ran against / what it did" from JobRun.detail. */
function summarizeRunDetail(detail: JobRunRow["detail"]): string {
  if (!detail) return "";
  const parts: string[] = [];
  if (detail.result != null) {
    if (typeof detail.result === "object" && !Array.isArray(detail.result)) {
      parts.push(
        Object.entries(detail.result as Record<string, unknown>)
          .slice(0, 5)
          .map(([k, v]) => `${k}=${fmtRunValue(v)}`)
          .join(", "),
      );
    } else {
      parts.push(fmtRunValue(detail.result));
    }
  }
  const inputs: string[] = [];
  if (detail.args?.length) inputs.push(detail.args.map(fmtRunValue).join(", "));
  if (detail.kwargs && Object.keys(detail.kwargs).length) {
    inputs.push(
      Object.entries(detail.kwargs)
        .map(([k, v]) => `${k}=${fmtRunValue(v)}`)
        .join(", "),
    );
  }
  if (inputs.length) parts.push(`on ${inputs.join(", ")}`);
  return parts.join(" · ");
}

/** A scheduled-job run (job_runs table) rendered as a log line — same shape as
 *  the parsed tasks.log lines so it flows through the level/search filters. */
function jobRunToLogLine(run: JobRunRow): ParsedLogLine {
  const dur = run.duration_ms != null ? ` (${run.duration_ms}ms)` : "";
  const details: string[] = [];
  const summary = summarizeRunDetail(run.detail);
  if (summary) details.push(summary);
  if (run.error) details.push(`error=${run.error.slice(0, 200)}`);
  return {
    timestamp: run.finished_at ? formatLogTs(run.finished_at) : "",
    epoch: run.finished_at ? new Date(run.finished_at).getTime() : 0,
    level: run.status === "error" ? "error" : run.status === "retry" ? "warning" : "info",
    event: `job ${run.job_key ?? run.task_name.split(".").pop()} ${run.status}${dur}`,
    details: details.join("  "),
  };
}

/** Highlight all occurrences of `query` in `text` */
function highlightText(text: string, query: string): React.ReactNode {
  if (!query) return text;
  const lower = text.toLowerCase();
  const qLower = query.toLowerCase();
  const parts: React.ReactNode[] = [];
  let last = 0;
  let idx = lower.indexOf(qLower);
  while (idx !== -1) {
    if (idx > last) parts.push(text.slice(last, idx));
    parts.push(<mark key={idx} className={styles.logHighlight}>{text.slice(idx, idx + query.length)}</mark>);
    last = idx + query.length;
    idx = lower.indexOf(qLower, last);
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts.length > 0 ? <>{parts}</> : text;
}

const AUTOMATION_LOG_LIMIT = 500;

type ActionRecord = Record<string, unknown>;

function formatActionType(type: string): string {
  return (type ?? "unknown")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function collapseActions(
  actions: ActionRecord[]
): Array<{ action: ActionRecord; count: number }> {
  const groups: Array<{ action: ActionRecord; count: number }> = [];
  for (const a of actions) {
    const key = `${a.type}|${a.status}`;
    const last = groups[groups.length - 1];
    const lastKey = last ? `${last.action.type}|${last.action.status}` : "";
    if (last && lastKey === key) {
      last.count++;
    } else {
      groups.push({ action: { ...a }, count: 1 });
    }
  }
  return groups;
}

function summarizeActions(actions: ActionRecord[]): string {
  if (actions.length === 0) return "";
  const counts: Record<string, number> = {};
  for (const a of actions) {
    const status = (a.status as string) ?? "unknown";
    counts[status] = (counts[status] ?? 0) + 1;
  }
  return Object.entries(counts)
    .map(([s, n]) => `${n} ${s}`)
    .join(", ");
}

function AutomationActionDetails({ action, count }: { action: ActionRecord; count: number }) {
  const details: string[] = [];
  if (action.task) details.push(`Task: ${action.task}`);
  if (action.entries_processed != null) details.push(`${action.entries_processed} entries processed`);
  if (action.platform) {
    let line = `Platform: ${action.platform}`;
    if (action.channel) line += ` / ${action.channel}`;
    details.push(line);
  }
  if (action.entries_included != null) details.push(`${action.entries_included} entries included`);
  if (action.has_ai_summary || action.included_ai_summary) details.push("Includes AI summary");
  if (Array.isArray(action.tags_added) && (action.tags_added as string[]).length > 0) {
    details.push(`Tags: ${(action.tags_added as string[]).join(", ")}`);
  }
  if (action.priority) details.push(`Priority: ${action.priority}`);
  if (action.http_status != null) details.push(`HTTP ${action.http_status}`);
  if (action.message) details.push(String(action.message));
  if (action.error) details.push(String(action.error));
  if (count > 1) details.push(`(x${count} entries)`);
  if (details.length === 0) return null;
  return (
    <>
      {details.map((d, i) => (
        <span key={i} className={action.error && d === String(action.error) ? styles.alError : styles.alActionDetail}>
          {d}
        </span>
      ))}
    </>
  );
}

function AutomationLogsPanel() {
  const [hideSkipped, setHideSkipped] = useState(true);
  const [expandedLogs, setExpandedLogs] = useState<Set<string>>(new Set());
  const clearLogs = useClearAutomationLogs();

  const excludeStatus = hideSkipped ? "skipped" : undefined;
  const { data: logsData } = useAutomationLogs(undefined, 0, AUTOMATION_LOG_LIMIT, excludeStatus);

  const logs = useMemo(() => [...(logsData?.items ?? [])].reverse(), [logsData]);
  const logsTotal = logsData?.total ?? 0;
  const rowsRef = useRef<HTMLDivElement>(null);

  const toggleLogExpand = useCallback((logId: string) => {
    setExpandedLogs((prev) => {
      const next = new Set(prev);
      if (next.has(logId)) next.delete(logId); else next.add(logId);
      return next;
    });
  }, []);

  // Scroll to bottom on load
  useEffect(() => {
    if (rowsRef.current) rowsRef.current.scrollTop = rowsRef.current.scrollHeight;
  }, [logs]);

  return (
    <div className={styles.logPanel}>
      <div className={styles.logToolbar}>
        <div className={styles.logToolbarLeft}>
          <span className={styles.logFileName}>Automation Execution Logs</span>
          <span className={styles.logFileMeta}>{logsTotal} total</span>
        </div>
        <div className={styles.logToolbarRight}>
          <label className={styles.logAutoRefresh} title="Hide skipped automation runs">
            <input
              type="checkbox"
              checked={hideSkipped}
              onChange={(e) => setHideSkipped(e.target.checked)}
            />
            <span>Hide skipped</span>
          </label>
          {logsTotal > 0 && (
            <button
              className={styles.logToolbarBtn}
              onClick={() => {
                if (confirm("Clear all execution logs? This cannot be undone.")) {
                  clearLogs.mutate(undefined, {
                    onSuccess: () => {
                      setExpandedLogs(new Set());
                      toast.success("Execution logs cleared");
                    },
                  });
                }
              }}
              disabled={clearLogs.isPending}
            >
              {clearLogs.isPending ? "Clearing..." : "Clear All"}
            </button>
          )}
        </div>
      </div>

      <div ref={rowsRef} className={styles.logRows}>
        {logs.length === 0 && (
          <div className={styles.logEmpty}>No automation activity yet.</div>
        )}
        {logs.map((log) => {
          const isExpanded = expandedLogs.has(log.id);
          const actions = log.actions_executed ?? [];
          const actionSummary = summarizeActions(actions);
          const collapsed = collapseActions(actions);
          return (
            <div key={log.id} className={styles.alItem}>
              <button
                className={styles.alEntry}
                onClick={() => toggleLogExpand(log.id)}
                type="button"
              >
                <span className={styles.alExpandIcon} data-expanded={isExpanded}>&#9656;</span>
                <Chip
                  tone={AL_STATUS_TINT[log.status] ? "toned" : "default"}
                  tint={AL_STATUS_TINT[log.status]}
                >
                  {log.status}
                </Chip>
                <span className={styles.alTime}>{formatDate(log.executed_at, "Never")}</span>
                {log.rule_name && <span className={styles.alRuleName}>{log.rule_name}</span>}
                <span className={styles.alTrigger}>{log.trigger_type}</span>
                {actionSummary && <span className={styles.alSummary}>{actionSummary}</span>}
                {log.error_message && <span className={styles.alError}>{log.error_message}</span>}
              </button>
              {isExpanded && (
                <div className={styles.alDetails}>
                  {actions.length === 0 && <span className={styles.muted}>No actions recorded.</span>}
                  {collapsed.map((group, i) => (
                    <div key={i} className={styles.alAction}>
                      <div className={styles.alActionHeader}>
                        <span className={styles.alActionType}>{formatActionType(group.action.type as string)}</span>
                        <Chip
                          size="sm"
                          tone={AL_STATUS_TINT[group.action.status as string] ? "toned" : "default"}
                          tint={AL_STATUS_TINT[group.action.status as string]}
                        >
                          {group.action.status as string}
                        </Chip>
                        {group.count > 1 && <span className={styles.alActionCount}>x{group.count}</span>}
                      </div>
                      <AutomationActionDetails action={group.action} count={group.count} />
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function LogsSection() {
  const [files, setFiles] = useState<LogFileMeta[]>([]);
  const [activeTab, setActiveTab] = useState<string>("automation");
  const [content, setContent] = useState("");
  const [jobRunLines, setJobRunLines] = useState<ParsedLogLine[]>([]);
  const [loading, setLoading] = useState(false);
  const [lineCount, setLineCount] = useState(500);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [hiddenLevels, setHiddenLevels] = useState<Set<LogLevel>>(new Set());
  const rowsRef = useRef<HTMLDivElement>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const isFileTab = activeTab !== "automation";
  const activeFile = isFileTab ? activeTab : null;

  const fetchFiles = useCallback(async () => {
    try {
      const res = await api.get<{ files: LogFileMeta[] }>("/logs");
      setFiles(res.data.files);
    } catch {
      /* swallow */
    }
  }, []);

  const fetchContent = useCallback(async (filename: string) => {
    setLoading(true);
    try {
      const res = await api.get(`/logs/${filename}`, {
        params: { lines: lineCount },
        responseType: "text",
        transformResponse: [(data: unknown) => data],
      });
      setContent(typeof res.data === "string" ? res.data : String(res.data ?? ""));
    } catch {
      setContent("Failed to load log file.");
    } finally {
      setLoading(false);
    }
    // The Tasks view interleaves the structured job_runs rows (status,
    // duration, what-it-did) with the raw worker log lines.
    if (filename === "tasks.log") {
      try {
        const res = await api.get<{ runs: JobRunRow[] }>("/engine/job-runs");
        setJobRunLines(res.data.runs.map(jobRunToLogLine));
      } catch {
        setJobRunLines([]);
      }
    }
  }, [lineCount]);

  useEffect(() => { fetchFiles(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (activeFile) fetchContent(activeFile);
  }, [activeFile, lineCount, fetchContent]);

  useEffect(() => {
    if (autoRefresh && activeFile) {
      intervalRef.current = setInterval(() => fetchContent(activeFile), 5000);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [autoRefresh, activeFile, fetchContent]);

  // Scroll to bottom on new content
  useEffect(() => {
    if (rowsRef.current) rowsRef.current.scrollTop = rowsRef.current.scrollHeight;
  }, [content]);

  const parsedLines = useMemo(() => {
    const lines = parseLogContent(content);
    if (activeFile !== "tasks.log" || !jobRunLines.length) return lines;
    // Interleave job-run rows chronologically; cap to the window covered by
    // the loaded file lines so old DB rows don't pad the top of the view.
    const firstEpoch = lines.find((l) => l.epoch != null)?.epoch ?? 0;
    return [...lines, ...jobRunLines.filter((j) => (j.epoch ?? 0) >= firstEpoch)].sort(
      (a, b) => (a.epoch ?? 0) - (b.epoch ?? 0),
    );
  }, [content, activeFile, jobRunLines]);

  const levelCounts = useMemo(() => {
    const c: Record<LogLevel, number> = { error: 0, warning: 0, info: 0, debug: 0 };
    for (const l of parsedLines) c[l.level]++;
    return c;
  }, [parsedLines]);

  const filteredLines = useMemo(() => {
    let lines = parsedLines;
    if (hiddenLevels.size > 0) lines = lines.filter((l) => !hiddenLevels.has(l.level));
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      lines = lines.filter(
        (l) => l.event.toLowerCase().includes(q) || l.details.toLowerCase().includes(q) || l.timestamp.toLowerCase().includes(q),
      );
    }
    return lines;
  }, [parsedLines, hiddenLevels, searchQuery]);

  const toggleLevel = (level: LogLevel) => {
    setHiddenLevels((prev) => {
      const next = new Set(prev);
      if (next.has(level)) next.delete(level); else next.add(level);
      return next;
    });
  };

  const handleDownload = () => {
    if (!activeFile || !content) return;
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = activeFile;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleClear = async () => {
    if (!activeFile) return;
    try {
      await api.delete(`/logs/${activeFile}`);
      setContent("");
      fetchFiles();
    } catch {
      /* swallow */
    }
  };

  const activeFileMeta = files.find((f) => f.name === activeFile);

  const allTabs = useMemo(() => {
    const tabs: { key: string; label: string; title: string }[] = [
      { key: "automation", label: "Automation", title: "Automation execution logs" },
    ];
    for (const f of files) {
      const info = LOG_FILE_LABELS[f.name] || { label: f.name, description: "" };
      tabs.push({ key: f.name, label: info.label, title: `${info.description} (${formatBytes(f.size)})` });
    }
    tabs.sort((a, b) => a.label.localeCompare(b.label));
    return tabs;
  }, [files]);

  return (
    <div className={styles.logsLayout}>
      <div className={styles.logsHeader}>
        <h2 className={styles.sectionTitle}>Logs</h2>
        <div className={styles.logTabs}>
          {allTabs.map((tab) => (
            <button
              key={tab.key}
              className={`${styles.logTab} ${activeTab === tab.key ? styles.logTabActive : ""}`}
              onClick={() => setActiveTab(tab.key)}
              title={tab.title}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {activeTab === "automation" && <AutomationLogsPanel />}

      {activeFile && (
        <div className={styles.logPanel}>
          <div className={styles.logToolbar}>
            <div className={styles.logToolbarLeft}>
              <span className={styles.logFileName}>{activeFile}</span>
              {activeFileMeta && (
                <span className={styles.logFileMeta}>
                  {formatBytes(activeFileMeta.size)} &middot; {new Date(activeFileMeta.modified).toLocaleString()}
                </span>
              )}
            </div>
            <div className={styles.logToolbarRight}>
              <select
                className={styles.logSelect}
                value={lineCount}
                onChange={(e) => setLineCount(Number(e.target.value))}
                title="Number of lines to show"
              >
                <option value={100}>100 lines</option>
                <option value={500}>500 lines</option>
                <option value={1000}>1,000 lines</option>
                <option value={5000}>5,000 lines</option>
              </select>
              <label className={styles.logAutoRefresh} title="Refresh every 5 seconds">
                <input
                  type="checkbox"
                  checked={autoRefresh}
                  onChange={(e) => setAutoRefresh(e.target.checked)}
                />
                <span>Auto</span>
              </label>
              <button
                className={styles.logToolbarBtn}
                onClick={() => activeFile && fetchContent(activeFile)}
                disabled={loading}
                title="Refresh"
              >
                {loading ? "..." : "Refresh"}
              </button>
              <button className={styles.logToolbarBtn} onClick={handleDownload} disabled={!content} title="Download log file">
                Download
              </button>
              <button className={styles.logToolbarBtn} onClick={handleClear} title="Clear log file">
                Clear
              </button>
            </div>
          </div>

          {/* Filter bar: search + level toggles */}
          <div className={styles.logFilterBar}>
            <input
              type="text"
              className={styles.logSearch}
              placeholder="Filter logs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            <div className={styles.logLevelFilters}>
              {ALL_LEVELS.map((lvl) => (
                <Chip
                  key={lvl}
                  tone="toned"
                  tint={LEVEL_TINT[lvl]}
                  className={`${styles.logLevelPill} ${hiddenLevels.has(lvl) ? styles.logLevelPillOff : ""}`}
                  onClick={() => toggleLevel(lvl)}
                  aria-pressed={!hiddenLevels.has(lvl)}
                  title={`${hiddenLevels.has(lvl) ? "Show" : "Hide"} ${lvl} logs`}
                >
                  {lvl.toUpperCase()} <span className={styles.logLevelCount}>{levelCounts[lvl]}</span>
                </Chip>
              ))}
            </div>
            <span className={styles.logLineCount}>
              {filteredLines.length === parsedLines.length
                ? `${parsedLines.length} lines`
                : `${filteredLines.length} / ${parsedLines.length}`}
            </span>
          </div>

          {/* Log rows */}
          <div ref={rowsRef} className={styles.logRows}>
            {filteredLines.length === 0 && (
              <div className={styles.logEmpty}>
                {loading ? "Loading..." : content ? "No matching log lines." : "Empty log file."}
              </div>
            )}
            {filteredLines.map((line, i) => (
              <div key={i} className={styles.logRow}>
                {line.timestamp && (
                  <span className={styles.logTs}>{searchQuery ? highlightText(line.timestamp, searchQuery) : line.timestamp}</span>
                )}
                <Chip tone="toned" tint={LEVEL_TINT[line.level]} className={styles.logBadge}>
                  {LEVEL_LABELS[line.level]}
                </Chip>
                <span className={styles.logMsg}>{searchQuery ? highlightText(line.event, searchQuery) : line.event}</span>
                {line.details && (
                  <span className={styles.logDetails}>{searchQuery ? highlightText(line.details, searchQuery) : line.details}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── Users (Admin) ──────────────────────────────────── */

function extractErrorMsg(err: unknown): string {
  const resp = (err as { response?: { data?: { error?: { message?: string; details?: { message?: string }[] } } } })?.response?.data?.error;
  if (resp?.details?.length) return resp.details.map((d) => d.message).join("; ");
  return resp?.message || "An error occurred";
}

function UsersSection() {
  const { data: users, isLoading } = useUsers();
  const updateUser = useUpdateUser();
  const deleteUser = useDeleteUser();
  const currentUser = useAuthStore((s) => s.user);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [linkCopied, setLinkCopied] = useState(false);
  const [editForm, setEditForm] = useState<{
    username: string;
    role: string;
    is_active: boolean;
    password: string;
  }>({ username: "", role: "user", is_active: true, password: "" });
  const [error, setError] = useState<string | null>(null);

  const startEdit = (u: { id: string; username: string; role: string; is_active: boolean }) => {
    setEditingId(u.id);
    setDeletingId(null);
    setEditForm({
      username: u.username,
      role: u.role,
      is_active: u.is_active,
      password: "",
    });
    setError(null);
  };

  const cancelEdit = () => {
    setEditingId(null);
    setDeletingId(null);
    setError(null);
  };

  const saveEdit = async () => {
    if (!editingId) return;
    setError(null);
    const original = users?.find((u) => u.id === editingId);
    if (!original) return;

    const data: Record<string, unknown> = {};
    if (editForm.username !== original.username) data.username = editForm.username;
    if (editForm.role !== original.role) data.role = editForm.role;
    if (editForm.is_active !== original.is_active) data.is_active = editForm.is_active;
    if (editForm.password) data.password = editForm.password;

    if (Object.keys(data).length === 0) {
      setEditingId(null);
      return;
    }

    try {
      await updateUser.mutateAsync({ userId: editingId, data });
      setEditingId(null);
    } catch (err: unknown) {
      setError(extractErrorMsg(err));
    }
  };

  const handleDelete = async (userId: string) => {
    setError(null);
    try {
      await deleteUser.mutateAsync(userId);
      setDeletingId(null);
    } catch (err: unknown) {
      setError(extractErrorMsg(err));
    }
  };

  if (isLoading) {
    return (
      <div className={styles.sectionContent}>
        <h2 className={styles.sectionTitle}>User Management</h2>
        <p className={styles.sectionDesc}>Loading users...</p>
      </div>
    );
  }

  return (
    <div className={styles.sectionContent}>
      <h2 className={styles.sectionTitle}>User Management</h2>
      <p className={styles.sectionDesc}>
        Manage user accounts, roles, and access.
      </p>

      <SystemSettings
        filterGroups={["security"]}
        renderAfterKey={{
          registration_invite_code: (_pendingValue, meta) => {
            if (!meta.is_set) return null;
            return (
              <div style={{ padding: "0 0 0.75rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <button
                  className={styles.btnSmall}
                  onClick={async () => {
                    try {
                      const res = await api.get<{ invite_code: string | null }>("/auth/invite-code");
                      const code = res.data.invite_code;
                      if (!code) return;
                      const link = `${window.location.origin}/register?invite=${encodeURIComponent(code)}`;
                      await navigator.clipboard.writeText(link);
                      setLinkCopied(true);
                      setTimeout(() => setLinkCopied(false), 2000);
                    } catch { /* ignore */ }
                  }}
                >
                  {linkCopied ? "Copied!" : "Copy Invite Link"}
                </button>
                {linkCopied && (
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                    Link copied to clipboard
                  </span>
                )}
              </div>
            );
          },
        }}
      />

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>Users ({users?.length || 0})</h3>

        <table className={styles.usersTable}>
          <thead>
            <tr>
              <th>Username</th>
              <th>Role</th>
              <th>Status</th>
              <th title="Feeds this account subscribes to, out of the shared pool">Feeds</th>
              <th>Last Login</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {users?.map((u) => (
              editingId === u.id ? (
                <tr key={u.id} className={styles.editingRow}>
                  <td>
                    <input
                      className={styles.inputSmall}
                      value={editForm.username}
                      onChange={(e) => setEditForm({ ...editForm, username: e.target.value })}
                    />
                  </td>
                  <td>
                    <select
                      className={styles.selectSmall}
                      value={editForm.role}
                      onChange={(e) => setEditForm({ ...editForm, role: e.target.value })}
                      disabled={u.id === currentUser?.id}
                    >
                      <option value="user">user</option>
                      <option value="admin">admin</option>
                    </select>
                  </td>
                  <td>
                    <label className={styles.toggle}>
                      <input
                        type="checkbox"
                        checked={editForm.is_active}
                        onChange={(e) => setEditForm({ ...editForm, is_active: e.target.checked })}
                        disabled={u.id === currentUser?.id}
                      />
                      <span className={styles.toggleSlider} />
                    </label>
                  </td>
                  <td colSpan={4}>
                    <input
                      className={styles.inputSmall}
                      type="password"
                      value={editForm.password}
                      onChange={(e) => setEditForm({ ...editForm, password: e.target.value })}
                      placeholder="New password (leave blank to keep)"
                    />
                  </td>
                </tr>
              ) : (
                <tr key={u.id}>
                  <td>
                    <span className={styles.userCell}>
                      {u.username}
                      {u.id === currentUser?.id && (
                        <Chip tone="toned" tint="var(--accent)" className={styles.youBadge}>you</Chip>
                      )}
                    </span>
                  </td>
                  <td>
                    <Chip
                      className={styles.roleBadge}
                      tone={u.role === "admin" ? "toned" : "default"}
                      tint={u.role === "admin" ? "#8b5cf6" : undefined}
                    >
                      {u.role}
                    </Chip>
                  </td>
                  <td>
                    <Chip tone="toned" tint={u.is_active ? "#22c55e" : "#ef4444"} className={styles.statusBadge}>
                      {u.is_active ? "Active" : "Inactive"}
                    </Chip>
                  </td>
                  <td className={styles.muted}>
                    {u.feed_count ?? 0}
                    {(u.muted_feed_count ?? 0) > 0 && (
                      <span title={`${u.muted_feed_count} muted`}> ({u.muted_feed_count} muted)</span>
                    )}
                  </td>
                  <td className={styles.muted}>{u.last_login ? new Date(u.last_login).toLocaleDateString() : "Never"}</td>
                  <td className={styles.muted}>{new Date(u.created_at).toLocaleDateString()}</td>
                  <td>
                    <span className={styles.actionButtons}>
                      <button className={styles.btnSmall} onClick={() => startEdit(u)}>Edit</button>
                      {u.id !== currentUser?.id && (
                        deletingId === u.id ? (
                          <>
                            <button
                              className={styles.btnDangerSmall}
                              onClick={() => handleDelete(u.id)}
                              disabled={deleteUser.isPending}
                            >
                              {deleteUser.isPending ? "..." : "Confirm"}
                            </button>
                            <button className={styles.btnSmall} onClick={() => setDeletingId(null)}>Cancel</button>
                          </>
                        ) : (
                          <button className={styles.btnDangerSmall} onClick={() => setDeletingId(u.id)}>Delete</button>
                        )
                      )}
                    </span>
                  </td>
                </tr>
              )
            ))}
          </tbody>
        </table>

        {error && <p className={styles.confirmText} style={{ padding: "0.5rem 0" }}>{error}</p>}

        {editingId && (
          <div className={styles.cardActions}>
            <button
              className={styles.btnPrimary}
              onClick={saveEdit}
              disabled={updateUser.isPending}
            >
              {updateUser.isPending ? "Saving..." : "Save Changes"}
            </button>
            <button className={styles.btnSecondary} onClick={cancelEdit}>
              Cancel
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

/* ─── Claude Code Skill ──────────────────────────────── */

function TelegramSection() {
  return (
    <div className={styles.sectionContent}>
      <h2 className={styles.sectionTitle}>Telegram Setup</h2>
      <p className={styles.sectionDesc}>
        Telegram is a high-signal source for threat intel — ransomware leak sites, hacktivist
        coordination channels, and eCrime brokers all publish there. Setup is a one-time bootstrap
        per IntelFeed instance because Telegram requires an interactive login on stdin.
      </p>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>Before you start</h3>
        <p className={styles.cardDesc}>
          Telegram ingestion requires a real <strong>user</strong> account (bots cannot read
          channels they aren't admin of). Aggressive use can permanently ban the account, and the
          resulting session file is a credential equivalent to the account password. Use a
          dedicated burner SIM / Telegram identity, not your personal account. Monitoring channels
          banned in your jurisdiction may have legal implications — operator's responsibility.
        </p>
      </div>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>1. Create a Telegram API application</h3>
        <p className={styles.cardDesc}>
          Visit <a href="https://my.telegram.org" target="_blank" rel="noopener noreferrer">my.telegram.org</a> →{" "}
          <strong>API development tools</strong> → create an application. Save the
          <code className={styles.inlineCode}>api_id</code> and{" "}
          <code className={styles.inlineCode}>api_hash</code>.
        </p>
      </div>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>2. Add credentials to .env and rebuild</h3>
        <p className={styles.cardDesc}>
          Set the values in your <code className={styles.inlineCode}>.env</code> on the host:
        </p>
        <pre className={styles.codeBlock}>
          <code>{`TELEGRAM_API_ID=12345
TELEGRAM_API_HASH=abc123...`}</code>
        </pre>
        <p className={styles.cardDesc}>
          Then restart the api + celery-worker services so they pick up the new env vars
          (substitute <code className={styles.inlineCode}>docker-compose.dev.yml</code> for dev):
        </p>
        <pre className={styles.codeBlock}>
          <code>docker compose -f docker-compose.prod.yml up -d --build api celery-worker</code>
        </pre>
      </div>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>3. Run the interactive bootstrap script</h3>
        <p className={styles.cardDesc}>
          The <code className={styles.inlineCode}>-it</code> flags are critical — Telethon prompts
          on stdin for your phone number, the SMS code Telegram sends, and (if enabled) your 2FA
          password.
        </p>
        <pre className={styles.codeBlock}>
          <code>docker compose -f docker-compose.prod.yml exec -it api python scripts/telegram_login.py</code>
        </pre>
        <p className={styles.cardDesc}>
          On success the script prints{" "}
          <code className={styles.inlineCode}>Logged in as &lt;name&gt; @&lt;username&gt;, id &lt;id&gt;</code>{" "}
          and exits.
        </p>
      </div>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>4. Secure and back up the session file</h3>
        <p className={styles.cardDesc}>
          The session file lives at{" "}
          <code className={styles.inlineCode}>./telegram_data/telegram.session</code> on the host.
          Treat it as a credential — back it up alongside the database and lock down its
          permissions:
        </p>
        <pre className={styles.codeBlock}>
          <code>chmod 600 ./telegram_data/telegram.session</code>
        </pre>
      </div>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>5. Add channels via the Add Feed modal</h3>
        <p className={styles.cardDesc}>
          From the feeds page, the <strong>Add Feed</strong> modal exposes a{" "}
          <em>"Discover from my Telegram account"</em> button that lists every channel the
          bootstrap account is joined to and flags which ones are already wired up. For private
          channels, either join through the Telegram client app or run:
        </p>
        <pre className={styles.codeBlock}>
          <code>docker compose -f docker-compose.prod.yml exec api python scripts/telegram_join.py "https://t.me/+HASH"</code>
        </pre>
      </div>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>Operational notes</h3>
        <ul className={styles.skillExamples}>
          <li>
            Default poll interval is <strong>30 minutes per channel</strong>. Lower intervals risk
            flood waits and account bans.
          </li>
          <li>
            If the account is logged out from another device or banned, fetches fail with{" "}
            <code className={styles.inlineCode}>Telegram session revoked</code> until you re-run the
            bootstrap script.
          </li>
          <li>
            Media (photos, videos, voice notes, documents) downloads to{" "}
            <code className={styles.inlineCode}>./telegram_media/</code> and serves from{" "}
            <code className={styles.inlineCode}>/api/telegram-media/...</code> (auth required).
            Default cap is 25 MB — set{" "}
            <code className={styles.inlineCode}>TELEGRAM_MAX_MEDIA_SIZE_MB</code> to change.
          </li>
          <li>
            Multi-session: pass{" "}
            <code className={styles.inlineCode}>--session NAME</code> to{" "}
            <code className={styles.inlineCode}>telegram_login.py</code> to bootstrap a second
            identity, then reference the same{" "}
            <code className={styles.inlineCode}>session_name</code> in each feed's{" "}
            <code className={styles.inlineCode}>adapter_config</code>.
          </li>
          <li>
            <strong>Realtime ingest</strong> (optional): the{" "}
            <code className={styles.inlineCode}>telegram-listener</code> container holds a
            long-lived MTProto connection and pushes new messages as they arrive. Opt in per-feed
            via the "Realtime ingest" checkbox in Edit Feed (or{" "}
            <code className={styles.inlineCode}>adapter_config.realtime: true</code>). Polling
            stays as a safety net.
          </li>
          <li>
            Keep the host clock in sync (<code className={styles.inlineCode}>chronyd</code> /{" "}
            <code className={styles.inlineCode}>systemd-timesyncd</code>) — MTProto rejects
            requests that drift more than ~5 minutes.
          </li>
        </ul>
      </div>
    </div>
  );
}

function SkillSection() {
  const user = useAuthStore((s) => s.user);
  return (
    <div className={styles.sectionContent}>
      <h2 className={styles.sectionTitle}>Claude Code Skill</h2>
      <p className={styles.sectionDesc}>
        Query IntelFeed directly from Claude Code using the IntelFeed skill.
        Search entries, extract intelligence, generate detection rules, and more — all through natural language.
      </p>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>1. Install the Skill</h3>
        <p className={styles.cardDesc}>
          Clone the skill into your Claude Code skills directory:
        </p>
        <pre className={styles.codeBlock}>
          <code>git clone https://github.com/a-oneil/intelfeed-skill ~/Downloads/intelfeed-skill</code>
        </pre>
      </div>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>1a. Select the skill you want to use</h3>
        <p className={styles.cardDesc}>
          Setup the lite skill if you just want the agent to perform searches and retrieve content from intelfeed.
        </p>
        <pre className={styles.codeBlock}>
          <code>cp -r ~/Downloads/intelfeed-skill/intelfeed-lite-skill ~/.claude/skills/intelfeed</code>
        </pre>
        <p className={styles.cardDesc}>
          Setup the full skill if you need the agent to modify intelfeed configurations.
        </p>
        <pre className={styles.codeBlock}>
          <code>cp -r ~/Downloads/intelfeed-skill/intelfeed-full-skill ~/.claude/skills/intelfeed</code>
        </pre>
      </div>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>2. Set Environment Variables</h3>
        <p className={styles.cardDesc}>
          Add these to your shell profile (<code className={styles.inlineCode}>.bashrc</code>, <code className={styles.inlineCode}>.zshrc</code>, etc.) so the skill can authenticate with your IntelFeed instance:
        </p>
        <pre className={styles.codeBlock}>
          <code>{`export INTELFEED_API_URL=${window.location.origin}
export INTELFEED_USERNAME=${user?.username || "your_username"}
export INTELFEED_PASSWORD=your_password`}</code>
        </pre>
      </div>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>3. Reload Your Shell</h3>
        <p className={styles.cardDesc}>
          After saving the environment variables, reload your shell profile so they take effect:
        </p>
        <pre className={styles.codeBlock}>
          <code>source ~/.zshrc  # or source ~/.bashrc</code>
        </pre>
      </div>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>4. Start Using It</h3>
        <p className={styles.cardDesc}>
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

