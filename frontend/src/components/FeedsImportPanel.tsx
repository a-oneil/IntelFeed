import { useState } from "react";
import { toast } from "sonner";

import api from "@/api/client";
import SystemSettings from "@/components/SystemSettings";
import { useUpdateProfile } from "@/hooks/useAuth";
import { useBulkExcludeShorts, useCategories } from "@/hooks/useFeeds";
import { usePublicRssToken, useRegeneratePublicRssToken } from "@/hooks/useSystemSettings";
import { useAuthStore } from "@/stores/authStore";

import styles from "@/pages/SettingsPage.module.css";

/** Feed subscription export (OPML), YouTube defaults, public RSS. OPML
 *  *import* lives on the Add Feed button, where new subscriptions start.
 *  Fetch-behavior settings (intervals, rate limiting, image proxy) live on the
 *  Engine pipeline's feeds/sanitize cards. */
export function FeedsImportPanel() {
  const user = useAuthStore((s) => s.user);
  const updateProfile = useUpdateProfile();
  const bulkExcludeShorts = useBulkExcludeShorts();

  const [excludeShortsDefault, setExcludeShortsDefault] = useState(
    (user?.settings?.youtube_exclude_shorts_default as boolean) ?? true
  );
  const [ytMsg, setYtMsg] = useState<string | null>(null);

  const handleExport = async () => {
    try {
      const res = await api.get("/opml/export", { responseType: "blob" });
      const url = window.URL.createObjectURL(res.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = "intelfeed-subscriptions.opml";
      a.click();
      window.URL.revokeObjectURL(url);
    } catch {
      /* swallow */
    }
  };

  const handleExcludeShortsToggle = async (checked: boolean) => {
    setExcludeShortsDefault(checked);
    try {
      setYtMsg(null);
      const newSettings = {
        ...(user?.settings || {}),
        youtube_exclude_shorts_default: checked,
      };
      await updateProfile.mutateAsync({ settings: newSettings });
      setYtMsg(checked ? "Default enabled" : "Default disabled");
    } catch {
      setExcludeShortsDefault(!checked);
      setYtMsg("Failed to save setting");
    }
  };

  const handleBulkExcludeShorts = async () => {
    try {
      setYtMsg(null);
      const result = await bulkExcludeShorts.mutateAsync(excludeShortsDefault);
      setYtMsg(
        `Updated ${result.updated} YouTube feed${result.updated !== 1 ? "s" : ""}`
      );
    } catch {
      setYtMsg("Failed to update feeds");
    }
  };

  return (
    <div className={styles.sectionContent}>
      <h2 className={styles.sectionTitle}>Feeds &amp; Export</h2>
      <p className={styles.sectionDesc}>
        Manage feed subscriptions and export data. To import an OPML file, use Add Feed.
      </p>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>OPML Export</h3>
        <p className={styles.hint}>
          Download your current subscriptions as an OPML file for backup or migration.
        </p>
        <div className={styles.cardActions}>
          <button onClick={handleExport} className={styles.btnSecondary}>
            Export OPML
          </button>
        </div>
      </div>

      <div className={styles.card}>
        <h3 className={styles.cardTitle}>YouTube</h3>
        <div className={styles.settingRow}>
          <div className={styles.settingInfo}>
            <span className={styles.settingLabel}>Exclude Shorts by default</span>
            <span className={styles.settingHint}>
              New YouTube feeds will automatically exclude Shorts during sync.
            </span>
          </div>
          <label className={styles.toggle}>
            <input
              type="checkbox"
              checked={excludeShortsDefault}
              onChange={(e) => handleExcludeShortsToggle(e.target.checked)}
            />
            <span className={styles.toggleSlider} />
          </label>
        </div>
        <div className={styles.cardActions}>
          <button
            onClick={handleBulkExcludeShorts}
            disabled={bulkExcludeShorts.isPending}
            className={styles.btnSecondary}
          >
            {bulkExcludeShorts.isPending
              ? "Updating..."
              : excludeShortsDefault
                ? "Enable on all YouTube feeds"
                : "Disable on all YouTube feeds"}
          </button>
          {ytMsg && <span className={styles.successMsg}>{ytMsg}</span>}
        </div>
      </div>

      <SystemSettings filterGroups={["public_rss"]} />

      <PublicRssCard />
    </div>
  );
}

/* ─── Public RSS ──────────────────────────────────────── */

function _slugifyCategory(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "category";
}

function PublicRssCard() {
  const { data: token, isLoading } = usePublicRssToken();
  const { data: categories } = useCategories();
  const regenerate = useRegeneratePublicRssToken();
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);

  const origin =
    typeof window !== "undefined" ? window.location.origin : "";

  const allUrl = token ? `${origin}/api/public/rss/${token}.xml` : "";

  const copy = async (url: string, key: string) => {
    try {
      await navigator.clipboard.writeText(url);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey((k) => (k === key ? null : k)), 1500);
    } catch {
      toast.error("Failed to copy URL");
    }
  };

  const handleRegenerate = async () => {
    if (!confirming) {
      setConfirming(true);
      setTimeout(() => setConfirming(false), 4000);
      return;
    }
    try {
      await regenerate.mutateAsync();
      toast.success("New token issued. Old URLs no longer work.");
      setConfirming(false);
    } catch {
      toast.error("Failed to regenerate token");
    }
  };

  return (
    <div className={styles.card}>
      <h3 className={styles.cardTitle}>Public RSS URLs</h3>
      <p className={styles.hint}>
        Share these URLs with any RSS reader. The token in the URL is the only
        access control — treat it like a password. Re-publishing is gated by the{" "}
        <strong>Enable Public RSS</strong> setting above.
      </p>

      {isLoading || !token ? (
        <p className={styles.hint}>Loading feed token…</p>
      ) : (
        <>
          <div className={styles.settingRow}>
            <div className={styles.settingInfo}>
              <span className={styles.settingLabel}>All sources</span>
              <code className={styles.settingHint} style={{ wordBreak: "break-all" }}>
                {allUrl}
              </code>
            </div>
            <button
              className={styles.btnSecondary}
              onClick={() => copy(allUrl, "all")}
            >
              {copiedKey === "all" ? "Copied" : "Copy"}
            </button>
          </div>

          {categories && categories.length > 0 && (
            <div style={{ marginTop: "1rem" }}>
              <h4 style={{ margin: "0 0 0.5rem" }}>Per category</h4>
              {categories.flatMap((c) => [c, ...(c.children || [])]).map((cat) => {
                const slug = _slugifyCategory(cat.name);
                const url = `${origin}/api/public/rss/${token}/category/${slug}.xml`;
                const key = `cat:${cat.id}`;
                return (
                  <div key={cat.id} className={styles.settingRow}>
                    <div className={styles.settingInfo}>
                      <span className={styles.settingLabel}>{cat.name}</span>
                      <code
                        className={styles.settingHint}
                        style={{ wordBreak: "break-all" }}
                      >
                        {url}
                      </code>
                    </div>
                    <button
                      className={styles.btnSecondary}
                      onClick={() => copy(url, key)}
                    >
                      {copiedKey === key ? "Copied" : "Copy"}
                    </button>
                  </div>
                );
              })}
            </div>
          )}

          <div className={styles.cardActions} style={{ marginTop: "1rem" }}>
            <button
              onClick={handleRegenerate}
              className={styles.btnSecondary}
              disabled={regenerate.isPending}
            >
              {regenerate.isPending
                ? "Regenerating…"
                : confirming
                  ? "Click again to confirm — old URLs will break"
                  : "Regenerate token"}
            </button>
          </div>
        </>
      )}
    </div>
  );
}
