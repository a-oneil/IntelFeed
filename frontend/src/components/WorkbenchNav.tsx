import { useNavigate, useLocation } from "react-router-dom";
import { useIntelStore, type WorkspaceSection } from "@/stores/intelStore";
import { getEntityCssVar } from "@/utils/entityTheme";
import { Hint } from "./primitives";
import styles from "./WorkbenchNav.module.css";

// Maps a workspace nav section to its canonical entity type, so the nav icon
// can be tinted with the same color used in entity profiles / intel panels.
export const SECTION_ENTITY_TYPE: Partial<Record<WorkspaceSection, string>> = {
  campaigns: "campaign",
  countries: "country",
  cves: "cve",
  cwes: "cwe",
  malware: "malware",
  mitigations: "mitigation",
  observables: "observable",
  products: "product",
  threat_actors: "threat_actor",
  tools: "tool",
  ttps: "ttp",
  vendors: "vendor",
};

// Nav items are either store-driven sections (key) or routed pages (path).
// An empty group name renders its items ungrouped at the top (no header, always visible).
//
// `swatch` is the nav's colour square. Entity sections take theirs from the
// canonical entity token via SECTION_ENTITY_TYPE; everything else names a
// domain accent here so each group reads as one family.
/**
 * What each group is *for*, on hover. The entity names below are self-evident
 * once you know the group they sit in, so the group header carries the
 * explanation and the rows stay quiet.
 */
const GROUP_HINTS: Record<string, { title: string; body: string; aside?: string }> = {
  DETECTION: {
    title: "Detection",
    body: "What you can actually catch: your rule library, the ATT&CK grid behind it, and the logs it all depends on.",
  },
  ENTITIES: {
    title: "Entities",
    body: "Everything the engine pulled out of your reading — actors, malware, CVEs, techniques, vendors.",
    aside: "Each one has a dossier that fills in as you read.",
  },
  INTELLIGENCE: {
    title: "Intelligence",
    body: "The analyst's own workspace — what you're watching, what you owe an answer on, and what you write up.",
  },
};

export const SECTION_CONFIG: Array<{
  group: string;
  items: Array<{
    key?: WorkspaceSection;
    path?: string;
    label: string;
    swatch?: string;
    /** Hover card, for the destinations whose name is jargon rather than an explanation. */
    hint?: { title: string; body: string; aside?: string };
  }>;
}> = [
  {
    group: "",
    items: [
      { path: "/workbench/dashboard", label: "Dashboard", swatch: "var(--accent-blue)" },
      // Reports sits top-level next to Dashboard — it's a primary product
      // surface, not something to dig out of the Intelligence group.
      {
        key: "reports", label: "Reports", swatch: "var(--accent-intel)",
        hint: {
          title: "Reports",
          body: "Build and publish intelligence products — exposure profiles, flash alerts, actor dossiers — from what the feeds collected.",
        },
      },
    ],
  },
  {
    group: "DETECTION",
    items: [
      {
        key: "attack_matrix", label: "ATT&CK Matrix", swatch: "var(--accent-detect)",
        hint: {
          title: "ATT&CK Matrix",
          body: "MITRE's grid, shaded two ways: what your feeds have reported, and what your rules already cover.",
        },
      },
      { key: "rules", label: "Rules Library", swatch: "var(--accent-detect)" },
      {
        key: "telemetry", label: "Telemetry Sources", swatch: "var(--accent-detect)",
        hint: {
          title: "Telemetry Sources",
          body: "The logs your rules depend on. Tick the ones you actually collect and coverage stops being theoretical.",
        },
      },
      {
        path: "/workbench/threats", label: "Threats", swatch: "var(--accent-detect)",
        hint: {
          title: "Threats",
          body: "What's moving right now, ranked by story rather than by outlet — so ten write-ups of one breach count once.",
        },
      },
    ],
  },
  {
    group: "ENTITIES",
    items: [
      { key: "campaigns", label: "Campaigns" },
      { key: "countries", label: "Countries" },
      { key: "cves", label: "CVEs" },
      { key: "malware", label: "Malware" },
      { key: "mitigations", label: "Mitigations" },
      { key: "observables", label: "Observables" },
      { key: "products", label: "Products" },
      { key: "threat_actors", label: "Threat Actors" },
      { key: "tools", label: "Tools" },
      { key: "ttps", label: "TTPs" },
      { key: "vendors", label: "Vendors" },
      { key: "cwes", label: "Weaknesses" },
    ],
  },
  {
    group: "INTELLIGENCE",
    items: [
      { key: "glossary", label: "Glossary", swatch: "var(--accent-intel)" },
      { key: "ransomware", label: "Ransomware", swatch: "var(--accent-intel)" },
      {
        key: "requirements", label: "Requirements", swatch: "var(--accent-intel)",
        hint: {
          title: "Requirements",
          body: "The standing questions you owe someone an answer on. New articles get matched against them as they arrive.",
        },
      },
      { key: "telegram_mentions", label: "Telegram Mentions", swatch: "var(--accent-intel)" },
      {
        key: "watchlist", label: "Watchlist", swatch: "var(--accent-intel)",
        hint: {
          title: "Watchlist",
          body: "Entities you're tracking. New mentions of them surface here before they reach your feed.",
        },
      },
    ],
  },
];

// All valid workspace-section keys — for validating the ?section= deep link.
export const SECTION_KEYS = new Set<string>(
  SECTION_CONFIG.flatMap((group) =>
    group.items.map((item) => item.key).filter((key): key is WorkspaceSection => !!key),
  ),
);

/**
 * The workbench's section nav.
 *
 * It used to be an `aside` inside WorkbenchLayout, which meant the workbench
 * ran two nav rails side by side and had to auto-collapse the app sidebar to
 * pay for them. It now renders *as* the app sidebar whenever the sidebar is in
 * Workbench mode, so there is one rail, one width, one collapse.
 */
export function WorkbenchNav({ onNavigate }: { onNavigate?: () => void }) {
  const navigate = useNavigate();
  const location = useLocation();
  const activeSection = useIntelStore((s) => s.activeSection);
  const setActiveSection = useIntelStore((s) => s.setActiveSection);
  const clearSelectedEntity = useIntelStore((s) => s.clearSelectedEntity);

  const sectionCollapsed: Record<string, boolean> = {
    ENTITIES: useIntelStore((s) => s.entitiesSectionCollapsed),
    DETECTION: useIntelStore((s) => s.detectionSectionCollapsed),
    INTELLIGENCE: useIntelStore((s) => s.intelligenceSectionCollapsed),
    EXPLORE: useIntelStore((s) => s.exploreSectionCollapsed),
    SYSTEM: useIntelStore((s) => s.systemSectionCollapsed),
  };

  const toggleSectionCollapsed: Record<string, (v: boolean) => void> = {
    ENTITIES: useIntelStore((s) => s.setEntitiesSectionCollapsed),
    DETECTION: useIntelStore((s) => s.setDetectionSectionCollapsed),
    INTELLIGENCE: useIntelStore((s) => s.setIntelligenceSectionCollapsed),
    EXPLORE: useIntelStore((s) => s.setExploreSectionCollapsed),
    SYSTEM: useIntelStore((s) => s.setSystemSectionCollapsed),
  };

  return (
    <nav className={styles.nav} aria-label="Workbench navigation">
      {SECTION_CONFIG.map((section) => (
        <div key={section.group} className={styles.section}>
          {section.group && (
            <Hint
              title={GROUP_HINTS[section.group]?.title ?? section.group}
              body={GROUP_HINTS[section.group]?.body ?? ""}
              aside={GROUP_HINTS[section.group]?.aside}
              disabled={!GROUP_HINTS[section.group]}
            >
              <div
                className={styles.sectionHeader}
                onClick={() =>
                  toggleSectionCollapsed[section.group](!sectionCollapsed[section.group])
                }
              >
                <svg
                  className={`${styles.sectionChevron} ${!sectionCollapsed[section.group] ? styles.sectionChevronOpen : ""}`}
                  viewBox="0 0 10 10"
                >
                  <path d="M2.5 1L7.5 5L2.5 9" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                {section.group}
              </div>
            </Hint>
          )}
          {(!section.group || !sectionCollapsed[section.group]) &&
            section.items.map((item) => {
              const entityType = item.key ? SECTION_ENTITY_TYPE[item.key] : undefined;
              const iconColor = entityType ? getEntityCssVar(entityType) : item.swatch;
              const isActive = item.path
                ? location.pathname === item.path
                : activeSection === item.key && location.pathname === "/workbench/explore";
              return (
                <Hint
                  key={item.key ?? item.path}
                  title={item.hint?.title ?? item.label}
                  body={item.hint?.body ?? ""}
                  aside={item.hint?.aside}
                  disabled={!item.hint}
                >
                <button
                  className={`${styles.navItem} ${isActive ? styles.navItemActive : ""}`}
                  onClick={() => {
                    if (item.path) {
                      navigate(item.path);
                    } else {
                      setActiveSection(item.key!);
                      clearSelectedEntity();
                      navigate("/workbench/explore");
                    }
                    onNavigate?.();
                  }}
                >
                  {/* Colour square, not a glyph: at 14px the entity icons
                      were indistinguishable, and colour is already the
                      entity vocabulary everywhere else in the app. */}
                  <span
                    className={styles.navSwatch}
                    style={iconColor ? { background: iconColor } : undefined}
                    aria-hidden="true"
                  />
                  <span className={styles.navLabel}>{item.label}</span>
                </button>
                </Hint>
              );
            })}
        </div>
      ))}
    </nav>
  );
}
