import { useNavigate, useLocation } from "react-router-dom";
import { useIntelStore, type WorkspaceSection } from "@/stores/intelStore";
import { getEntityCssVar } from "@/utils/entityTheme";
import { Hint } from "./primitives";
import styles from "./WorkbenchNav.module.css";
import { useIsVisitor } from "@/stores/authStore";

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
  sectors: "sector",
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
    body: "Your rule library, the ATT&CK matrix it maps to, and the telemetry sources the rules depend on.",
  },
  ENTITIES: {
    title: "Entities",
    body: "Entities extracted from your articles: actors, malware, CVEs, techniques, vendors.",
    aside: "Each one has a profile built from the articles that mention it.",
  },
  INTELLIGENCE: {
    title: "Intelligence",
    body: "Analyst tools: the watchlist, intelligence requirements, Telegram mentions, ransomware victims and the glossary.",
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
          body: "Build and publish reports from collected articles, such as exposure reports and flash alerts.",
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
          body: "The MITRE ATT&CK matrix, shaded by what your feeds have reported and by what your rules cover.",
        },
      },
      { key: "rules", label: "Rules Library", swatch: "var(--accent-detect)" },
      {
        key: "telemetry", label: "Telemetry Sources", swatch: "var(--accent-detect)",
        hint: {
          title: "Telemetry Sources",
          body: "The log sources your rules depend on. Mark the ones you collect so coverage reflects what can run.",
        },
      },
      {
        path: "/workbench/threats", label: "Threats", swatch: "var(--accent-detect)",
        hint: {
          title: "Threats",
          body: "Active threats ranked by story, not by outlet. Ten articles about one breach count once.",
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
      { key: "sectors", label: "Sectors" },
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
          body: "Questions you need to answer. New articles are matched against them as they arrive.",
        },
      },
      { key: "telegram_mentions", label: "Telegram Mentions", swatch: "var(--accent-intel)" },
      {
        key: "watchlist", label: "Watchlist", swatch: "var(--accent-intel)",
        hint: {
          title: "Watchlist",
          body: "Entities you follow. New mentions are listed here.",
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
 * Workbench areas that aren't part of the public read-only view: detection
 * work, intel work products, observables, and anything personal.
 */
export const VISITOR_HIDDEN_SECTIONS = new Set<string>([
  "reports",
  "rules",
  "telemetry",
  "campaigns",
  "observables",
  "ransomware",
  "requirements",
  "telegram_mentions",
  "watchlist",
  "/workbench/threats",
]);

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
  const isVisitor = useIsVisitor();

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
            section.items
              .filter((item) => !isVisitor || !VISITOR_HIDDEN_SECTIONS.has(item.key ?? item.path ?? ""))
              .map((item) => {
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
