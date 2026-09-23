import type { ComponentType } from "react";
import StatCard from "./StatCard";
import FeedActivityChart from "./FeedActivityChart";
import CVESeverityChart from "./CVESeverityChart";
import TrendingCVEs from "./TrendingCVEs";
import AttackHeatmap from "./AttackHeatmap";
import LatestEntries from "./LatestEntries";
import NewActorsWidget from "./NewActorsWidget";
import NewCVEsWidget from "./NewCVEsWidget";
import DetectionCoverageWidget from "./DetectionCoverageWidget";
import CorrelationEventsWidget from "./CorrelationEventsWidget";
import CorrelationBrowserWidget from "./CorrelationBrowserWidget";
import IntelVelocityAnalyticsWidget from "./IntelVelocityWidget";
import OverviewWidget from "./OverviewWidget";
import TrendingEntitiesWidget from "./TrendingEntitiesWidget";
import SourceReliabilityWidget from "./SourceReliabilityWidget";
import PIRCoverageWidget from "./PIRCoverageWidget";
import AutomationLogsWidget from "./AutomationLogsWidget";
import NewDetectionsWidget from "./NewDetectionsWidget";
import VendorsTrendingWidget from "./VendorsTrendingWidget";
import ProductsTrendingWidget from "./ProductsTrendingWidget";
import TargetedCountriesWidget from "./TargetedCountriesWidget";
import ActiveCampaignsWidget from "./ActiveCampaignsWidget";
import FeedHealthWidget from "./FeedHealthWidget";
import WorkerQueueWidget from "./WorkerQueueWidget";
import AIUsageWidget from "./AIUsageWidget";
import DetectionFormatBreakdownWidget from "./DetectionFormatBreakdownWidget";
import AttackCoverageGapWidget from "./AttackCoverageGapWidget";
import KEVMatchesWidget from "./KEVMatchesWidget";
import TriageQueueStatsWidget from "./TriageQueueStatsWidget";
import SavedSearchHitsWidget from "./SavedSearchHitsWidget";
import TopTagsWidget from "./TopTagsWidget";
import TelegramMentionsWidget from "./TelegramMentionsWidget";
import WeeklyRecapWidget from "./WeeklyRecapWidget";
import ActorActivityTimelineWidget from "./ActorActivityTimelineWidget";
import HotCorrelationsWidget from "./HotCorrelationsWidget";
// ── Board widgets (round 2) ──
import OverviewRowWidget from "./OverviewRowWidget";
import RansomwarePulseWidget from "./RansomwarePulseWidget";
import WatchlistPulseWidget from "./WatchlistPulseWidget";
import RulesAttentionWidget from "./RulesAttentionWidget";
import TargetingGridWidget from "./TargetingGridWidget";
import PlaybookDriftWidget from "./PlaybookDriftWidget";
import RelationshipInboxWidget from "./RelationshipInboxWidget";
import TelemetryGapsWidget from "./TelemetryGapsWidget";
import KEVDeadlinesWidget from "./KEVDeadlinesWidget";
import TriageFlowWidget from "./TriageFlowWidget";
import CampaignMomentumWidget from "./CampaignMomentumWidget";
import UnderReportedWidget from "./UnderReportedWidget";
import MorningBriefingWidget from "./MorningBriefingWidget";

export interface WidgetConfig {
  [key: string]: unknown;
}

export interface WidgetComponentProps {
  config: WidgetConfig;
}

/** One user-editable config field, rendered by the widget settings popover. */
export interface WidgetConfigField {
  key: string;
  label: string;
  type: "number" | "select" | "boolean";
  min?: number;
  max?: number;
  options?: Array<{ value: string; label: string }>;
}

export interface WidgetDefinition {
  /** Stable widget type ID stored in dashboard configs. Renaming any of these will break saved dashboards. */
  type: string;
  /** Human-readable label shown in the picker and as the default title when added. */
  label: string;
  /** Short description shown in the picker card. */
  description: string;
  /** Default grid width when newly added. */
  defaultW: number;
  /** Default grid height when newly added. */
  defaultH: number;
  /** React component that renders the widget body. */
  component: ComponentType<WidgetComponentProps>;
  /**
   * Optional config patch merged into the resolved config before rendering.
   * Used to specialize a generic component (e.g. TrendingEntitiesWidget) for a
   * specific widget type without needing a dedicated component file.
   * Acts as a default layer: the user's saved config overrides it.
   */
  configPatch?: WidgetConfig;
  /** User-editable config fields; presence enables the settings gear. */
  configFields?: WidgetConfigField[];
  /**
   * Hidden widgets don't appear in the picker but still render for dashboards
   * that already persist them (retired types keep working, new adds stop).
   */
  hidden?: boolean;
}

/** Shorthand for the ubiquitous row-limit setting (max mirrors the API bound). */
const limitField = (max: number, label = "Rows"): WidgetConfigField => ({
  key: "limit",
  label,
  type: "number",
  min: 1,
  max,
});

// NOTE: `vendors_trending` / `products_trending` use noun-first ordering while
// `trending_actors` / `trending_cves` / `trending_ttps` / `trending_malware` use
// verb-first ordering. This is intentionally NOT renamed for consistency —
// these ids are persisted in user dashboard configs and a rename would break
// existing dashboards.
export const WIDGET_REGISTRY: WidgetDefinition[] = [
  {
    type: "active_campaigns",
    label: "Active Campaigns",
    description: "Most active campaigns by recent entries",
    defaultW: 4,
    defaultH: 6,
    component: ActiveCampaignsWidget,
    configFields: [limitField(500)],
  },

  /* ── Board widgets (round 2) ── */
  {
    type: "overview_row",
    label: "Overview",
    description: "Headline counts plus new entities of every workbench type, vs the prior window",
    defaultW: 12,
    defaultH: 3,
    component: OverviewRowWidget,
  },
  {
    type: "ransomware_pulse",
    label: "Ransomware Pulse",
    description: "Weekly victim disclosures stacked by ransomware group",
    defaultW: 8,
    defaultH: 4,
    component: RansomwarePulseWidget,
  },
  {
    type: "watchlist_pulse",
    label: "Watchlist Pulse",
    description: "Your watched entities ranked by mention movement",
    defaultW: 4,
    defaultH: 4,
    component: WatchlistPulseWidget,
  },
  {
    type: "rules_attention",
    label: "Rules Needing Attention",
    description: "Detection rules with fresh intel since their last update",
    defaultW: 6,
    defaultH: 4,
    component: RulesAttentionWidget,
    configFields: [limitField(50)],
  },
  {
    type: "targeting_grid",
    label: "Targeting Grid",
    description: "Which sectors are being hit, by region",
    defaultW: 6,
    defaultH: 4,
    component: TargetingGridWidget,
  },
  {
    type: "playbook_drift",
    label: "Playbook Drift",
    description: "New techniques attributed to actors you watch",
    defaultW: 6,
    defaultH: 4,
    component: PlaybookDriftWidget,
  },
  {
    type: "relationship_inbox",
    label: "Relationship Inbox",
    description: "Trust-ladder counts plus claims awaiting confirm or reject",
    defaultW: 4,
    defaultH: 4,
    component: RelationshipInboxWidget,
    configFields: [limitField(25, "Pending claims")],
  },
  {
    type: "telemetry_gaps",
    label: "Telemetry Gaps",
    description: "Log sources you lack, ranked by how many rules they unblock",
    defaultW: 4,
    defaultH: 4,
    component: TelemetryGapsWidget,
    configFields: [limitField(20, "Sources")],
  },
  {
    type: "kev_deadlines",
    label: "KEV Deadlines",
    description: "CISA remediation due dates for KEV-listed CVEs, soonest first",
    defaultW: 4,
    defaultH: 4,
    component: KEVDeadlinesWidget,
    configFields: [limitField(50)],
  },
  {
    type: "triage_flow",
    label: "Triage Flow",
    description: "Entries arriving versus entries you read, per day",
    defaultW: 6,
    defaultH: 3,
    component: TriageFlowWidget,
    configFields: [{ key: "days", label: "Days", type: "number", min: 7, max: 90 }],
  },
  {
    type: "campaign_momentum",
    label: "Campaign Momentum",
    description: "Open campaigns as activity strips — accelerating, steady, or quiet",
    defaultW: 6,
    defaultH: 3,
    component: CampaignMomentumWidget,
    configFields: [limitField(20, "Campaigns")],
  },
  {
    type: "under_reported",
    label: "Under the Radar",
    description: "High-severity items with thin source coverage",
    defaultW: 6,
    defaultH: 3,
    component: UnderReportedWidget,
    configFields: [limitField(50)],
  },
  {
    type: "morning_briefing",
    label: "Morning Briefing",
    description: "The latest AI daily summary, with entity links",
    defaultW: 6,
    defaultH: 4,
    component: MorningBriefingWidget,
  },
  {
    type: "kev_matches",
    label: "Actively Exploited CVEs",
    description: "Recently mentioned CVEs flagged as actively exploited",
    defaultW: 4,
    defaultH: 4,
    component: KEVMatchesWidget,
    configFields: [limitField(200)],
  },
  {
    type: "actor_activity_timeline",
    label: "Actor Activity",
    description: "Sparkline of mentions per top actor",
    defaultW: 6,
    defaultH: 4,
    component: ActorActivityTimelineWidget,
  },
  {
    type: "ai_usage",
    label: "AI Usage",
    description: "Calls, tokens, and cost per AI provider",
    defaultW: 6,
    defaultH: 3,
    component: AIUsageWidget,
  },
  {
    type: "analytics_overview",
    label: "Analytics Overview",
    description: "Entity counts and event summary",
    defaultW: 6,
    defaultH: 3,
    component: OverviewWidget,
    /** Superseded by the Overview row widget. */
    hidden: true,
  },
  {
    type: "attack_coverage_gap",
    label: "ATT&CK Coverage Gap",
    description: "Observed TTPs with no detection rule",
    defaultW: 4,
    defaultH: 4,
    component: AttackCoverageGapWidget,
    configFields: [limitField(200)],
  },
  {
    type: "attack_heatmap",
    label: "ATT&CK Heatmap",
    description: "MITRE ATT&CK technique frequency",
    defaultW: 8,
    defaultH: 4,
    component: AttackHeatmap,
  },
  {
    type: "automation_logs",
    label: "Automation Logs",
    description: "Recent automation execution logs with status summary",
    defaultW: 4,
    defaultH: 4,
    component: AutomationLogsWidget,
    configFields: [limitField(100)],
  },
  {
    type: "correlation_events_feed",
    label: "Correlation Events",
    description: "Recent correlation event feed",
    defaultW: 4,
    defaultH: 4,
    component: CorrelationEventsWidget,
    configFields: [limitField(500)],
  },
  {
    type: "correlation_browser",
    label: "Correlation Events Browser",
    description: "Browse, filter, and triage every correlation event",
    defaultW: 12,
    defaultH: 8,
    component: CorrelationBrowserWidget,
  },
  {
    type: "cve_severity",
    label: "CVE Severity",
    description: "CVE distribution by severity",
    defaultW: 4,
    defaultH: 3,
    component: CVESeverityChart,
  },
  {
    type: "detection_coverage",
    label: "Detection Coverage",
    description: "TTP detection rule coverage",
    defaultW: 3,
    defaultH: 3,
    component: DetectionCoverageWidget,
  },
  {
    type: "detection_format_breakdown",
    label: "Detection Format Breakdown",
    description: "Detection rules grouped by rule type",
    defaultW: 4,
    defaultH: 3,
    component: DetectionFormatBreakdownWidget,
  },
  {
    type: "feed_activity",
    label: "Feed Activity",
    description: "Article count over time",
    defaultW: 6,
    defaultH: 3,
    component: FeedActivityChart,
  },
  {
    type: "feed_health",
    label: "Feed Health",
    description: "Failing or stale feeds with last error and fetch age",
    defaultW: 4,
    defaultH: 4,
    component: FeedHealthWidget,
    configFields: [limitField(200)],
  },
  {
    type: "hot_correlations",
    label: "Hot Correlations",
    description: "Top co-occurring entity pairs in the window",
    defaultW: 4,
    defaultH: 4,
    component: HotCorrelationsWidget,
    configFields: [limitField(100)],
  },
  {
    type: "intel_velocity",
    label: "Intel Velocity",
    description: "New entities per day by type",
    defaultW: 6,
    defaultH: 3,
    component: IntelVelocityAnalyticsWidget,
  },
  {
    type: "latest_entries",
    label: "Latest Entries",
    description: "Most recent feed entries",
    defaultW: 4,
    defaultH: 4,
    component: LatestEntries,
    configFields: [limitField(100)],
  },
  {
    type: "new_actors",
    label: "New Actors",
    description: "Recently discovered threat actors",
    defaultW: 4,
    defaultH: 4,
    component: NewActorsWidget,
  },
  {
    type: "new_cves",
    label: "New CVEs",
    description: "Recently published CVEs with CVSS and mentions",
    defaultW: 4,
    defaultH: 4,
    component: NewCVEsWidget,
  },
  {
    type: "new_detections",
    label: "New Detections",
    description: "Recently created detection rules with type, severity, and source",
    defaultW: 4,
    defaultH: 5,
    component: NewDetectionsWidget,
    configFields: [limitField(100)],
  },
  {
    type: "pir_coverage",
    label: "PIR Coverage",
    description: "Intelligence requirement fulfillment status",
    defaultW: 4,
    defaultH: 3,
    component: PIRCoverageWidget,
  },
  {
    type: "saved_search_hits",
    label: "Saved Search Hits",
    description: "Unread and total counts per saved search",
    defaultW: 4,
    defaultH: 4,
    component: SavedSearchHitsWidget,
  },
  {
    type: "source_reliability",
    label: "Source Reliability",
    description: "Feed source intel contribution matrix",
    defaultW: 6,
    defaultH: 4,
    component: SourceReliabilityWidget,
  },
  {
    type: "stat_card",
    label: "Stat Card",
    description: "Single stat with trend indicator",
    defaultW: 3,
    defaultH: 2,
    component: StatCard,
    /** Superseded by the Overview row widget. */
    hidden: true,
  },
  {
    type: "targeted_countries",
    label: "Targeted Countries",
    description: "Top countries appearing as attack targets",
    defaultW: 4,
    defaultH: 6,
    component: TargetedCountriesWidget,
    configFields: [limitField(500)],
  },
  {
    type: "telegram_mentions",
    label: "Telegram Mentions",
    description: "Most-mentioned Telegram channels",
    defaultW: 4,
    defaultH: 4,
    component: TelegramMentionsWidget,
    configFields: [limitField(100)],
  },
  {
    type: "top_tags",
    label: "Top Tags",
    description: "Most-applied tags in the time window",
    defaultW: 4,
    defaultH: 3,
    component: TopTagsWidget,
    configFields: [limitField(100)],
  },
  {
    type: "trending_actors",
    label: "Trending Actors",
    description: "Top threat actors by article count",
    defaultW: 4,
    defaultH: 4,
    component: TrendingEntitiesWidget,
    configPatch: { entity_type: "threat_actor" },
  },
  {
    type: "trending_cves",
    label: "Trending CVEs",
    description: "Most-mentioned CVEs this week",
    defaultW: 4,
    defaultH: 4,
    component: TrendingCVEs,
    configFields: [limitField(500)],
  },
  {
    type: "trending_malware",
    label: "Trending Malware",
    description: "Top malware families by mentions",
    defaultW: 4,
    defaultH: 4,
    component: TrendingEntitiesWidget,
    configPatch: { entity_type: "malware" },
  },
  {
    type: "products_trending",
    label: "Trending Products",
    description: "Top products by article mentions",
    defaultW: 4,
    defaultH: 6,
    component: ProductsTrendingWidget,
    configFields: [limitField(500)],
  },
  {
    type: "trending_ttps",
    label: "Trending TTPs",
    description: "Most observed MITRE techniques",
    defaultW: 4,
    defaultH: 4,
    component: TrendingEntitiesWidget,
    configPatch: { entity_type: "ttp" },
  },
  {
    type: "vendors_trending",
    label: "Trending Vendors",
    description: "Top vendors by article mentions",
    defaultW: 4,
    defaultH: 6,
    component: VendorsTrendingWidget,
    configFields: [limitField(500)],
  },
  {
    type: "triage_queue_stats",
    label: "Triage Queue Stats",
    description: "Unread, starred, and total counts",
    defaultW: 3,
    defaultH: 2,
    component: TriageQueueStatsWidget,
    /** Superseded by the Overview row widget. */
    hidden: true,
  },
  {
    type: "unread_count",
    label: "Unread Count",
    description: "Unread entry count",
    defaultW: 2,
    defaultH: 2,
    component: StatCard,
    configPatch: { stat_type: "unread" },
    /** Superseded by the Overview row widget. */
    hidden: true,
  },
  {
    type: "weekly_recap",
    label: "Weekly Recap",
    description: "Entries, actors, CVEs, and detections vs prior window",
    defaultW: 6,
    defaultH: 2,
    component: WeeklyRecapWidget,
    /** Superseded by the Overview row widget. */
    hidden: true,
  },
  {
    type: "worker_queue",
    label: "Worker Queue",
    description: "Celery task queue depth and Redis status",
    defaultW: 2,
    defaultH: 2,
    component: WorkerQueueWidget,
  },
];

const REGISTRY_BY_TYPE: Record<string, WidgetDefinition> = WIDGET_REGISTRY.reduce(
  (acc, def) => {
    acc[def.type] = def;
    return acc;
  },
  {} as Record<string, WidgetDefinition>,
);

export function getWidgetDefinition(type: string): WidgetDefinition | undefined {
  return REGISTRY_BY_TYPE[type];
}
