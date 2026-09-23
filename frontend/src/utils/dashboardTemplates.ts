export interface DashboardTemplate {
  name: string;
  description: string;
  widgets: Array<{
    widget_type: string;
    title: string;
    width: number;
    height: number;
    position_x: number;
    position_y: number;
    config?: Record<string, unknown>;
  }>;
}

export const DASHBOARD_TEMPLATES: DashboardTemplate[] = [
  {
    name: "Morning Triage",
    description: "Start your day: the overview row, overnight briefing, radar items, and what's moving",
    widgets: [
      { widget_type: "overview_row", title: "Overview", width: 12, height: 3, position_x: 0, position_y: 0 },
      { widget_type: "morning_briefing", title: "Morning Briefing", width: 6, height: 4, position_x: 0, position_y: 3 },
      { widget_type: "under_reported", title: "Under the Radar", width: 6, height: 4, position_x: 6, position_y: 3 },
      { widget_type: "watchlist_pulse", title: "Watchlist Pulse", width: 4, height: 4, position_x: 0, position_y: 7 },
      { widget_type: "correlation_browser", title: "Correlation Events", width: 8, height: 4, position_x: 4, position_y: 7 },
      { widget_type: "triage_flow", title: "Triage Flow", width: 6, height: 3, position_x: 0, position_y: 11 },
      { widget_type: "latest_entries", title: "Latest Articles", width: 6, height: 3, position_x: 6, position_y: 11 },
    ],
  },
  {
    name: "Detection Engineering",
    description: "ATT&CK heatmap, rules needing attention, telemetry gaps, and coverage",
    widgets: [
      { widget_type: "attack_heatmap", title: "ATT&CK Heatmap", width: 12, height: 5, position_x: 0, position_y: 0 },
      { widget_type: "rules_attention", title: "Rules Needing Attention", width: 6, height: 4, position_x: 0, position_y: 5 },
      { widget_type: "telemetry_gaps", title: "Telemetry Gaps", width: 6, height: 4, position_x: 6, position_y: 5 },
      { widget_type: "detection_coverage", title: "Detection Coverage", width: 4, height: 4, position_x: 0, position_y: 9 },
      { widget_type: "attack_coverage_gap", title: "ATT&CK Coverage Gap", width: 4, height: 4, position_x: 4, position_y: 9 },
      { widget_type: "new_detections", title: "New Detections", width: 4, height: 4, position_x: 8, position_y: 9 },
    ],
  },
  {
    name: "Ransomware Ops",
    description: "Victim disclosures, sector targeting, watched groups, and campaign momentum",
    widgets: [
      { widget_type: "ransomware_pulse", title: "Ransomware Pulse", width: 8, height: 4, position_x: 0, position_y: 0 },
      { widget_type: "watchlist_pulse", title: "Watchlist Pulse", width: 4, height: 4, position_x: 8, position_y: 0 },
      { widget_type: "targeting_grid", title: "Targeting Grid", width: 6, height: 4, position_x: 0, position_y: 4 },
      { widget_type: "playbook_drift", title: "Playbook Drift", width: 6, height: 4, position_x: 6, position_y: 4 },
      { widget_type: "campaign_momentum", title: "Campaign Momentum", width: 6, height: 3, position_x: 0, position_y: 8 },
      { widget_type: "active_campaigns", title: "Active Campaigns", width: 6, height: 3, position_x: 6, position_y: 8 },
    ],
  },
  {
    name: "Threat Landscape",
    description: "Track threat actors, malware families, and new CVEs across your feeds",
    widgets: [
      { widget_type: "new_actors", title: "New Threat Actors", width: 6, height: 4, position_x: 0, position_y: 0 },
      { widget_type: "trending_malware", title: "Trending Malware", width: 6, height: 4, position_x: 6, position_y: 0 },
      { widget_type: "trending_cves", title: "New CVEs", width: 6, height: 4, position_x: 0, position_y: 4 },
      { widget_type: "intel_velocity", title: "Intel Velocity", width: 6, height: 4, position_x: 6, position_y: 4 },
      { widget_type: "trending_actors", title: "Trending Actors", width: 4, height: 4, position_x: 0, position_y: 8 },
      { widget_type: "source_reliability", title: "Source Reliability", width: 8, height: 4, position_x: 4, position_y: 8 },
    ],
  },
  {
    name: "Vulnerability Intel",
    description: "KEV remediation deadlines, exploited CVEs, severity mix, and what's under-covered",
    widgets: [
      { widget_type: "kev_deadlines", title: "KEV Deadlines", width: 4, height: 4, position_x: 0, position_y: 0 },
      { widget_type: "kev_matches", title: "Actively Exploited CVEs", width: 4, height: 4, position_x: 4, position_y: 0 },
      { widget_type: "trending_cves", title: "Trending CVEs", width: 4, height: 4, position_x: 8, position_y: 0 },
      { widget_type: "cve_severity", title: "CVE Severity", width: 6, height: 4, position_x: 0, position_y: 4 },
      { widget_type: "under_reported", title: "Under the Radar", width: 6, height: 4, position_x: 6, position_y: 4 },
    ],
  },
];
