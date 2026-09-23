import { Component, type ReactNode } from "react";
import type { DashboardWidget } from "@/api/types";
import { getWidgetDefinition } from "./registry";

export type TimeRange = "24h" | "7d" | "30d" | "90d" | "1y" | "all" | "custom";

interface Props {
  widget: DashboardWidget;
  timeRange?: TimeRange;
  timeRangeStart?: string;
  timeRangeEnd?: string;
}

class WidgetErrorBoundary extends Component<
  { children: ReactNode },
  { hasError: boolean }
> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ color: "var(--text-muted)", fontSize: 13, display: "flex", alignItems: "center", justifyContent: "center", height: "100%" }}>
          Widget failed to load
        </div>
      );
    }
    return this.props.children;
  }
}

function timeRangeToDays(range: TimeRange, start?: string, end?: string): number {
  if (range === "custom" && start && end) {
    const ms = new Date(end).getTime() - new Date(start).getTime();
    return Math.max(1, Math.round(ms / 86400000));
  }
  switch (range) {
    case "24h": return 1;
    case "7d": return 7;
    case "30d": return 30;
    case "90d": return 90;
    case "1y": return 365;
    case "all": return 36500;
    default: return 30;
  }
}

function timeRangeToDateFrom(range: TimeRange, start?: string, end?: string): { date_from?: string; date_to?: string } {
  if (range === "custom" && start && end) {
    return { date_from: start, date_to: end };
  }
  if (range === "all") return {};
  const days = timeRangeToDays(range);
  const from = new Date();
  from.setDate(from.getDate() - days);
  return { date_from: from.toISOString().slice(0, 10) };
}

function WidgetContent({ widget, timeRange, timeRangeStart, timeRangeEnd }: Props) {
  const config = widget.config as Record<string, unknown>;
  const tr = timeRange || "30d";
  const dateParams = timeRangeToDateFrom(tr, timeRangeStart, timeRangeEnd);
  const days = timeRangeToDays(tr, timeRangeStart, timeRangeEnd);
  const configWithTime = { ...config, timeRange: tr, timeRangeStart, timeRangeEnd, days, date_from: dateParams.date_from, date_to: dateParams.date_to };

  const def = getWidgetDefinition(widget.widget_type);
  if (!def) {
    return <div style={{ color: "var(--text-muted)", fontSize: 13 }}>Unknown widget: {widget.widget_type}</div>;
  }

  const Component = def.component;
  // Precedence (lowest → highest): registry defaults (configPatch) → the
  // user's saved per-widget config → the dashboard's global time range.
  // User config must beat configPatch so the settings popover works; the
  // global range stays authoritative over both ("one range, one truth").
  const finalConfig = def.configPatch ? { ...def.configPatch, ...configWithTime } : configWithTime;
  return <Component config={finalConfig} />;
}

export default function WidgetRenderer({ widget, timeRange, timeRangeStart, timeRangeEnd }: Props) {
  return (
    <WidgetErrorBoundary>
      <WidgetContent widget={widget} timeRange={timeRange} timeRangeStart={timeRangeStart} timeRangeEnd={timeRangeEnd} />
    </WidgetErrorBoundary>
  );
}
