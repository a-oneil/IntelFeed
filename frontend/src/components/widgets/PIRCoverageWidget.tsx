import { useNavigate } from "react-router-dom";
import { useRequirementCoverage } from "@/hooks/useRequirements";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetStatSkeleton } from "@/components/Skeleton";

export default function PIRCoverageWidget({ config }: { config: Record<string, unknown> }) {
  const navigate = useNavigate();
  const setActiveSection = useIntelStore((s) => s.setActiveSection);
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const params = date_from ? { date_from, ...(date_to ? { date_to } : {}) } : undefined;
  const { data, isLoading } = useRequirementCoverage(params);

  if (isLoading) return <WidgetStatSkeleton />;
  if (!data) return <div style={{ color: "var(--text-muted)", fontSize: 13, padding: 16 }}>No PIR data</div>;

  const items = [
    { label: "Active", value: data.active, color: "#3182ce" },
    { label: "Fulfilled", value: data.fulfilled, color: "#38a169" },
    { label: "With Recent Matches", value: data.with_recent_matches, color: "#805ad5" },
    { label: "Stale", value: data.stale, color: "#dd6b20" },
    { label: "Expired", value: data.expired, color: "#e53e3e" },
  ];

  return (
    <div style={{ padding: "12px 16px", height: "100%", display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ fontSize: 24, fontWeight: 700, color: "var(--text-primary)" }}>
        {data.total_requirements}
        <span style={{ fontSize: 13, fontWeight: 400, color: "var(--text-muted)", marginLeft: 6 }}>total PIRs</span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {items.map((item) => (
          <button
            key={item.label}
            onClick={() => { setActiveSection("requirements"); navigate("/workbench/explore"); }}
            style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: 12, background: "none", border: "none", cursor: "pointer", padding: 0, width: "100%" }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: item.color, flexShrink: 0 }} />
              <span style={{ color: "var(--text-secondary)" }}>{item.label}</span>
            </div>
            <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>{item.value}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
