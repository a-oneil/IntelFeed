import { Chip } from "./primitives";
import type { EntryExposure } from "@/api/types";

/**
 * "Watching {vendor}" chip for radar entries about a vulnerability in a vendor
 * or product the analyst follows, plus a detection-library marker (does
 * IntelFeed have a rule for it) — a landscape property, not personal risk.
 */
export function ExposureChip({ exposure }: { exposure: EntryExposure }) {
  const vendor = exposure.asset_name;
  const cves = exposure.cve_ids.slice(0, 4).join(", ");
  const watchTip = `${cves}${vendor ? ` in ${vendor}, which you follow` : " in a vendor you follow"}`;
  const posture = exposure.posture;
  // covered = a rule exists (defended, or library_only/"blind"); no_rule = gap.
  const covered = posture === "defended" || posture === "blind";
  const gap = posture === "no_rule";

  return (
    <>
      {/* "watching {vendor}" — uses the intel/watch blue */}
      <Chip tone="toned" tint="var(--accent-intel)" pill title={watchTip}>
        ◈ {vendor ?? "followed vendor"}
      </Chip>
      {/* detection-library markers (landscape property) */}
      {covered && (
        <Chip
          tone="toned"
          tint="var(--success)"
          pill
          title="A detection rule for this exists in the library"
        >
          covered
        </Chip>
      )}
      {gap && (
        <Chip
          tone="toned"
          tint="var(--accent-dash)"
          pill
          title="No detection rule in the library yet — a content gap"
        >
          no detection
        </Chip>
      )}
    </>
  );
}
