/**
 * Shared convert-type action — used by the profile/table actions menu and by the
 * reader's "Wrong? → wrong type" menu, so both prompt for the same things and
 * describe the same consequences.
 */
import { toast } from "sonner";
import { confirmDialog, promptDialog } from "@/utils/dialog";
import { getEntityLabel } from "@/utils/entityTheme";
import type { EntityType } from "@/stores/intelStore";

/** Every type the /entities/convert engine understands, in menu order.
 *  cve/ttp carry an external identity we can't derive from a name, so they need
 *  one prompted for when they're the *target*. */
export const CONVERTIBLE_TYPES: { key: EntityType; label: string; needsIdentifier?: "cve" | "ttp" }[] = [
  { key: "threat_actor", label: "Threat Actor" },
  { key: "malware", label: "Malware Family" },
  { key: "tool", label: "Tool" },
  { key: "vendor", label: "Vendor" },
  { key: "product", label: "Product" },
  { key: "country", label: "Country" },
  { key: "cve", label: "CVE", needsIdentifier: "cve" },
  { key: "ttp", label: "TTP (ATT&CK technique)", needsIdentifier: "ttp" },
];

export type ConvertTarget = (typeof CONVERTIBLE_TYPES)[number];

export function convertTargetsFor(entityType: string): ConvertTarget[] {
  // Observables have a (kind, value) identity, not a name — the convert engine
  // can't make a threat actor out of an IP, so a ledger row offers no targets.
  if (entityType === "observable") return [];
  return CONVERTIBLE_TYPES.filter((t) => t.key !== entityType);
}

interface RunConvertArgs {
  entityType: string;
  entityId: string;
  target: ConvertTarget;
  /** The useConvertEntity() mutation from the calling component. */
  convert: {
    mutate: (
      vars: { entityId: string; targetType: string; targetIdentifier?: string },
      opts: { onSuccess: () => void; onError: (err: unknown) => void },
    ) => void;
  };
  onConverted?: () => void;
}

/** Prompt, confirm, then convert. No-op if the analyst cancels either dialog. */
export async function runEntityConvert({
  entityType,
  entityId,
  target,
  convert,
  onConverted,
}: RunConvertArgs): Promise<void> {
  let targetIdentifier: string | undefined;
  if (target.needsIdentifier) {
    const isCve = target.needsIdentifier === "cve";
    const answer = await promptDialog({
      title: isCve ? "CVE ID" : "ATT&CK technique ID",
      message: isCve
        ? "Enter the CVE ID for the new record (e.g. CVE-2024-1234):"
        : "Enter the ATT&CK technique ID for the new record (e.g. T1059 or T1059.001):",
      placeholder: isCve ? "CVE-2024-1234" : "T1059.001",
    });
    if (!answer) return;
    targetIdentifier = answer;
  }

  const dropsNote =
    target.needsIdentifier || entityType === "country"
      ? " Type-specific fields (and any origin/targeting links) will be dropped."
      : "";
  if (
    !(await confirmDialog({
      title: `Convert to ${target.label}`,
      message: `Convert this ${getEntityLabel(entityType)} to ${target.label}? Entry links, relationships, notes and campaign memberships will be migrated.${dropsNote}`,
      confirmLabel: "Convert",
      destructive: true,
    }))
  )
    return;

  convert.mutate(
    { entityId, targetType: target.key, targetIdentifier },
    {
      onSuccess: () => {
        toast.success(`Converted to ${target.label}`);
        onConverted?.();
      },
      onError: (err: unknown) => {
        const data = (err as { response?: { data?: { error?: { message?: string }; detail?: string } } })?.response
          ?.data;
        toast.error(data?.error?.message || data?.detail || "Conversion failed");
      },
    },
  );
}
