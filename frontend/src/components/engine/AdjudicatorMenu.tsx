/** AdjudicatorMenu is the single control for the adjudicate stage on the Review tab. It sets the stage's mode (Proposed files verdicts as suggestions in the queue; Applied applies high-confidence verdicts at ingest) and toggles the stage's settings panel, which the console opens above the table. It sits at the right end of the lens row so the stage's controls stay separate from the queue's filters. */

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import api from "@/api/client";
import { DropdownItem, ToolbarDropdown } from "@/components/ToolbarDropdown";
import { useHygieneStats } from "@/hooks/useHygiene";

import styles from "./AdjudicatorMenu.module.css";

type Mode = "off" | "shadow" | "apply";
const MODE_LABEL: Record<Mode, string> = { off: "Off", shadow: "Proposed", apply: "Applied" };
const MODE_KEY = "adjudication_mode";

export function AdjudicatorMenu({
  settingsOpen,
  onToggleSettings,
}: {
  settingsOpen?: boolean;
  onToggleSettings?: () => void;
}) {
  const qc = useQueryClient();
  const stats = useHygieneStats();
  const [pending, setPending] = useState(false);
  const mode: Mode =
    stats.data?.adjudication_mode === "apply" ? "apply" : stats.data?.adjudication_mode === "shadow" ? "shadow" : "off";

  const setMode = async (next: "shadow" | "apply") => {
    if (next === mode || pending) return;
    setPending(true);
    // Patch the cached stats and don't refetch them right away: the per-worker settings cache can return the old value for a moment, which would flip the menu back and look like the change did nothing.
    const patch = (value: Mode) =>
      qc.setQueryData(["hygiene", "stats"], (prev: unknown) =>
        prev && typeof prev === "object" ? { ...(prev as Record<string, unknown>), [MODE_KEY]: value } : prev,
      );
    patch(next);
    try {
      await api.patch("/system-settings", { settings: { [MODE_KEY]: next } });
      toast.success(
        next === "apply"
          ? "Applied mode: high-confidence verdicts are now applied at ingest."
          : "Proposed mode: verdicts are filed as suggestions for review.",
      );
    } catch (e) {
      patch(mode);
      toast.error(`Failed to change mode: ${(e as Error).message}`);
    } finally {
      setPending(false);
    }
  };

  return (
    <ToolbarDropdown
      icon={<span className={styles.system}>Adjudicator</span>}
      label={MODE_LABEL[mode]}
      triggerClassName={styles.trigger}
      title={
        mode === "off"
          ? "The adjudicate stage is off. Pick a mode here, or turn it on from its settings."
          : "Proposed: verdicts are filed as suggestions in this queue. Applied: high-confidence verdicts are applied at ingest."
      }
    >
      <DropdownItem
        label="Proposed"
        title="Verdicts are filed here as suggestions. Nothing changes until a person applies one."
        active={mode === "shadow"}
        disabled={pending}
        onClick={() => void setMode("shadow")}
      />
      <DropdownItem
        label="Applied"
        title="High-confidence verdicts are applied at ingest. The rest are filed here for review."
        active={mode === "apply"}
        disabled={pending}
        onClick={() => void setMode("apply")}
      />
      {onToggleSettings && (
        <DropdownItem
          label={settingsOpen ? "Hide settings" : "Settings…"}
          title="Confidence floor, reclassify consensus, circuit breaker, review scope, the duplicate review's batch and floor"
          onClick={onToggleSettings}
        />
      )}
    </ToolbarDropdown>
  );
}
