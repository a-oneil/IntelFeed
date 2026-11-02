import { toast } from "sonner";

import { type EngineState, useEngineState, useSetEngineStopped } from "@/hooks/useEngine";
import { confirmDialog } from "@/utils/dialog";

import styles from "./EngineSwitch.module.css";

/** Tasks waiting across every queue, or null when Redis couldn't be asked. */
function queuedCount(state: EngineState): number | null {
  const counts = Object.values(state.queued);
  if (counts.some((n) => n === null)) return null;
  return counts.reduce<number>((a, b) => a + (b ?? 0), 0);
}

function queuedNote(queued: number | null): string {
  if (queued === null) return "How many tasks are waiting is unknown: Redis couldn't be asked.";
  return queued ? `${queued} queued tasks are waiting.` : "";
}

/** Stops or starts all background work. Sits in the Engine top bar. */
export function EngineSwitch() {
  const { data } = useEngineState();
  const setStopped = useSetEngineStopped();
  if (!data) return null;
  const { stopped } = data;
  const queued = queuedCount(data);

  const toggle = async () => {
    const next = !stopped;
    const confirmed = await confirmDialog({
      title: next ? "Stop the engine?" : "Start the engine?",
      message: next
        ? "Feed polling, AI analysis, enrichment, automations and scheduled jobs all stop. " +
          "Anything already queued waits until you start the engine again.\n\n" +
          "Reading, search, editing and AI you run yourself keep working."
        : queued
          ? `Everything picks up where it stopped, starting with the ${queued} queued tasks.`
          : "Everything picks up where it stopped.",
      confirmLabel: next ? "Stop engine" : "Start engine",
      destructive: next,
    });
    if (!confirmed) return;
    setStopped.mutate(next, {
      onSuccess: (s) => toast.success(s.stopped ? "Engine stopped" : "Engine started"),
      onError: () => toast.error(next ? "Could not stop the engine" : "Could not start the engine"),
    });
  };

  return (
    <button
      type="button"
      className={`${styles.btn} ${stopped ? styles.stopped : ""}`}
      onClick={toggle}
      disabled={setStopped.isPending}
      title={stopped ? "Start all background work again" : "Stop all background work"}
    >
      <span className={styles.icon} aria-hidden>
        {stopped ? "▶" : "■"}
      </span>
      {stopped ? "Start engine" : "Stop engine"}
    </button>
  );
}

/** Shown at the top of the Engine pages while the engine is stopped. */
export function EngineStoppedBanner() {
  const { data } = useEngineState();
  if (!data?.stopped) return null;
  const queued = queuedCount(data);
  return (
    <div className={styles.banner} role="status">
      <strong>Engine stopped.</strong> No feeds are polled and no automations or
      scheduled jobs will run while the engine is stopped. {queuedNote(queued)}
    </div>
  );
}
