import { toast } from "sonner";

import {
  type EngineState,
  useClearEngineHealth,
  useEngineHealth,
  useEngineState,
  useSetEngineStopped,
} from "@/hooks/useEngine";
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

/** Turns the header's check-engine light green until a new error or retry
 *  comes in: for failures the admin knows about and has chosen to leave (a
 *  feed worth keeping, an entry that can't be retried). Greyed out while
 *  there is nothing to clear. */
export function ClearCheckEngine() {
  const health = useEngineHealth(true);
  const clear = useClearEngineHealth();
  if (!health) return null;
  const lit = health.level === "err" || health.level === "warn";

  return (
    <button
      type="button"
      className={`${styles.btn} ${styles.secondary}`}
      onClick={() =>
        clear.mutate(undefined, {
          onSuccess: () => toast.success("Check engine cleared until the next error"),
          onError: () => toast.error("Could not clear the check-engine light"),
        })
      }
      disabled={!lit || clear.isPending}
      title={
        lit
          ? "Turn the header light green until a new error or retry comes in. The errors stay in the console."
          : health.level === "stopped"
            ? "The light shows the engine is stopped until you start it again."
            : "No new errors or retries to clear."
      }
    >
      Clear check engine
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
