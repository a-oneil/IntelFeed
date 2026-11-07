import { useNavigate } from "react-router-dom";

import { ERROR_LIGHT_THRESHOLD, useEngineHealth, type EngineHealth } from "@/hooks/useEngine";
import { useIsAdmin } from "@/stores/authStore";
import { useUIStore } from "@/stores/uiStore";

import { Hint } from "./primitives";
import styles from "./AppHeader.module.css";

/** Check-engine light: an engine block with intake, exhaust and mount, in a
 *  24-unit box. Shared with the settings nav so the two always match. */
export const ENGINE_ICON_PATH = "M7 6h6M10 6v3M5 9h10l2 2h2v-2h2v8h-2v-2h-2v3h-9l-3-3H3v-3h2z";
/** The block only fills the middle of its box; crop to it so it reads at the
 *  size of the icons around it. */
export const ENGINE_ICON_VIEWBOX = "2 2 20 20";

function formatClearedAt(iso: string): string {
  return `at ${new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}`;
}

function describe(h: EngineHealth): { title: string; body: string } {
  switch (h.level) {
    case "stopped":
      return { title: "Engine stopped", body: "No feeds are polled and no background work runs until you start it again." };
    case "err": {
      const total = h.failing.reduce((n, f) => n + f.count, 0);
      const where = h.failing.map((f) => `${f.stage} ${f.count.toLocaleString()}`).join(", ");
      return {
        title: "Engine errors",
        body: `${total.toLocaleString()} ${total === 1 ? "entry is" : "entries are"} stuck at a stage (${where}).`,
      };
    }
    case "warn":
      return { title: "Engine retrying", body: `${h.retrying.toLocaleString()} runs retried in the last 24 hours.` };
    default:
      if (h.failing.length) {
        const total = h.failing.reduce((n, f) => n + f.count, 0);
        return {
          title: "Engine healthy",
          body: `${total.toLocaleString()} ${total === 1 ? "entry is" : "entries are"} stuck at a stage, under the ${ERROR_LIGHT_THRESHOLD} it takes to turn the light red.`,
        };
      }
      if (h.clearedAt && h.clearedErrors) {
        return {
          title: "Engine healthy",
          body:
            `Nothing new since you cleared the light ${formatClearedAt(h.clearedAt)}. ` +
            `${h.clearedErrors.toLocaleString()} older ${h.clearedErrors === 1 ? "error is" : "errors are"} still in the Engine console.`,
        };
      }
      return { title: "Engine healthy", body: "Every stage ran clean in the last 24 hours." };
  }
}

/** Check-engine light in the header: admins only, opens the Engine console
 *  with the settings nav collapsed. */
export function EngineStatusButton() {
  const isAdmin = useIsAdmin();
  const health = useEngineHealth(isAdmin);
  const setSettingsNavCollapsed = useUIStore((s) => s.setSettingsNavCollapsed);
  const navigate = useNavigate();
  if (!isAdmin || !health) return null;
  const { title, body } = describe(health);

  return (
    <Hint title={title} body={body} aside="Click to open the Engine console." align="end">
      <button
        className={`${styles.iconBtn} ${styles[`engine_${health.level}`]}`}
        onClick={() => {
          // The Engine console wants the width: fold the settings nav away.
          // The rail's own toggle brings it back.
          setSettingsNavCollapsed(true);
          navigate("/settings?section=engine");
        }}
        aria-label={title}
        data-level={health.level}
      >
        <svg width="18" height="18" viewBox={ENGINE_ICON_VIEWBOX} fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d={ENGINE_ICON_PATH} />
        </svg>
      </button>
    </Hint>
  );
}
