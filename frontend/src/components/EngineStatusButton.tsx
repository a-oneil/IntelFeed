import { useNavigate } from "react-router-dom";

import { useEngineHealth, type EngineHealth } from "@/hooks/useEngine";
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

const entries = (n: number) => `${n.toLocaleString()} ${n === 1 ? "entry is" : "entries are"} erroring.`;

function describe(h: EngineHealth): { title: string; body: string } {
  const failing = h.failing.reduce((n, f) => n + f.count, 0);
  switch (h.level) {
    case "stopped":
      return { title: "Engine stopped", body: "Nothing runs until you start it." };
    case "err":
      return { title: "Engine errors", body: entries(failing) };
    case "warn":
      return {
        title: "Engine retrying",
        body: `${h.retrying.toLocaleString()} ${h.retrying === 1 ? "run is" : "runs are"} retrying.`,
      };
    default:
      return { title: "Engine healthy", body: failing ? entries(failing) : "No errors." };
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
    <Hint title={title} body={body} aside="Click to open the Engine." align="end">
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
