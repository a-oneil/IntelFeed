import type {
  EnrichmentConsoleSource,
  EnrichmentEgress,
  EnrichmentKeyStatus,
} from "@/hooks/useEnrichment";

export const num = (n: number) => n.toLocaleString();

/** "about 3 days", "under a day", "about a day". */
export function aboutDays(days: number): string {
  if (days < 1) return "under a day";
  const d = Math.round(days);
  return d === 1 ? "about a day" : `about ${num(d)} days`;
}

export function period(sec: number): string {
  if (sec === 1) return "second";
  if (sec === 60) return "minute";
  if (sec === 3600) return "hour";
  if (sec === 86400) return "day";
  return `${num(sec)} seconds`;
}

/** "every 30 days", "every day", "every 12 hours". */
export function refreshText(days: number): string {
  if (days < 1) {
    const h = Math.max(1, Math.round(days * 24));
    return h === 1 ? "every hour" : `every ${h} hours`;
  }
  const d = Math.round(days);
  return d === 1 ? "every day" : `every ${num(d)} days`;
}

export type Tone = "ok" | "bad" | "warn" | "off";

/** At or past its daily cap: lookups wait for midnight UTC. */
function atCap(x: EnrichmentConsoleSource): boolean {
  return x.enabled && x.daily_budget != null && x.daily_budget > 0 && x.used_today >= x.daily_budget;
}

/** The status word and tone a source shows. Color only marks what needs action. */
export function statusOf(x: EnrichmentConsoleSource): { word: string; tone: Tone } {
  if (x.status === "key_rejected") return { word: "Key rejected", tone: "bad" };
  if (x.status === "failing") return { word: "Failing", tone: "bad" };
  if (x.status === "needs_key") {
    return { word: x.needs && x.needs !== "key" ? `Needs ${x.needs}` : "Needs a key", tone: "off" };
  }
  if (x.status === "off") return { word: "Off", tone: "off" };
  if (atCap(x)) return { word: "At daily cap", tone: "warn" };
  return { word: "Working", tone: "ok" };
}

export const SENDS: Record<EnrichmentEgress, string> = {
  none: "nothing (downloads a file)",
  low: "public ids (a CVE, a name)",
  shares_ioc: "your indicators",
};

export const KEY_STATUS: Record<EnrichmentKeyStatus, string> = {
  set: "set",
  missing: "not set",
  optional: "optional, not set",
  rejected: "rejected",
};
