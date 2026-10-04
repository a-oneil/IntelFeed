import { describe, it, expect } from "vitest";
import { STEPS, skipReason, visibleSteps } from "../steps";
import type { OnboardingStatus } from "@/api/types";

const READY: OnboardingStatus = {
  reference_data: { ok: true, checks: [], missing: [], remedy: "", consequence: "" },
  feeds: { total: 37, polled_ok: 34, errored: 0, never_polled: 3 },
  entries: { total: 1284, last_24h: 1284 },
  autolink: { entity_links: 412 },
  ai: { providers: 1, active: "ollama" },
  ready: true,
};

const FRESH: OnboardingStatus = {
  reference_data: {
    ok: false,
    checks: [],
    missing: ["countries", "attack"],
    remedy: "python scripts/seed/seed_all.py",
    consequence: "nothing will link",
  },
  feeds: { total: 0, polled_ok: 0, errored: 0, never_polled: 0 },
  entries: { total: 0, last_24h: 0 },
  autolink: { entity_links: 0 },
  ai: { providers: 1, active: "claude_code" },
  ready: false,
};

const nonSetup = STEPS.filter((s) => s.chapter !== "setup").length;

describe("onboarding step selection", () => {
  it("gives a fresh admin the whole flow", () => {
    const steps = visibleSteps(true, FRESH);
    expect(steps).toEqual(STEPS);
    expect(steps.some((s) => s.id === "readiness")).toBe(true);
  });

  it("drops satisfied setup steps for an admin on a running instance", () => {
    const steps = visibleSteps(true, READY);
    expect(steps.map((s) => s.id)).not.toContain("readiness");
    expect(steps.map((s) => s.id)).not.toContain("feeds");
    expect(steps.map((s) => s.id)).not.toContain("ai");
    expect(steps.map((s) => s.id)).not.toContain("verify");
  });

  it("hides every setup step from a non-admin", () => {
    const steps = visibleSteps(false, READY);
    expect(steps.every((s) => s.chapter !== "setup")).toBe(true);
  });

  it("never leaves a non-admin with a gutted wizard", () => {
    // The old flow gave a second analyst five steps: welcome, theme, shortcuts,
    // docs and a CLI install guide. Dropping setup must mean *more* product
    // content, not a shorter wizard.
    const steps = visibleSteps(false, READY);
    expect(steps.length).toBe(nonSetup);
    expect(steps.length).toBeGreaterThanOrEqual(9);
    for (const id of ["reader", "queue", "entities", "search"]) {
      expect(steps.map((s) => s.id)).toContain(id);
    }
  });

  it("explains why a step was dropped rather than silently vanishing", () => {
    const readiness = STEPS.find((s) => s.id === "readiness")!;
    expect(skipReason(readiness, false, READY)).toBe("admin only");
    expect(skipReason(readiness, true, READY)).toBe("already set up");
    expect(skipReason(readiness, true, FRESH)).toBeNull();
  });

  it("shows setup steps while readiness is still unknown", () => {
    // Showing a step that turns out to be unnecessary is a far smaller failure
    // than hiding the seeding step from an instance that genuinely needs it.
    expect(visibleSteps(true, undefined)).toEqual(STEPS);
  });

  it("does not treat the auto-created claude_code provider as a chosen one", () => {
    // main.py seeds a claude_code provider at startup for the link validator,
    // so its presence says nothing about whether anyone picked a provider.
    const ai = STEPS.find((s) => s.id === "ai")!;
    expect(skipReason(ai, true, FRESH)).toBeNull();
    expect(skipReason(ai, true, READY)).toBe("already set up");
  });

  it("teaches no CLI tooling in the first-run flow", () => {
    expect(STEPS.map((s) => s.id)).not.toContain("skill");
  });

  it("keeps every step inside a known chapter", () => {
    for (const s of STEPS) expect(["intro", "setup", "learn", "yours"]).toContain(s.chapter);
  });
});
