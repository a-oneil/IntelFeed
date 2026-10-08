import type { OnboardingStatus } from "@/api/types";

/**
 * The onboarding flow, as data.
 *
 * Three chapters. The setup chapter is admin-only and each of its steps also
 * knows how to tell whether it is already satisfied, so an admin on a running
 * instance isn't walked through configuring what is already configured.
 *
 * The rule that matters: skipping setup must leave *more* product content, not
 * a shorter wizard. Every persona lands on the whole Learn and Make-it-yours
 * chapters, which is what a second analyst joining the team actually needs —
 * previously they got theme, shortcuts, docs and a CLI install guide.
 */

export type ChapterId = "intro" | "setup" | "learn" | "yours";

export const CHAPTERS: Record<ChapterId, { title: string; blurb: string }> = {
  intro: { title: "Welcome", blurb: "What this is" },
  setup: { title: "Set up", blurb: "Get this instance working" },
  learn: { title: "Learn the app", blurb: "How to actually use it" },
  yours: { title: "Make it yours", blurb: "Settle in" },
};

export type StepId =
  | "welcome"
  | "readiness"
  | "feeds"
  | "ai"
  | "extras"
  | "verify"
  | "reader"
  | "queue"
  | "entities"
  | "search"
  | "workbench"
  | "intel"
  | "theme"
  | "shortcuts"
  | "help";

export interface StepDef {
  id: StepId;
  chapter: ChapterId;
  /** Short name for the chapter rail. */
  label: string;
  adminOnly?: boolean;
  /**
   * Given current instance state, is this step already handled? Satisfied setup
   * steps are dropped, with the reason shown in the rail rather than silently
   * vanishing.
   */
  satisfiedBy?: (status: OnboardingStatus) => boolean;
}

export const STEPS: StepDef[] = [
  // A prologue, not setup: every persona gets it, including the non-admins
  // who never see the setup chapter at all.
  { id: "welcome", chapter: "intro", label: "Welcome" },

  {
    id: "readiness",
    chapter: "setup",
    label: "Reference data",
    adminOnly: true,
    satisfiedBy: (s) => s.reference_data.ok,
  },
  {
    id: "feeds",
    chapter: "setup",
    label: "Add feeds",
    adminOnly: true,
    satisfiedBy: (s) => s.feeds.total > 0,
  },
  {
    id: "ai",
    chapter: "setup",
    label: "AI provider",
    adminOnly: true,
    // Two separate things have to be true, and a provider row proves only the
    // first: claude_code is auto-created at startup for the copilot's default assignment, so
    // its presence says nobody chose anything — and a chosen provider with no
    // task routed at it still runs no AI, which is how this step used to "pass"
    // while the instance did nothing.
    satisfiedBy: (s) => s.ai.active !== null && s.ai.active !== "claude_code" && s.ai.tasks_assigned > 0,
  },
  { id: "extras", chapter: "setup", label: "Services & team", adminOnly: true },
  {
    id: "verify",
    chapter: "setup",
    label: "Verify it works",
    adminOnly: true,
    satisfiedBy: (s) => s.ready,
  },

  { id: "reader", chapter: "learn", label: "The reading loop" },
  { id: "queue", chapter: "learn", label: "Priority Queue" },
  { id: "entities", chapter: "learn", label: "Entities & pivoting" },
  { id: "search", chapter: "learn", label: "Search" },
  { id: "workbench", chapter: "learn", label: "The workbench" },
  { id: "intel", chapter: "learn", label: "Rules & intel products" },

  { id: "theme", chapter: "yours", label: "Appearance" },
  { id: "shortcuts", chapter: "yours", label: "Keyboard" },
  { id: "help", chapter: "yours", label: "Where help lives" },
];

export type SkipReason = "admin only" | "already set up";

/** Why a step isn't in this user's flow, or null if it is. */
export function skipReason(
  step: StepDef,
  isAdmin: boolean,
  status: OnboardingStatus | undefined,
): SkipReason | null {
  if (step.adminOnly && !isAdmin) return "admin only";
  // Without a status read yet, assume nothing is satisfied: showing a step that
  // turns out to be unnecessary is a much smaller failure than hiding the
  // seeding step from an instance that genuinely needs it.
  if (status && step.satisfiedBy?.(status)) return "already set up";
  return null;
}

export function visibleSteps(isAdmin: boolean, status: OnboardingStatus | undefined): StepDef[] {
  return STEPS.filter((s) => skipReason(s, isAdmin, status) === null);
}

export const KEY_GROUPS: { section: string; items: [string, string][] }[] = [
  {
    section: "Navigation",
    items: [
      ["j / ↓", "Next entry"],
      ["k / ↑", "Previous entry"],
      ["o", "Open original article"],
    ],
  },
  {
    section: "Actions",
    items: [
      ["s", "Star / unstar entry"],
      ["b", "Bookmark / unbookmark"],
      ["m", "Toggle read / unread"],
      ["Shift+M", "Mark all above as read"],
      ["n", "Create note on entry"],
      ["t", "Add tag to entry"],
      ["e", "Export entry as markdown"],
    ],
  },
  {
    section: "Panels",
    items: [
      ["⌘+K", "Command palette"],
      ["/", "Open search"],
      ["Escape", "Close panel"],
      ["?", "Show shortcuts help"],
    ],
  },
];
