import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useAuthStore } from "@/stores/authStore";
import { useOnboardingStatus, useSaveOnboardingProgress } from "@/hooks/useOnboarding";
import { useThemes, useSetThemePreference } from "@/hooks/useThemes";
import { CHAPTERS, STEPS, skipReason, visibleSteps, type StepId } from "./steps";
import { StepBody } from "./StepBody";
import { IntelFeedLogo } from "../IntelFeedLogo";
import styles from "./OnboardingWizard.module.css";

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function OnboardingWizard() {
  const runId = useAuthStore((s) => s.user?.settings?.onboarding_run_id as string | undefined);
  // Replay starts a new session even when the previous tour was only deferred.
  return <OnboardingSession key={runId} />;
}

function OnboardingSession() {
  const user = useAuthStore((s) => s.user);
  const isAdmin = user?.role === "admin";
  const saveProgress = useSaveOnboardingProgress();
  const { data: status, refetch: refetchStatus, isLoading: statusLoading } = useOnboardingStatus();
  const themes = useThemesSafely();

  const [dismissed, setDismissed] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const restoreFocusTo = useRef<Element | null>(null);

  const steps = useMemo(() => visibleSteps(!!isAdmin, status), [isAdmin, status]);

  // Resume where they left off. Closing the modal saves the step; only
  // finishing sets onboarding_completed, so a stray Escape can no longer burn
  // the entire flow for an account — which it used to.
  // Track position by step id, never by index. The visible set legitimately
  // changes under the user — they run the seeder and re-check, a feed finishes
  // polling — and an index would silently point at a different step when it
  // does, teleporting them mid-sentence.
  const savedStep = user?.settings?.onboarding_step as StepId | undefined;
  const [currentId, setCurrentId] = useState<StepId | null>(null);
  const resumed = useRef(false);
  useEffect(() => {
    if (resumed.current || statusLoading || !steps.length) return;
    resumed.current = true;
    setCurrentId(savedStep && steps.some((s) => s.id === savedStep) ? savedStep : steps[0].id);
  }, [savedStep, steps, statusLoading]);

  // If the step they were on disappears (they just satisfied it), fall to the
  // next one still standing rather than back to the beginning.
  const found = steps.findIndex((s) => s.id === currentId);
  const position = STEPS.findIndex((s) => s.id === currentId);
  const nextRemaining = steps.findIndex((s) => STEPS.indexOf(s) > position);
  const index = found >= 0 ? found : nextRemaining >= 0 ? nextRemaining : steps.length - 1;
  const step = steps[index];
  const isLast = index === steps.length - 1;

  useEffect(() => {
    if (currentId !== null && found < 0 && step) setCurrentId(step.id);
  }, [currentId, found, step]);

  // Closing saves the step *and* records the deferral. `dismissed` dies with the
  // page, so without the second half every hard refresh reopened the tour and
  // closing meant nothing until you walked all the way to Finish.
  const close = useCallback(() => {
    setDismissed(true);
    saveProgress.mutate({
      onboarding_step: step?.id ?? null,
      onboarding_deferred_at: new Date().toISOString(),
    });
  }, [saveProgress, step]);

  const finish = useCallback(() => {
    setDismissed(true);
    saveProgress.mutate({
      onboarding_completed: true,
      onboarding_step: null,
      onboarding_deferred_at: null,
    });
  }, [saveProgress]);

  const goTo = useCallback(
    (id: StepId) => {
      setCurrentId(id);
      saveProgress.mutate({ onboarding_step: id });
    },
    [saveProgress],
  );

  const next = useCallback(
    () => (isLast ? finish() : goTo(steps[index + 1].id)),
    [finish, goTo, index, isLast, steps],
  );
  const prev = useCallback(() => index > 0 && goTo(steps[index - 1].id), [goTo, index, steps]);

  // Focus management: move focus into the dialog on open, keep Tab inside it,
  // and hand focus back to whatever had it when we close.
  useEffect(() => {
    if (dismissed) return;
    restoreFocusTo.current = document.activeElement;
    dialogRef.current?.focus();
    const el = restoreFocusTo.current;
    return () => {
      if (el instanceof HTMLElement) el.focus();
    };
  }, [dismissed]);

  useEffect(() => {
    if (dismissed) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        close();
        return;
      }
      if (e.key !== "Tab" || !dialogRef.current) return;
      const items = [...dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(
        (n) => n.offsetParent !== null,
      );
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [close, dismissed]);

  if (dismissed || !step) return null;

  const chapterSteps = steps.filter((s) => s.chapter === step.chapter);
  const chapterIndex = chapterSteps.indexOf(step) + 1;

  return (
    <div className={styles.overlay}>
      <div
        className={styles.wizard}
        role="dialog"
        aria-modal="true"
        aria-labelledby="onb-title"
        tabIndex={-1}
        ref={dialogRef}
      >
        <div className={styles.top}>
          <span className={styles.chapterTag}>
            {CHAPTERS[step.chapter].title}
            <span className={styles.chapterCount}>
              {chapterIndex} of {chapterSteps.length}
            </span>
          </span>
          <button type="button" className={styles.close} onClick={close}>
            Close &mdash; resumes here
          </button>
        </div>

        <div className={styles.main}>
          <nav className={styles.rail} aria-label="Onboarding steps">
            {(["intro", "setup", "learn", "yours"] as const).map((ch) => {
              const all = STEPS.filter((s) => s.chapter === ch);
              const shown = all.filter((s) => steps.includes(s));
              if (!shown.length && ch !== "setup") return null;
              return (
                <div key={ch}>
                  <p className={styles.railChapter}>
                    {CHAPTERS[ch].title}
                    <span>{shown.length || "skipped"}</span>
                  </p>
                  {all.map((s) => {
                    const why = skipReason(s, !!isAdmin, status);
                    if (why) {
                      return (
                        <p key={s.id} className={`${styles.railStep} ${styles.railSkipped}`}>
                          {s.label}
                          <span className={styles.railWhy}>{why}</span>
                        </p>
                      );
                    }
                    return (
                      <button
                        key={s.id}
                        type="button"
                        className={styles.railStep}
                        aria-current={s.id === step.id ? "step" : undefined}
                        onClick={() => goTo(s.id)}
                      >
                        {s.label}
                      </button>
                    );
                  })}
                </div>
              );
            })}
          </nav>

          <div className={styles.body}>
            <StepBody
              step={step.id}
              status={status}
              refetchStatus={refetchStatus}
              isAdmin={!!isAdmin}
              username={user?.username}
              Logo={IntelFeedLogo}
              themes={themes}
            />
          </div>
        </div>

        <div className={styles.foot}>
          <div className={styles.progress} aria-hidden="true">
            {steps.map((s, i) => (
              <span
                key={s.id}
                className={`${styles.seg} ${i < index ? styles.segDone : ""} ${i === index ? styles.segHere : ""}`}
              />
            ))}
          </div>
          <p className={styles.progressLabel}>
            Step {index + 1} of {steps.length}
          </p>
          <div className={styles.actions}>
            <button type="button" className={styles.btn} onClick={prev} disabled={index === 0}>
              Back
            </button>
            <button type="button" className={`${styles.btn} ${styles.btnPrimary}`} onClick={next}>
              {isLast ? "Finish" : "Next"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/** Themes are only needed by one step; fetch once here and hand them down. */
function useThemesSafely() {
  const { data } = useThemes();
  const setThemePref = useSetThemePreference();
  // The preference is a column on the user, not a key in the settings blob —
  // nothing ever writes `settings.theme_id`, so reading it meant no theme
  // showed as selected, not even the one just clicked.
  const current = useAuthStore((s) => s.user?.theme_id ?? undefined);
  return { list: data ?? [], current, apply: (id: string) => setThemePref.mutate({ theme_id: id }) };
}
