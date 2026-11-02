import { useState, useCallback } from "react";
import { toast } from "sonner";
import {
  useJobSchedules,
  useUpdateJobSchedule,
  useResetJobSchedule,
  useRunJobNow,
} from "@/hooks/useJobSchedules";
import type { JobSchedule, JobScheduleDef } from "@/hooks/useJobSchedules";
import SystemSettings from "./SystemSettings";
import { Chip } from "./primitives";
import styles from "./JobSchedules.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";

export default function JobSchedules({
  onOpenEnrichment,
}: {
  /** Enrichment jobs belong to their source: their rows here are read-only
   *  and open the Enrichment console with that source expanded. */
  onOpenEnrichment: (source: string) => void;
}) {
  const { data, isLoading } = useJobSchedules();
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    new Set()
  );
  const [editingJob, setEditingJob] = useState<string | null>(null);
  const [hasChanges, setHasChanges] = useState(false);

  const toggleCategory = useCallback((cat: string) => {
    setExpandedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  }, []);

  if (isLoading || !data) {
    return <AsyncStateLoading label="Loading job schedules…" compact />;
  }

  const { jobs, categories, category_order } = data;

  const grouped: Record<string, JobSchedule[]> = {};
  for (const job of jobs) {
    (grouped[job.category] = grouped[job.category] || []).push(job);
  }

  // Default: all collapsed
  const isExpanded = (cat: string) => expandedCategories.has(cat);

  return (
    <div className={styles.container}>
      {hasChanges && (
        <div className={styles.restartBanner}>
          <svg
            className={styles.restartIcon}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          Schedule changes take effect after restarting workers:{" "}
          <code>docker compose restart celery-beat</code>
        </div>
      )}

      {category_order.map((cat) => {
        const catJobs = grouped[cat];
        if (!catJobs?.length) return null;
        const expanded = isExpanded(cat);
        const disabledCount = catJobs.filter((j) => !j.enabled).length;

        return (
          <div key={cat} className={styles.group}>
            <div
              className={styles.groupHeader}
              onClick={() => toggleCategory(cat)}
            >
              <h3 className={styles.groupTitle}>
                {categories[cat] || cat}
                <span className={styles.groupCount}>
                  {catJobs.length} job{catJobs.length !== 1 ? "s" : ""}
                  {disabledCount > 0 && `, ${disabledCount} disabled`}
                </span>
              </h3>
              <svg
                className={`${styles.chevron} ${expanded ? styles.chevronOpen : ""}`}
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <polyline points="9 18 15 12 9 6" />
              </svg>
            </div>
            {expanded && (
              <div className={styles.groupBody}>
                {catJobs.map((job) =>
                  job.source ? (
                    <SourceJobRow
                      key={job.name}
                      job={job}
                      source={job.source}
                      onOpen={onOpenEnrichment}
                    />
                  ) : (
                  <JobRow
                    key={job.name}
                    job={job}
                    isEditing={editingJob === job.name}
                    onEdit={() =>
                      setEditingJob(
                        editingJob === job.name ? null : job.name
                      )
                    }
                    onCancelEdit={() => setEditingJob(null)}
                    onChanged={() => setHasChanges(true)}
                  />
                  )
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/** A job owned by an enrichment source: shown for the full picture, edited
 *  from the source's row in Engine → Enrichment. */
function SourceJobRow({
  job,
  source,
  onOpen,
}: {
  job: JobSchedule;
  source: string;
  onOpen: (source: string) => void;
}) {
  const runs = job.runs_30d ?? 0;
  const ok = job.ok_30d ?? 0;
  const failed = job.last_status === "error";
  return (
    <div className={`${styles.jobRow} ${!job.enabled ? styles.jobDisabled : ""}`}>
      <div className={styles.jobInfo}>
        <p className={styles.jobName}>
          <span>{formatJobName(job.name)}</span>
          <Chip
            tone="toned"
            tint="var(--accent)"
            className={styles.ownerTag}
            title="Owned by this enrichment source; edit it there"
          >
            source · {job.source_label ?? source}
          </Chip>
        </p>
        <p className={styles.jobDesc}>{job.description}</p>
        <div className={styles.jobSchedule}>
          <span>{job.human_schedule}</span>
          <span
            className={failed ? styles.runsBad : styles.runs}
            title="Successful runs of all runs in the last 30 days"
          >
            {runs === 0 ? "no runs in 30 days" : `${ok}/${runs} ok in 30 days`}
          </span>
        </div>
        {failed && job.last_error && (
          <p className={styles.lastError} title={job.last_error}>
            Last run: {job.last_error}
          </p>
        )}
      </div>
      <div className={styles.jobControls}>
        <button type="button" className={styles.settingsToggle} onClick={() => onOpen(source)}>
          Open in Enrichment
        </button>
      </div>
    </div>
  );
}

function JobRow({
  job,
  isEditing,
  onEdit,
  onCancelEdit,
  onChanged,
}: {
  job: JobSchedule;
  isEditing: boolean;
  onEdit: () => void;
  onCancelEdit: () => void;
  onChanged: () => void;
}) {
  const updateJob = useUpdateJobSchedule();
  const resetJob = useResetJobSchedule();
  const runJob = useRunJobNow();
  const [runMsg, setRunMsg] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const settingsKeys = job.settings_keys ?? [];

  const handleToggle = (enabled: boolean) =>
    updateJob.mutate(
      { name: job.name, enabled },
      {
        onSuccess: onChanged,
        onError: (e) => toast.error(`Couldn't ${enabled ? "enable" : "disable"} ${job.name}: ${(e as Error).message}`),
      },
    );

  const handleRun = async () => {
    setRunMsg(null);
    try {
      const res = await runJob.mutateAsync(job.name);
      setRunMsg(`Queued (${res.task_id.slice(0, 8)}...)`);
      setTimeout(() => setRunMsg(null), 4000);
    } catch {
      setRunMsg("Failed");
      setTimeout(() => setRunMsg(null), 3000);
    }
  };

  const handleReset = () =>
    resetJob.mutate(job.name, {
      onSuccess: () => {
        onChanged();
        onCancelEdit();
      },
      onError: (e) => toast.error(`Couldn't reset ${job.name}: ${(e as Error).message}`),
    });

  return (
    <div
      className={`${styles.jobRow} ${!job.enabled ? styles.jobDisabled : ""}`}
    >
      <div className={styles.jobInfo}>
        <p className={styles.jobName}>
          {formatJobName(job.name)}
          {job.uses_ai && (
            <Chip
              tone="toned"
              tint="var(--entity-ai, #22c55e)"
              className={styles.aiTag}
              title="This job uses AI"
            >
              AI
            </Chip>
          )}
          {!job.enabled && (
            <Chip tone="toned" tint="var(--danger)" className={styles.nameTag}>
              disabled
            </Chip>
          )}
          {job.is_customized && job.enabled && (
            <Chip tone="toned" tint="var(--accent)" className={styles.nameTag}>
              customized
            </Chip>
          )}
        </p>
        <p className={styles.jobDesc}>{job.description}</p>
        <div className={styles.jobSchedule}>
          <svg
            className={styles.scheduleIcon}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <circle cx="12" cy="12" r="10" />
            <polyline points="12 6 12 12 16 14" />
          </svg>
          {job.human_schedule}
          {job.is_customized && (
            <span style={{ opacity: 0.5 }}>
              (default: {job.human_default_schedule})
            </span>
          )}
          {runMsg && <span className={styles.statusMsg}>{runMsg}</span>}
        </div>

        {settingsKeys.length > 0 && (
          <button
            type="button"
            className={styles.settingsToggle}
            onClick={() => setShowSettings((v) => !v)}
            aria-expanded={showSettings}
          >
            {showSettings ? "Hide" : "Show"} {settingsKeys.length} setting
            {settingsKeys.length !== 1 ? "s" : ""}
          </button>
        )}

        {showSettings && settingsKeys.length > 0 && (
          <div className={styles.settingsPanel}>
            <SystemSettings filterKeys={settingsKeys} flat />
          </div>
        )}

        {isEditing && (
          <ScheduleEditor
            job={job}
            onSave={(schedule) => {
              updateJob.mutate(
                { name: job.name, schedule },
                {
                  onSuccess: () => {
                    onChanged();
                    onCancelEdit();
                  },
                  onError: (e) => toast.error(`Couldn't save the schedule: ${(e as Error).message}`),
                }
              );
            }}
            onCancel={onCancelEdit}
            onReset={job.is_customized ? handleReset : undefined}
            saving={updateJob.isPending}
          />
        )}
      </div>

      <div className={styles.jobControls}>
        <label className={styles.toggle} title={job.enabled ? "Disable" : "Enable"}>
          <input
            type="checkbox"
            checked={job.enabled}
            onChange={(e) => handleToggle(e.target.checked)}
          />
          <span className={styles.toggleSlider} />
        </label>

        <button
          className={styles.iconBtn}
          onClick={onEdit}
          title="Edit schedule"
        >
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
            <path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
          </svg>
        </button>

        <button
          className={styles.iconBtn}
          onClick={handleRun}
          disabled={runJob.isPending}
          title="Run now"
        >
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <polygon points="5 3 19 12 5 21 5 3" />
          </svg>
        </button>
      </div>
    </div>
  );
}

export function ScheduleEditor({
  job,
  onSave,
  onCancel,
  onReset,
  saving,
}: {
  job: JobSchedule;
  onSave: (schedule: JobScheduleDef) => void;
  onCancel: () => void;
  onReset?: () => void;
  saving: boolean;
}) {
  const sched = job.effective_schedule;
  const [schedType, setSchedType] = useState<"interval" | "crontab">(
    sched.type
  );
  const [seconds, setSeconds] = useState(String(sched.seconds || 60));
  const [minute, setMinute] = useState(sched.minute || "*");
  const [hour, setHour] = useState(sched.hour || "*");
  const [dayOfWeek, setDayOfWeek] = useState(sched.day_of_week || "*");

  const handleSave = () => {
    if (schedType === "interval") {
      onSave({ type: "interval", seconds: Number(seconds) });
    } else {
      const def: JobScheduleDef = { type: "crontab", minute, hour };
      if (dayOfWeek !== "*") def.day_of_week = dayOfWeek;
      onSave(def);
    }
  };

  return (
    <div className={styles.editPanel}>
      <div className={styles.editFields}>
        <div className={styles.editField}>
          <span className={styles.editLabel}>Type</span>
          <select
            className={styles.editSelect}
            value={schedType}
            onChange={(e) =>
              setSchedType(e.target.value as "interval" | "crontab")
            }
          >
            <option value="interval">Interval</option>
            <option value="crontab">Crontab</option>
          </select>
        </div>

        {schedType === "interval" ? (
          <div className={styles.editField}>
            <span className={styles.editLabel}>Seconds</span>
            <input
              className={styles.editInput}
              type="number"
              min={5}
              value={seconds}
              onChange={(e) => setSeconds(e.target.value)}
            />
          </div>
        ) : (
          <>
            <div className={styles.editField}>
              <span className={styles.editLabel}>Minute</span>
              <input
                className={styles.editInput}
                value={minute}
                onChange={(e) => setMinute(e.target.value)}
                placeholder="* or */15 or 0"
              />
            </div>
            <div className={styles.editField}>
              <span className={styles.editLabel}>Hour</span>
              <input
                className={styles.editInput}
                value={hour}
                onChange={(e) => setHour(e.target.value)}
                placeholder="* or */6 or 2"
              />
            </div>
            <div className={styles.editField}>
              <span className={styles.editLabel}>Day of week</span>
              <input
                className={styles.editInput}
                value={dayOfWeek}
                onChange={(e) => setDayOfWeek(e.target.value)}
                placeholder="* or 0=Sun"
              />
            </div>
          </>
        )}
      </div>

      <div className={styles.editActions}>
        <button
          className={styles.btnSave}
          onClick={handleSave}
          disabled={saving}
        >
          {saving ? "Saving..." : "Save"}
        </button>
        <button className={styles.btnCancel} onClick={onCancel}>
          Cancel
        </button>
        {onReset && (
          <button className={styles.btnReset} onClick={onReset}>
            Reset to Default
          </button>
        )}
        <span className={styles.editHint}>
          Crontab: minute hour day-of-week (0=Sun)
        </span>
      </div>
    </div>
  );
}

function formatJobName(name: string): string {
  return name
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}
