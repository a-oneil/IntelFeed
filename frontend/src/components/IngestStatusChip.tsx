import { Chip, Spinner } from "@/components/primitives";
import type { IngestItem, IngestItemStatus } from "@/hooks/useIngest";

/**
 * One chip per batch-item outcome. `created` splits into "analyzing" (the
 * entry exists; the pipeline and the one-pass AI analysis are still to come)
 * and "done" (the analysis landed), because that gap is minutes to hours on a
 * local model and a chip that just said "done" would be lying.
 */
export function ingestStatusLabel(status: IngestItemStatus, phase: IngestItem["phase"]): string {
  switch (status) {
    case "created":
      return phase === "done" ? "done" : "analyzing";
    case "no_text":
      return "no text";
    case "too_large":
      return "too large";
    default:
      return status;
  }
}

function tintFor(status: IngestItemStatus, phase: IngestItem["phase"]): string | undefined {
  switch (status) {
    case "parsing":
      return "var(--accent-intel)";
    case "created":
      return phase === "done" ? "var(--success)" : "var(--accent-intel)";
    case "expanded":
      return "var(--success)";
    case "duplicate":
      return "var(--warning)";
    case "no_text":
    case "unsupported":
    case "too_large":
    case "failed":
      return "var(--danger)";
    default:
      return undefined; // queued, cancelled: the plain chip
  }
}

export function ingestStatusTitle(status: IngestItemStatus, phase: IngestItem["phase"]): string {
  switch (status) {
    case "queued":
      return "Stored, waiting for a worker";
    case "parsing":
      return "A worker is extracting the text";
    case "created":
      return phase === "done"
        ? "Entry created and AI analysis complete"
        : "Entry created; autolink and extraction ran, the one-pass AI analysis is queued";
    case "expanded":
      return "Expanded into one item per file";
    case "duplicate":
      return "Already ingested; this points at the existing entry";
    case "no_text":
      return "Parsed, but nothing to read (scanned PDF or empty file)";
    case "unsupported":
      return "No parser for this file type";
    case "too_large":
      return "Over the per-file size cap";
    case "failed":
      return "Fetch or parse failed; retry when the cause is fixed";
    case "cancelled":
      return "Removed before a worker took it";
  }
}

export function IngestStatusChip({ status, phase }: { status: IngestItemStatus; phase: IngestItem["phase"] }) {
  const tint = tintFor(status, phase);
  return (
    <Chip
      tone={tint ? "toned" : "default"}
      tint={tint}
      pill
      title={ingestStatusTitle(status, phase)}
    >
      {status === "parsing" && <Spinner size="sm" />}
      {ingestStatusLabel(status, phase)}
    </Chip>
  );
}
