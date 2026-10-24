import { useEffect, useRef, useCallback } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { useAuthStore } from "@/stores/authStore";
import api from "@/api/client";

const MAX_RETRIES = 10;
const BASE_DELAY_MS = 1000;
const MAX_DELAY_MS = 30000;
const INVALIDATION_DEBOUNCE_MS = 2000;

export function useSSE() {
  const queryClient = useQueryClient();
  const token = useAuthStore((s) => s.accessToken);
  const eventSourceRef = useRef<EventSource | null>(null);
  const retriesRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  // Debounce SSE-triggered invalidations to prevent request storms
  // when many feeds are fetched in quick succession
  const pendingInvalidationsRef = useRef(new Set<string>());
  const invalidationTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  const debouncedInvalidate = useCallback(
    (...queryKeys: string[]) => {
      for (const key of queryKeys) {
        pendingInvalidationsRef.current.add(key);
      }
      clearTimeout(invalidationTimerRef.current);
      invalidationTimerRef.current = setTimeout(() => {
        const keys = [...pendingInvalidationsRef.current];
        pendingInvalidationsRef.current.clear();
        for (const key of keys) {
          queryClient.invalidateQueries({ queryKey: [key] });
        }
      }, INVALIDATION_DEBOUNCE_MS);
    },
    [queryClient]
  );

  // Set by the effect's cleanup. `connect` awaits a ticket before it can build
  // the EventSource, so an unmount during that await would otherwise land a
  // brand-new connection *after* cleanup had already run — with the ref still
  // null, there was nothing for cleanup to close, and the orphan stayed open
  // forever. Six of those exhaust the browser's per-origin HTTP/1.1 connection
  // pool and every subsequent request in the app hangs until its timeout.
  const cancelledRef = useRef(false);

  const connect = useCallback(async () => {
    if (!token || cancelledRef.current) return;

    // Fetch a short-lived, single-use ticket instead of exposing the JWT in the URL
    let ticket: string;
    try {
      const res = await api.post<{ ticket: string }>("/events/ticket");
      ticket = res.data.ticket;
    } catch {
      // If ticket fetch fails, retry with backoff
      if (!cancelledRef.current && retriesRef.current < MAX_RETRIES) {
        const delay = Math.min(
          BASE_DELAY_MS * Math.pow(2, retriesRef.current),
          MAX_DELAY_MS,
        );
        retriesRef.current++;
        timerRef.current = setTimeout(connect, delay);
      }
      return;
    }

    // Unmounted while the ticket was in flight: never open the connection.
    if (cancelledRef.current) return;

    const url = `/api/events?ticket=${encodeURIComponent(ticket)}`;
    const es = new EventSource(url);
    eventSourceRef.current = es;

    // feed_fetched now carries entry data too (coalesced on backend)
    // entry_new kept for backwards compat but both debounce to the same invalidation
    const onFeedFetched = () => {
      debouncedInvalidate("entries", "feeds");
    };

    const onEntryNew = () => {
      debouncedInvalidate("entries", "feeds");
    };

    const onAiTaskComplete = (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        queryClient.invalidateQueries({
          queryKey: ["entries", data.entry_id],
        });
        debouncedInvalidate("intelligence");
      } catch {
        // Malformed SSE data — ignore
      }
    };

    const onAutomationResult = () => {
      debouncedInvalidate("automation-logs", "entries");
    };

    const onReportSectionGenerated = (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        queryClient.invalidateQueries({
          queryKey: ["intel-report", data.report_id],
        });
      } catch {
        // Malformed SSE data — ignore
      }
    };

    const onReportGenerationComplete = (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        queryClient.invalidateQueries({
          queryKey: ["intel-report", data.report_id],
        });
        queryClient.invalidateQueries({ queryKey: ["intel-reports"] });
        toast.success("Report generation complete");
        window.dispatchEvent(
          new CustomEvent("report-generation-done", { detail: { reportId: data.report_id } })
        );
      } catch {
        // Malformed SSE data — ignore
      }
    };

    const onReportGenerationError = (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        toast.error(`Report generation failed: ${data.error || "Unknown error"}`);
        window.dispatchEvent(
          new CustomEvent("report-generation-done", { detail: { reportId: data.report_id, error: data.error } })
        );
      } catch {
        // Malformed SSE data — ignore
      }
    };

    const onEntryScored = () => {
      debouncedInvalidate("entries");
    };

    const onRansomwareDisclosure = (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        debouncedInvalidate("ransomware");
        const who = data.victim_name ?? "An organization";
        const grp = data.group_name ? ` by ${data.group_name}` : "";
        toast.warning(`Leak-site hit: ${who} posted${grp}`, {
          description: data.reason ? `Matched your ${data.reason}` : undefined,
        });
      } catch {
        // Malformed SSE data — ignore
      }
    };

    es.addEventListener("entry_scored", onEntryScored);
    es.addEventListener("ransomware_disclosure", onRansomwareDisclosure);
    es.addEventListener("feed_fetched", onFeedFetched);
    es.addEventListener("entry_new", onEntryNew);
    es.addEventListener("ai_task_complete", onAiTaskComplete);
    es.addEventListener("automation_result", onAutomationResult);
    es.addEventListener("report_section_generated", onReportSectionGenerated);
    es.addEventListener("report_generation_complete", onReportGenerationComplete);
    es.addEventListener("report_generation_error", onReportGenerationError);

    es.onopen = () => {
      retriesRef.current = 0;
    };

    es.onerror = () => {
      es.removeEventListener("feed_fetched", onFeedFetched);
      es.removeEventListener("entry_new", onEntryNew);
      es.removeEventListener("ransomware_disclosure", onRansomwareDisclosure);
      es.removeEventListener("ai_task_complete", onAiTaskComplete);
      es.removeEventListener("automation_result", onAutomationResult);
      es.removeEventListener("report_section_generated", onReportSectionGenerated);
      es.removeEventListener("report_generation_complete", onReportGenerationComplete);
      es.removeEventListener("report_generation_error", onReportGenerationError);
      es.close();
      eventSourceRef.current = null;
      if (!cancelledRef.current && retriesRef.current < MAX_RETRIES) {
        const delay = Math.min(
          BASE_DELAY_MS * Math.pow(2, retriesRef.current),
          MAX_DELAY_MS,
        );
        retriesRef.current++;
        timerRef.current = setTimeout(connect, delay);
      }
    };
  }, [token, queryClient, debouncedInvalidate]);

  useEffect(() => {
    cancelledRef.current = false;
    connect();
    return () => {
      cancelledRef.current = true;
      clearTimeout(timerRef.current);
      clearTimeout(invalidationTimerRef.current);
      const es = eventSourceRef.current;
      if (es) {
        es.close();
        eventSourceRef.current = null;
      }
    };
  }, [connect]);
}
