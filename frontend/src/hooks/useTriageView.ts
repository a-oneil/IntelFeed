import { useCallback, useEffect, useMemo, useRef } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import api from "@/api/client";
import type { User } from "@/api/types";
import type { TimeRange } from "@/components/TimeRangeSelector";
import { isVisitorNow, useAuthStore } from "@/stores/authStore";
import { useTriageViewStore } from "@/stores/triageViewStore";
import {
  buildDefaultView,
  getSavedTriageView,
  viewsEqual,
} from "@/types/triageView";
import type {
  TriageView,
  TriageWidgetName,
  TriageWidgetsConfig,
} from "@/types/triageView";

interface ConvergenceDefaults {
  windowHours: number;
  minShared: number;
}

interface UseTriageViewResult {
  view: TriageView;
  setGlobalRange: (range: TimeRange, customStart?: string, customEnd?: string) => void;
  setWidget: <K extends TriageWidgetName>(name: K, patch: Partial<TriageWidgetsConfig[K]>) => void;
}

const AUTOSAVE_DEBOUNCE_MS = 600;
const AUTOSAVE_MAX_BACKOFF_MS = 30_000;

export function useTriageView(convergenceDefaults: ConvergenceDefaults = { windowHours: 24, minShared: 2 }): UseTriageViewResult {
  const user = useAuthStore((s) => s.user);
  const setUser = useAuthStore((s) => s.setUser);
  const queryClient = useQueryClient();
  const userSettings = user?.settings;

  const storeView = useTriageViewStore((s) => s.view);
  const viewOwnerId = useTriageViewStore((s) => s.viewOwnerId);
  const setStoreView = useTriageViewStore((s) => s.setView);
  const patchStoreView = useTriageViewStore((s) => s.patchView);
  const takeOverView = useTriageViewStore((s) => s.takeOverView);

  const savedView = useMemo<TriageView>(
    () =>
      getSavedTriageView(userSettings, {
        convergenceWindowHours: convergenceDefaults.windowHours,
        convergenceMinShared: convergenceDefaults.minShared,
      }),
    [userSettings, convergenceDefaults.windowHours, convergenceDefaults.minShared],
  );

  // First mount (or after settings refetch when nothing is in the store yet): hydrate the store from the server-side saved view. When the persisted store belongs to a different account (shared browser), replace it with this account's server copy instead of merging, so the leftover view is never auto-saved onto this user's profile.
  useEffect(() => {
    if (!user) return;
    if (viewOwnerId && viewOwnerId !== user.id) {
      takeOverView(user.id, savedView);
      return;
    }
    if (!storeView) {
      setStoreView(savedView);
    }
    if (!viewOwnerId) {
      useTriageViewStore.setState({ viewOwnerId: user.id });
    }
  }, [user, viewOwnerId, storeView, savedView, setStoreView, takeOverView]);

  // Until the takeover has run, another account's store view must not be displayed (or diffed for auto-save); fall back to this user's server copy.
  const foreignStore = Boolean(user && viewOwnerId && viewOwnerId !== user.id);
  const view = (!foreignStore ? storeView : null) ?? savedView;

  // Shallow settings patch, not a whole-blob PUT: other auto-savers (table column layouts) write the same settings object, and a merge from this hook's captured snapshot would silently drop their writes.
  const saveSettings = useMutation({
    mutationFn: async (payload: Record<string, unknown>) => {
      const res = await api.patch<User>("/auth/me/settings", { settings: payload });
      return res.data;
    },
    onSuccess: (data) => {
      setUser(data);
      queryClient.invalidateQueries({ queryKey: ["triage"] });
    },
  });

  // Debounced auto-save: each edit restarts the timer, and the view is compared against the last persisted view to avoid no-op writes.
  const persistedRef = useRef<TriageView | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Counts consecutive save failures so the debounce delay can back off, instead of retrying the API rapidly in an endless loop while persistedRef stays out of sync with the store.
  const failureCountRef = useRef(0);

  useEffect(() => {
    persistedRef.current = savedView;
  }, [savedView]);

  useEffect(() => {
    if (!storeView) return;
    // A visitor's view changes stay in the store only: there is no account to save them to, and the refused write would toast and retry forever.
    if (isVisitorNow()) return;
    // Never auto-save a view that belongs to a different account (a render before the takeover on a shared browser); that would write their config onto this user's profile.
    if (foreignStore) return;
    if (persistedRef.current && viewsEqual(storeView, persistedRef.current)) return;
    if (timerRef.current) clearTimeout(timerRef.current);
    const backoff = Math.min(
      AUTOSAVE_DEBOUNCE_MS * 2 ** failureCountRef.current,
      AUTOSAVE_MAX_BACKOFF_MS,
    );
    timerRef.current = setTimeout(() => {
      saveSettings.mutate({ triage_view: storeView }, {
        onSuccess: () => {
          persistedRef.current = storeView;
          failureCountRef.current = 0;
        },
        onError: (err) => {
          // Do NOT update persistedRef: leaving it on the last successfully saved view means the next debounce run retries the same diff instead of treating the failed write as saved.
          failureCountRef.current += 1;
          console.warn("[useTriageView] auto-save failed", err);
          if (failureCountRef.current === 1) {
            toast.error("Could not save the dashboard layout. It will retry.");
          }
        },
      });
    }, backoff);
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
    // saveSettings is stable across renders (returned from useMutation); the store view and its ownership are the only things that should restart the save timer.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [storeView, foreignStore]);

  const setGlobalRange = useCallback<UseTriageViewResult["setGlobalRange"]>(
    (range, customStart, customEnd) => {
      patchStoreView((current) => ({
        ...current,
        global_range: range,
        global_custom_start: range === "custom" ? customStart ?? null : null,
        global_custom_end: range === "custom" ? customEnd ?? null : null,
      }));
    },
    [patchStoreView],
  );

  const setWidget = useCallback<UseTriageViewResult["setWidget"]>(
    (name, patch) => {
      patchStoreView((current) => ({
        ...current,
        widgets: {
          ...current.widgets,
          [name]: { ...current.widgets[name], ...patch },
        },
      }));
    },
    [patchStoreView],
  );

  // First render before hydration: show the server-side saved view (or the built-in default) rather than nothing.
  if (!storeView) {
    return {
      view: savedView ?? buildDefaultView(),
      setGlobalRange,
      setWidget,
    };
  }

  return { view, setGlobalRange, setWidget };
}
