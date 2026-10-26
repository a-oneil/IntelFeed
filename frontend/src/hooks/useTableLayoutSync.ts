import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { User } from "@/api/types";
import { useCurrentUser } from "@/hooks/useAuth";
import { isVisitorNow, useAuthStore } from "@/stores/authStore";
import { useUIStore } from "@/stores/uiStore";
import {
  TABLE_LAYOUTS_SETTINGS_KEY,
  layoutMapsEqual,
  parseTableLayouts,
  toTableLayoutMap,
} from "@/types/tableLayout";
import type { TableLayoutMap } from "@/types/tableLayout";

/** tablesOwnerId for layouts changed while browsing without an account. */
const VISITOR_OWNER = "visitor";

const AUTOSAVE_DEBOUNCE_MS = 800;
const AUTOSAVE_MAX_BACKOFF_MS = 30_000;

/**
 * Keeps DataTable column layouts (visibility, widths, order) on the user's
 * profile rather than in one browser's localStorage, so the columns you pick on
 * the desktop are the columns you get on the phone.
 *
 * Mount once, app-wide. Pulls the server-side layouts on load and merges them
 * into the UI store (newest edit per table wins), then debounce-saves local
 * arrangements back with a shallow settings patch.
 */
export function useTableLayoutSync() {
  const setUser = useAuthStore((s) => s.setUser);
  const applyRemoteTableLayouts = useUIStore((s) => s.applyRemoteTableLayouts);
  const takeOverTableLayouts = useUIStore((s) => s.takeOverTableLayouts);
  const tablesOwnerId = useUIStore((s) => s.tablesOwnerId);
  const tables = useUIStore((s) => s.tables);
  const queryClient = useQueryClient();

  // Refetches /auth/me on mount, which is what makes another device's changes
  // show up here — the persisted authStore user is a login-time snapshot.
  const { data: user } = useCurrentUser();

  const remote = useMemo<TableLayoutMap>(
    () => parseTableLayouts(user?.settings as Record<string, unknown> | undefined),
    [user?.settings]
  );

  // Nothing is pushed until we've seen the server's copy — otherwise a fresh
  // device would upload its empty defaults over a good saved layout. This is
  // state, not a ref, so a column toggled while /auth/me was still in flight
  // still gets saved once hydration lands.
  const [hydrated, setHydrated] = useState(false);
  const persistedRef = useRef<TableLayoutMap | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const failureCountRef = useRef(0);

  useEffect(() => {
    if (!user) {
      // A visitor's column changes are theirs: tag them, so whoever signs in
      // next takes the account's layouts over them instead of merging the
      // visitor's in and uploading them.
      if (isVisitorNow() && !tablesOwnerId) useUIStore.setState({ tablesOwnerId: VISITOR_OWNER });
      return;
    }
    if (tablesOwnerId && tablesOwnerId !== user.id) {
      // Someone else was signed in on this browser: take their layouts off the
      // screen rather than merging them — and, worse, uploading them onto this
      // account's profile. A null owner is a browser that predates the sync, so
      // its layouts are this user's own and get merged normally.
      takeOverTableLayouts(user.id, remote);
    } else {
      applyRemoteTableLayouts(remote);
      if (!tablesOwnerId) useUIStore.setState({ tablesOwnerId: user.id });
    }
    persistedRef.current = remote;
    setHydrated(true);
  }, [user, remote, applyRemoteTableLayouts, takeOverTableLayouts, tablesOwnerId]);

  const saveLayouts = useMutation({
    mutationFn: async (layouts: TableLayoutMap) => {
      const res = await api.patch<User>("/auth/me/settings", {
        settings: { [TABLE_LAYOUTS_SETTINGS_KEY]: layouts },
      });
      return res.data;
    },
    onSuccess: (data) => {
      setUser(data);
      // Keep the cached /auth/me in step, so the hydrate effect above doesn't
      // re-apply a stale settings blob on the next render.
      queryClient.setQueryData(["currentUser"], data);
    },
  });

  useEffect(() => {
    if (!hydrated) return;
    const local = toTableLayoutMap(tables);
    if (persistedRef.current && layoutMapsEqual(local, persistedRef.current)) return;
    if (timerRef.current) clearTimeout(timerRef.current);
    // Back off on repeated failures rather than retrying every keystroke-worth
    // of column dragging against an API that isn't answering.
    const delay = Math.min(
      AUTOSAVE_DEBOUNCE_MS * 2 ** failureCountRef.current,
      AUTOSAVE_MAX_BACKOFF_MS
    );
    timerRef.current = setTimeout(() => {
      saveLayouts.mutate(local, {
        onSuccess: () => {
          persistedRef.current = local;
          failureCountRef.current = 0;
        },
        onError: (err) => {
          // persistedRef stays on the last confirmed save so the next edit
          // retries this diff instead of treating the failure as committed.
          failureCountRef.current += 1;
          console.warn("[useTableLayoutSync] failed to save column layout", err);
        },
      });
    }, delay);
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
    // saveLayouts is stable (useMutation result); table state and hydration are
    // the only things that should arm the save timer.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tables, hydrated]);
}
