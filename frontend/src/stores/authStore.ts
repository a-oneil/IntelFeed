import axios from "axios";
import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { User } from "@/api/types";
import { queryClient } from "@/queryClient";
import { clearUserScopedState } from "@/stores/clearUserScopedState";

interface AuthState {
  accessToken: string | null;
  refreshToken: string | null;
  user: User | null;
  /** Public read-only mode is on (from /auth/registration-status). Not persisted. */
  publicReadOnly: boolean;
  /** registration-status has answered at least once this page load. */
  publicReadOnlyKnown: boolean;
  setPublicReadOnly: (on: boolean) => void;
  setTokens: (access: string, refresh: string) => void;
  setUser: (user: User) => void;
  logout: () => void;
  isAuthenticated: () => boolean;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      accessToken: null,
      refreshToken: null,
      user: null,
      publicReadOnly: false,
      publicReadOnlyKnown: false,
      setPublicReadOnly: (on) => set({ publicReadOnly: on, publicReadOnlyKnown: true }),
      setTokens: (access, refresh) => set({ accessToken: access, refreshToken: refresh }),
      setUser: (user) => set({ user }),
      logout: () => {
        const { accessToken, refreshToken } = get();
        // Fire-and-forget server-side revocation
        if (accessToken) {
          axios
            .post(
              "/api/auth/logout",
              { refresh_token: refreshToken },
              { headers: { Authorization: `Bearer ${accessToken}` } }
            )
            .catch(() => {});
        }
        set({ accessToken: null, refreshToken: null, user: null });
        queryClient.clear();
        // Don't leave this account's workspace state behind for the next login
        clearUserScopedState();
      },
      isAuthenticated: () => !!(get().accessToken || get().refreshToken),
    }),
    {
      name: "intelfeed-auth",
      partialize: (state) => ({
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        user: state.user,
      }),
    }
  )
);

type AuthSnapshot = Pick<AuthState, "accessToken" | "refreshToken" | "user" | "publicReadOnly">;

/** A visitor: nobody signed in, and the instance lets visitors browse read-only. */
export const selectIsVisitor = (s: AuthSnapshot) => !s.accessToken && !s.refreshToken && s.publicReadOnly;
export const selectIsAdmin = (s: AuthSnapshot) => s.user?.role === "admin";
/** Signed in: may see and use controls that change something. */
export const selectCanWrite = (s: AuthSnapshot) => !!(s.accessToken || s.refreshToken);

export const useIsVisitor = () => useAuthStore(selectIsVisitor);
export const useIsAdmin = () => useAuthStore(selectIsAdmin);
export const useCanWrite = () => useAuthStore(selectCanWrite);

/** Where logging out lands: the public view when visitors may browse, else the login page. */
export const logoutDestination = () => (useAuthStore.getState().publicReadOnly ? "/" : "/login");

/** Outside React: is this browser a visitor right now? (Personal-state writes no-op for one.) */
export const isVisitorNow = () => selectIsVisitor(useAuthStore.getState());
