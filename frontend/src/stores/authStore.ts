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
