import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import type { TokenResponse, User } from "@/api/types";

/**
 * Drop every cached query except the instance's registration status. Signing
 * in from the public view would otherwise show the visitor's responses — the
 * stand-in dashboards, counts with hidden areas zeroed — until each refetched.
 */
function dropCachedQueries(queryClient: ReturnType<typeof useQueryClient>) {
  queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== "registrationStatus" });
}

export function useLogin() {
  const setTokens = useAuthStore((s) => s.setTokens);
  const setUser = useAuthStore((s) => s.setUser);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (data: { username: string; password: string }) => {
      const res = await api.post<TokenResponse>("/auth/login", data);
      return res.data;
    },
    onSuccess: async (data) => {
      dropCachedQueries(queryClient);
      setTokens(data.access_token, data.refresh_token);
      const res = await api.get<User>("/auth/me", {
        headers: { Authorization: `Bearer ${data.access_token}` },
      });
      setUser(res.data);
    },
  });
}

export function useRegister() {
  const setTokens = useAuthStore((s) => s.setTokens);
  const setUser = useAuthStore((s) => s.setUser);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (data: { username: string; password: string; invite_code?: string }) => {
      const res = await api.post<TokenResponse>("/auth/register", data);
      return res.data;
    },
    onSuccess: async (data) => {
      dropCachedQueries(queryClient);
      setTokens(data.access_token, data.refresh_token);
      const res = await api.get<User>("/auth/me", {
        headers: { Authorization: `Bearer ${data.access_token}` },
      });
      setUser(res.data);
    },
  });
}

export function useUpdateProfile() {
  const setUser = useAuthStore((s) => s.setUser);

  return useMutation({
    mutationFn: async (data: { settings?: Record<string, unknown> }) => {
      const res = await api.put<User>("/auth/me", data);
      return res.data;
    },
    onSuccess: (data) => {
      setUser(data);
    },
  });
}

export function useChangePassword() {
  return useMutation({
    mutationFn: async (data: { current_password: string; new_password: string }) => {
      const res = await api.put("/auth/me/password", data);
      return res.data;
    },
  });
}

export interface RegistrationStatus {
  registration_enabled: boolean;
  invite_code_required: boolean;
  public_read_only_enabled: boolean;
}

export function useRegistrationStatus() {
  return useQuery({
    queryKey: ["registrationStatus"],
    queryFn: async () => {
      try {
        const res = await api.get<RegistrationStatus>("/auth/registration-status");
        // Whether a visitor may browse is decided here, before any login.
        useAuthStore.getState().setPublicReadOnly(!!res.data.public_read_only_enabled);
        return res.data;
      } catch (err) {
        // Unanswered on the first try, treat the instance as private: a
        // signed-out user gets the login page rather than a spinner that waits
        // on this forever. A later failure (a background refetch, a blip on
        // reconnect) keeps the answer already known, so a browsing visitor
        // isn't sent to the login page by one dropped request.
        if (!useAuthStore.getState().publicReadOnlyKnown) useAuthStore.getState().setPublicReadOnly(false);
        throw err;
      }
    },
    staleTime: 60_000,
  });
}

export function useCurrentUser() {
  const isAuth = useAuthStore((s) => s.isAuthenticated());
  const setUser = useAuthStore((s) => s.setUser);

  return useQuery({
    queryKey: ["currentUser"],
    queryFn: async () => {
      const res = await api.get<User>("/auth/me");
      setUser(res.data);
      return res.data;
    },
    enabled: isAuth,
  });
}
