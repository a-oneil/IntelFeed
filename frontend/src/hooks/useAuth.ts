import { useMutation, useQuery } from "@tanstack/react-query";
import api from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import type { TokenResponse, User } from "@/api/types";

export function useLogin() {
  const setTokens = useAuthStore((s) => s.setTokens);
  const setUser = useAuthStore((s) => s.setUser);

  return useMutation({
    mutationFn: async (data: { username: string; password: string }) => {
      const res = await api.post<TokenResponse>("/auth/login", data);
      return res.data;
    },
    onSuccess: async (data) => {
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

  return useMutation({
    mutationFn: async (data: { username: string; password: string; invite_code?: string }) => {
      const res = await api.post<TokenResponse>("/auth/register", data);
      return res.data;
    },
    onSuccess: async (data) => {
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

export function useRegistrationStatus() {
  return useQuery({
    queryKey: ["registrationStatus"],
    queryFn: async () => {
      const res = await api.get<{ registration_enabled: boolean; invite_code_required: boolean }>("/auth/registration-status");
      return res.data;
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
