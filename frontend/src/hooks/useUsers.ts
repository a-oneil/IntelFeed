import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { User } from "@/api/types";

export function useUsers() {
  return useQuery({
    queryKey: ["admin", "users"],
    queryFn: async () => {
      const res = await api.get<User[]>("/admin/users");
      return res.data;
    },
  });
}

export function useUpdateUser() {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: async ({
      userId,
      data,
    }: {
      userId: string;
      data: {
        username?: string;
        role?: string;
        is_active?: boolean;
        password?: string;
      };
    }) => {
      const res = await api.patch<User>(`/admin/users/${userId}`, data);
      return res.data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin", "users"] });
    },
  });
}

export function useDeleteUser() {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: async (userId: string) => {
      await api.delete(`/admin/users/${userId}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin", "users"] });
    },
  });
}
