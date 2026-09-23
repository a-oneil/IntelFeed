import { useCallback, useMemo } from "react";
import { useAuthStore } from "@/stores/authStore";
import { useUpdateProfile } from "@/hooks/useAuth";
import type { SidebarSectionId } from "@/api/types";

const DEFAULT_SECTION_ORDER: SidebarSectionId[] = [
  "nav",
  "saved_searches",
  "feeds",
];

export function useSidebarCustomization() {
  const user = useAuthStore((s) => s.user);
  const updateProfile = useUpdateProfile();
  const settings = user?.settings || {};

  const sectionOrder: SidebarSectionId[] = useMemo(() => {
    const stored = settings.sidebar_section_order as SidebarSectionId[] | undefined;
    if (!stored || !Array.isArray(stored)) return [...DEFAULT_SECTION_ORDER];
    // Ensure all built-in sections are present
    const result = [...stored];
    for (const builtin of DEFAULT_SECTION_ORDER) {
      if (!result.includes(builtin)) result.push(builtin);
    }
    // Drop anything that isn't a built-in section. Orders persisted before
    // custom link groups were removed still carry their ids; filtering here
    // means those stale entries simply stop resolving instead of leaving gaps.
    const builtinIds = new Set(DEFAULT_SECTION_ORDER);
    return result.filter((id) => builtinIds.has(id));
  }, [settings.sidebar_section_order]);

  const persistSettings = useCallback(
    (patch: Record<string, unknown>) => {
      updateProfile.mutate({ settings: { ...settings, ...patch } });
    },
    [settings, updateProfile],
  );

  const reorderSections = useCallback(
    (newOrder: SidebarSectionId[]) => {
      persistSettings({ sidebar_section_order: newOrder });
    },
    [persistSettings],
  );

  return {
    sectionOrder,
    reorderSections,
    isPending: updateProfile.isPending,
  };
}
