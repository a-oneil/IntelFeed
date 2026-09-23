import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";

export interface DocumentationPageSummary {
  slug: string;
  title: string;
  section: string;
  summary: string | null;
}

export interface DocumentationIndex {
  pages: DocumentationPageSummary[];
  sections: string[];
}

export interface DocumentationPage {
  slug: string;
  title: string;
  section: string;
  markdown: string;
}

// Docs are files on disk, picked up without a restart — refetch often enough
// that a page dropped into docs/ shows up in a session that is already open.
const DOC_STALE_TIME = 5 * 60 * 1000;

export function useDocumentationIndex() {
  return useQuery({
    queryKey: ["documentation", "index"],
    queryFn: async () => {
      const res = await api.get<DocumentationIndex>("/documentation");
      return res.data;
    },
    staleTime: DOC_STALE_TIME,
  });
}

export function useDocumentationPage(slug: string | undefined) {
  return useQuery({
    queryKey: ["documentation", "page", slug],
    queryFn: async () => {
      const res = await api.get<DocumentationPage>(`/documentation/${slug}`);
      return res.data;
    },
    enabled: Boolean(slug),
    staleTime: DOC_STALE_TIME,
  });
}
