import { useMemo } from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import axios from "axios";
import { toast } from "sonner";
import { IntelFeedLogo } from "@/components/IntelFeedLogo";
import { RouteFallback } from "@/components/RouteFallback";
import { ToolbarDropdown, DropdownItem } from "@/components/ToolbarDropdown";
import { ReportDocument } from "@/components/report/ReportDocument";
import { Chip } from "@/components/primitives/Chip";
import { TLP_COLORS } from "@/utils/colorSchemes";
import { formatDateTime } from "@/utils/formatDate";
import { useUIStore } from "@/stores/uiStore";
import type { SharedReport } from "@/api/types";
import readerStyles from "@/components/EntryReader.module.css";
import sharedStyles from "./SharedEntryPage.module.css";
import styles from "./SharedReportPage.module.css";

const publicApi = axios.create({ baseURL: "/api", timeout: 15000 });

function useSharedReport(token: string | undefined) {
  return useQuery({
    queryKey: ["shared-report", token],
    queryFn: async () => {
      const { data } = await publicApi.get<SharedReport>(`/shared/report/${token}`);
      return data;
    },
    enabled: !!token,
    retry: false,
  });
}

const EXPORTS = [
  { format: "markdown", label: "Download Markdown", ext: "md" },
  { format: "html", label: "Download HTML", ext: "html" },
  { format: "pdf", label: "Download PDF", ext: "pdf" },
] as const;

async function downloadExport(token: string, title: string, format: string, ext: string) {
  const resp = await publicApi.get(`/shared/report/${token}/export`, {
    params: { format },
    responseType: "blob",
  });
  const blob = resp.data as Blob;
  // Without WeasyPrint the server answers a PDF request with HTML — name the file for what it is.
  const actualExt = format === "pdf" && blob.type.startsWith("text/html") ? "html" : ext;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${title.slice(0, 50).replace(/[/\\]/g, "-")}.${actualExt}`;
  a.click();
  URL.revokeObjectURL(url);
}

const DownloadIcon = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <polyline points="7 10 12 15 17 10" />
    <line x1="12" y1="15" x2="12" y2="3" />
  </svg>
);

/**
 * Public, read-only view of a shared intel report. No auth — the same
 * IntelFeed top bar as a shared article, then the report drawn as a document.
 */
export function SharedReportPage() {
  const { token } = useParams<{ token: string }>();
  const { data: report, isLoading, error } = useSharedReport(token);
  // The reader's column width, so a shared report and a shared article are
  // the same width on the same screen.
  const readerMaxWidth = useUIStore((s) => s.readerMaxWidth);
  const articlePaneStyle = useMemo<React.CSSProperties>(() => ({
    ["--reader-col-width" as string]: readerMaxWidth === 0 ? "none" : `${readerMaxWidth + 64}px`,
    ["--reader-col-inner" as string]: readerMaxWidth === 0 ? "none" : `${readerMaxWidth}px`,
  }), [readerMaxWidth]);

  if (isLoading) return <RouteFallback />;

  if (error || !report || !token) {
    const is404 = axios.isAxiosError(error) && error.response?.status === 404;
    const is410 = axios.isAxiosError(error) && error.response?.status === 410;
    const is403 = axios.isAxiosError(error) && error.response?.status === 403;
    return (
      <div className={sharedStyles.errorContainer}>
        <div className={sharedStyles.errorTitle}>
          {is403 ? "Not Available" : is410 ? "Link Expired" : is404 ? "Not Found" : "Error"}
        </div>
        <div className={sharedStyles.errorMessage}>
          {is403
            ? "This report's TLP marking does not allow public sharing."
            : is410
              ? "This share link has expired."
              : is404
                ? "This share link does not exist or has been revoked."
                : "Could not load this report."}
        </div>
      </div>
    );
  }

  const tlpColor = TLP_COLORS[report.tlp_marking] ?? "var(--text-muted)";
  const dateLabel = report.published_at ? "Published" : "Updated";
  const dateValue = report.published_at ?? report.updated_at;

  return (
    <div className={sharedStyles.page}>
      <div className={readerStyles.readerContainer}>
        <article className={readerStyles.articlePane} style={articlePaneStyle}>
          {/* Top bar — identical to the shared article page */}
          <div className={`${readerStyles.topBar} ${sharedStyles.topBar}`}>
            <a className={sharedStyles.brand} href="/" title="Go to IntelFeed" aria-label="Go to IntelFeed">
              <IntelFeedLogo size={18} className={sharedStyles.brandLogo} />
              <span>
                Intel<span className={sharedStyles.brandAccent}>Feed</span>
              </span>
            </a>
            <Chip className={sharedStyles.sharedBadge}>Shared Report</Chip>
            <div className={readerStyles.topBarActions}>
              <ToolbarDropdown label="Export" icon={DownloadIcon}>
                {EXPORTS.map((x) => (
                  <DropdownItem
                    key={x.format}
                    icon={DownloadIcon}
                    label={x.label}
                    onClick={() =>
                      downloadExport(token, report.title, x.format, x.ext).catch(() =>
                        toast.error("Export failed")
                      )
                    }
                  />
                ))}
              </ToolbarDropdown>
              <div className={readerStyles.topBarDivider} />
              <a className={readerStyles.labelBtn} href="/" title="Open IntelFeed">
                Open IntelFeed
              </a>
            </div>
          </div>

          {/* Report header — same frame as the article header */}
          <header className={readerStyles.header}>
            <div className={`${readerStyles.meta} ${styles.meta}`}>
              <Chip tone="solid" tint={tlpColor} size="sm" title="Traffic Light Protocol marking">
                {report.tlp_marking}
              </Chip>
              <span className={readerStyles.feedName}>{report.template_name}</span>
              <span className={styles.metaDim}>v{report.version}</span>
            </div>
            <h1 className={readerStyles.title}>{report.title}</h1>
            <div className={readerStyles.byline}>
              <span>
                {dateLabel} {formatDateTime(dateValue)}
              </span>
              <span>Shared {formatDateTime(report.shared_at)}</span>
            </div>
          </header>

          <div className={`${readerStyles.content} ${styles.content}`}>
            {report.summary && <p className={styles.summary}>{report.summary}</p>}

            {/* Free text (a Manual report's whole body, or a preamble) and the
                sections go through one renderer, so code blocks, tables and
                long lines are drawn the same way as in the builder. */}
            {report.body || report.sections.length > 0 ? (
              <ReportDocument
                sections={report.sections}
                freeText={report.body}
                linkEntities={false}
                entityMatches={report.entities}
                frameless
              />
            ) : (
              <p className={styles.empty}>This report has no content yet.</p>
            )}

            {report.tags.length > 0 && (
              <div className={styles.tags}>
                {report.tags.map((t) => (
                  <Chip key={t} tone="quiet" size="sm">
                    {t}
                  </Chip>
                ))}
              </div>
            )}

            <footer className={styles.footer}>
              Generated with <a href="/">IntelFeed</a>
            </footer>
          </div>
        </article>
      </div>
    </div>
  );
}
