import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { MermaidDiagram } from "@/components/MermaidDiagram";
import { ResizeHandle } from "@/components/ResizeHandle";
import { MobileNavSheet, RailToggle } from "@/components/primitives";
import { useRailWidth } from "@/hooks/useRailWidth";
import { useAppSidebarAutoCollapse } from "@/hooks/useAppSidebarAutoCollapse";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { useDocumentationIndex, useDocumentationPage } from "@/hooks/useDocumentation";
import { DocsCopilot } from "@/components/DocsCopilot";
import { useUIStore } from "@/stores/uiStore";
import { useAuthStore } from "@/stores/authStore";
import { headingIdsByLine, nodeText, slugify } from "@/utils/headingAnchors";
import type { DocumentationPageSummary } from "@/hooks/useDocumentation";
import styles from "./DocumentationPage.module.css";
import { useIsVisitor } from "@/stores/authStore";

/** The docs landing page — `/documentation` with no slug after it. */
const LANDING = "";

/** Section name the `docs/guide/` directory produces — the user-facing guide. */
const GUIDE_SECTION = "Guide";

function ExternalIcon() {
  return (
    <svg className={styles.externalIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
      <polyline points="15 3 21 3 21 9" />
      <line x1="10" y1="14" x2="21" y2="3" />
    </svg>
  );
}

/** What react-markdown hands a heading renderer: the DOM props plus its source position. */
type HeadingProps = React.ComponentPropsWithoutRef<"h2"> & {
  node?: { position?: { start: { line: number } } };
};

/**
 * Root-relative paths the API serves itself, not the SPA router: handing these
 * to `navigate()` would land on the app's 404 instead of Swagger / ReDoc / an
 * API response.
 */
const SERVER_PATHS = [/^\/docs\b/, /^\/redoc\b/, /^\/api\//, /^\/openapi\.json/, /^\/metrics\b/];

function isAppRoute(href: string): boolean {
  return !SERVER_PATHS.some((re) => re.test(href));
}

/**
 * Resolve a docs link to an in-app route, or null to leave it to the browser.
 *
 * Two kinds qualify. Repo-relative markdown paths (`[x](operations.md)`,
 * `[y](diagrams/engine.md#anchor)`) are rewritten onto documentation routes.
 * Root-relative app paths (`/workbench/threats`, `/documentation/guide/...`)
 * are already routes — they only need routing through the SPA so that following
 * one out of the docs doesn't reload the whole app. External URLs and bare
 * anchors are left alone.
 */
function resolveHref(href: string | undefined, currentSlug: string): string | null {
  if (!href) return null;
  if (/^[a-z]+:/i.test(href) || href.startsWith("//") || href.startsWith("#")) return null;
  if (href.startsWith("/")) return isAppRoute(href) ? href : null;
  const [path, hash] = href.split("#");
  if (!path.endsWith(".md")) return null;

  const dir = currentSlug.includes("/") ? currentSlug.slice(0, currentSlug.lastIndexOf("/")) : "";
  const parts = (dir ? `${dir}/${path}` : path).split("/");
  const stack: string[] = [];
  for (const part of parts) {
    if (part === "." || part === "") continue;
    if (part === "..") stack.pop();
    else stack.push(part);
  }
  const target = stack.join("/").replace(/\.md$/, "");
  // `../readme.md`, `../setup.md` and friends escape docs/ — not ours to serve.
  if (!target || target.startsWith("..")) return null;
  return `/documentation/${target}${hash ? `#${hash}` : ""}`;
}

/**
 * Map a relative image in the markdown to the API route that serves it.
 *
 * The docs render from raw markdown, so `../assets/screenshots/x.png` would
 * otherwise resolve against the SPA route and 404. Normalise it against the
 * current slug the way resolveHref does, keep it inside docs/assets/, and point
 * it at /api/documentation/assets/. That route is auth-gated and an <img> tag
 * cannot set a header, so the access token rides in the query string — the same
 * bargain EntryReader makes for /api/telegram-media.
 */
function resolveAssetSrc(src: string | undefined, currentSlug: string): string | undefined {
  if (!src) return undefined;
  if (/^[a-z]+:/i.test(src) || src.startsWith("//") || src.startsWith("/")) return src;

  const dir = currentSlug.includes("/") ? currentSlug.slice(0, currentSlug.lastIndexOf("/")) : "";
  const stack: string[] = [];
  for (const part of (dir ? `${dir}/${src}` : src).split("/")) {
    if (part === "." || part === "") continue;
    if (part === "..") stack.pop();
    else stack.push(part);
  }
  const target = stack.join("/");
  // Anything that climbs out of docs/assets/ is not ours to serve.
  if (!target.startsWith("assets/")) return undefined;

  const url = `/api/documentation/${target}`;
  const accessToken = useAuthStore.getState().accessToken;
  return accessToken ? `${url}?token=${encodeURIComponent(accessToken)}` : url;
}

function groupBySection(pages: DocumentationPageSummary[]) {
  const groups: { section: string; pages: DocumentationPageSummary[] }[] = [];
  for (const page of pages) {
    const last = groups[groups.length - 1];
    if (last && last.section === page.section) last.pages.push(page);
    else groups.push({ section: page.section, pages: [page] });
  }
  return groups;
}

/**
 * The `/documentation` landing page: the two API references, the docs copilot,
 * and a jump-off into the user guide. The guide cards are read off the live
 * index rather than hand-listed, so adding a page under `docs/guide/` surfaces
 * it here the same way it surfaces in the rail.
 */
function DocsLanding({ index }: { index: { pages: DocumentationPageSummary[] } | undefined }) {
  const guide = (index?.pages ?? []).filter((p) => p.section === GUIDE_SECTION);
  const lastDocSlug = useUIStore((s) => s.docsChat.lastDocSlug);
  // Visitors (public read-only mode) get the pages, not the API references
  // (login-only) or the docs copilot (AI).
  const isVisitor = useIsVisitor();

  return (
    <div className={styles.landing}>
      <header className={styles.landingHeader}>
        <h1 className={styles.landingTitle}>IntelFeed documentation</h1>
        <p className={styles.landingLede}>
          How to use the app, how to run it, and how it
          works underneath. Pick a page from the contents, or just ask.
        </p>
      </header>

      {!isVisitor && (<>
      <div className={styles.apiRow}>
        <a href="/docs" target="_blank" rel="noopener noreferrer" className={styles.apiCard}>
          <svg className={styles.apiIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <polyline points="14 2 14 8 20 8" />
            <line x1="16" y1="13" x2="8" y2="13" />
            <line x1="16" y1="17" x2="8" y2="17" />
          </svg>
          <span className={styles.apiText}>
            <strong>API reference</strong>
            <em>Swagger UI — every endpoint, callable in the browser</em>
          </span>
          <ExternalIcon />
        </a>
        <a href="/redoc" target="_blank" rel="noopener noreferrer" className={styles.apiCard}>
          <svg className={styles.apiIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
            <line x1="8" y1="6" x2="21" y2="6" />
            <line x1="8" y1="12" x2="21" y2="12" />
            <line x1="8" y1="18" x2="21" y2="18" />
            <line x1="3" y1="6" x2="3.01" y2="6" />
            <line x1="3" y1="12" x2="3.01" y2="12" />
            <line x1="3" y1="18" x2="3.01" y2="18" />
          </svg>
          <span className={styles.apiText}>
            <strong>API reference (ReDoc)</strong>
            <em>The same API as a readable, searchable document</em>
          </span>
          <ExternalIcon />
        </a>
      </div>

      <DocsCopilot docSlug={lastDocSlug ?? undefined} />
      </>)}

      {guide.length > 0 && (
        <section className={styles.guide}>
          <h2 className={styles.guideTitle}>Start here</h2>
          <div className={styles.guideGrid}>
            {guide.map((p) => (
              <Link key={p.slug} to={`/documentation/${p.slug}`} className={styles.guideCard}>
                <strong>{p.title}</strong>
                {p.summary && <span>{p.summary}</span>}
              </Link>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

export default function DocumentationPage() {
  const { "*": splat } = useParams();
  // "" is the landing page, not a missing slug: /documentation is its own
  // surface (API references + the docs copilot), and the doc pages hang off it.
  const slug = splat ?? LANDING;
  const isLanding = slug === LANDING;
  const navigate = useNavigate();
  const [filter, setFilter] = useState("");

  const { data: index, isLoading: indexLoading } = useDocumentationIndex();
  const { data: page, isLoading: pageLoading, isError } = useDocumentationPage(slug);
  const rail = useRailWidth("docs-nav", { default: 260, min: 190, max: 480 });
  const navCollapsed = useUIStore((s) => s.docsNavCollapsed);
  const isVisitorPage = useIsVisitor();
  const toggleDocsNav = useUIStore((s) => s.toggleDocsNav);
  // Docs carry their own contents rail; the app sidebar folds away beside it,
  // the same bargain Settings makes.
  useAppSidebarAutoCollapse();
  const isMobile = useIsMobile();

  // Remember what was being read, so the landing page's chat still has the page
  // as context once you navigate back to it to ask about it.
  const setDocsChat = useUIStore((s) => s.setDocsChat);
  useEffect(() => {
    if (!isLanding && slug) setDocsChat((prev) => ({ ...prev, lastDocSlug: slug }));
  }, [isLanding, slug, setDocsChat]);

  const groups = useMemo(() => {
    const pages = index?.pages ?? [];
    const needle = filter.trim().toLowerCase();
    if (!needle) return groupBySection(pages);
    return groupBySection(
      pages.filter(
        (p) =>
          p.title.toLowerCase().includes(needle) ||
          p.slug.toLowerCase().includes(needle) ||
          (p.summary ?? "").toLowerCase().includes(needle),
      ),
    );
  }, [index, filter]);

  // Heading anchors worked out from the markdown source, so a repeated heading gets
  // its `-1` suffix and every id is the one GitHub would give it. The renderers
  // below look theirs up by line; the slug of the rendered text is the fallback.
  const headingIds = useMemo(() => headingIdsByLine(page?.markdown ?? ""), [page?.markdown]);

  const components = useMemo(
    () => ({
      code({ className, children, ...props }: React.ComponentPropsWithoutRef<"code">) {
        if (className === "language-mermaid") {
          return <MermaidDiagram chart={String(children).trim()} />;
        }
        return (
          <code className={className} {...props}>
            {children}
          </code>
        );
      },
      a({ href, children, ...props }: React.ComponentPropsWithoutRef<"a">) {
        const internal = resolveHref(href, slug);
        if (internal) {
          return (
            <a
              href={internal}
              onClick={(e) => {
                e.preventDefault();
                navigate(internal);
              }}
              {...props}
            >
              {children}
            </a>
          );
        }
        const external = href && /^https?:/i.test(href);
        return (
          <a href={href} {...(external ? { target: "_blank", rel: "noopener noreferrer" } : {})} {...props}>
            {children}
          </a>
        );
      },
      img({ src, alt, ...props }: React.ComponentPropsWithoutRef<"img">) {
        const resolved = resolveAssetSrc(typeof src === "string" ? src : undefined, slug);
        if (!resolved) return null;
        return <img src={resolved} alt={alt ?? ""} loading="lazy" {...props} />;
      },
      h2: ({ node, children, ...props }: HeadingProps) => (
        <h2 id={headingIds.get(node?.position?.start.line ?? -1) ?? slugify(nodeText(children))} {...props}>
          {children}
        </h2>
      ),
      h3: ({ node, children, ...props }: HeadingProps) => (
        <h3 id={headingIds.get(node?.position?.start.line ?? -1) ?? slugify(nodeText(children))} {...props}>
          {children}
        </h3>
      ),
    }),
    [slug, navigate, headingIds],
  );

  // Where you are, named on the mobile trigger the way Settings names its
  // active section.
  const activeTitle = isLanding ? "Documentation home" : page?.title ?? slug;

  // One nav, two containers: a resizable column on desktop, a slide-over sheet
  // behind a single row on mobile — the same bargain Settings makes, where
  // stacking the rail inline ate the screen before any prose.
  const navContent = (
    <>
      <input
        className={styles.filter}
        type="search"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter pages…"
        aria-label="Filter documentation pages"
      />
      <nav className={styles.nav}>
        <Link
          to="/documentation"
          className={`${styles.homeLink} ${isLanding ? styles.navLinkActive : ""}`}
        >
          <svg className={styles.footerIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
            <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
            <polyline points="9 22 9 12 15 12 15 22" />
          </svg>
          <span>Documentation home</span>
        </Link>
        {indexLoading && <p className={styles.muted}>Loading contents…</p>}
        {!indexLoading && groups.length === 0 && <p className={styles.muted}>No pages match “{filter}”.</p>}
        {groups.map((group) => (
          <div key={group.section} className={styles.group}>
            <h2 className={styles.groupTitle}>{group.section}</h2>
            <ul className={styles.groupList}>
              {group.pages.map((p) => (
                <li key={p.slug}>
                  <Link
                    to={`/documentation/${p.slug}`}
                    title={p.summary ?? undefined}
                    className={`${styles.navLink} ${p.slug === slug ? styles.navLinkActive : ""}`}
                  >
                    {p.title}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
      {!isVisitorPage && (
      <div className={styles.sidebarFooter}>
        <Link to="/settings" className={styles.footerLink}>
          <svg className={styles.footerIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
          </svg>
          <span>Settings</span>
        </Link>
      </div>
      )}
    </>
  );

  const pageContent = (
    <>
      {isLanding && <DocsLanding index={index} />}
      {!isLanding && pageLoading && <p className={styles.muted}>Loading…</p>}
      {!isLanding && isError && (
        <div className={styles.notFound}>
          <h2>Page not found</h2>
          <p>
            No documentation page named <code>{slug}</code>.
          </p>
          <Link to="/documentation">Back to the documentation home</Link>
        </div>
      )}
      {!isLanding && page && (
        <article className={styles.article}>
          <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
            {page.markdown}
          </ReactMarkdown>
        </article>
      )}
    </>
  );

  if (isMobile) {
    return (
      <div className={styles.container}>
        <MobileNavSheet title="Documentation" current={activeTitle}>
          {navContent}
        </MobileNavSheet>
        <main className={styles.content}>{pageContent}</main>
      </div>
    );
  }

  return (
    <div
      className={styles.container}
      style={{ "--docs-rail-w": `${rail.width}px` } as React.CSSProperties}
    >
      <aside className={`${styles.sidebar} ${navCollapsed ? styles.sidebarCollapsed : ""}`}>
        {navContent}
      </aside>

      {!navCollapsed && (
        <ResizeHandle label="documentation contents" className={styles.railResizer} {...rail.handleProps} />
      )}
      <RailToggle
        side="left"
        collapsed={navCollapsed}
        onToggle={toggleDocsNav}
        label="documentation contents"
      />

      <main className={styles.content}>{pageContent}</main>
    </div>
  );
}
