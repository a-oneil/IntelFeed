import { useRef, useEffect, useMemo } from "react";
import DOMPurify from "dompurify";
import api from "@/api/client";
import { annotateGlossaryHTML, type GlossaryTermHighlight } from "@/utils/highlightText";
import { UNTRUSTED_CONTENT_ATTR, isExternalWebUrl } from "@/utils/externalLinks";
import { useReadingPrefs } from "@/hooks/useReadingPrefs";

interface SafeHTMLProps {
  html: string;
  className?: string;
  style?: React.CSSProperties;
  glossaryTerms?: GlossaryTermHighlight[];
}

export function SafeHTML({ html, className, style, glossaryTerms }: SafeHTMLProps) {
  const ref = useRef<HTMLDivElement>(null);
  // Settings → Reading → "Open links in new tab": outside links in article
  // content get target="_blank" (on) or lose it (off). Same-site links are
  // left alone either way.
  const openLinksNewTab = useReadingPrefs().open_links_new_tab;

  const clean = useMemo(() => {
    DOMPurify.addHook("afterSanitizeAttributes", (node) => {
      if (node.tagName === "A") {
        const href = node.getAttribute("href") || "";
        if (isExternalWebUrl(href)) {
          if (openLinksNewTab) node.setAttribute("target", "_blank");
          else node.removeAttribute("target");
        }
      }
      // Enforce rel="noopener noreferrer" on all target="_blank" links
      if (node.tagName === "A" && node.getAttribute("target") === "_blank") {
        node.setAttribute("rel", "noopener noreferrer");
      }
      // A <form action> / formaction sends the browser off-site without an
      // <a>, so it would slip past the external-link confirmation. Drop only
      // destinations that LEAVE the site; forms, controls and same-site
      // destinations are left alone. (Image-map <area> links are handled by
      // the click guard itself, so their content stays intact.)
      for (const attr of ["action", "formaction"]) {
        const value = node.getAttribute?.(attr);
        if (value && isExternalWebUrl(value)) node.removeAttribute(attr);
      }
    });

    const sanitized = DOMPurify.sanitize(html, {
      USE_PROFILES: { html: true },
      ADD_ATTR: ["target", "loading"],
      FORBID_TAGS: ["style", "script", "iframe", "object", "embed"],
      FORBID_ATTR: ["onerror", "onload", "onclick", "onmouseover"],
      ALLOWED_URI_REGEXP: /^(?:(?:f|ht)tps?|mailto|tel|callto|cid|blob):|^\//i,
    });

    DOMPurify.removeHook("afterSanitizeAttributes");
    let result = sanitized;
    if (glossaryTerms && glossaryTerms.length > 0) {
      result = annotateGlossaryHTML(result, glossaryTerms);
    }
    return result;
  }, [html, glossaryTerms, openLinksNewTab]);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    const blobUrls: string[] = [];
    const controller = new AbortController();

    // Transparent 1x1 pixel to preserve image dimensions while loading
    const PLACEHOLDER =
      "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";

    // Lazy-load proxied images: only fetch when near viewport
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          const img = entry.target as HTMLImageElement;
          observer.unobserve(img);

          const src = img.dataset.proxySrc;
          if (!src) return;

          const apiPath = src.replace(/^\/api/, "");
          api
            .get<Blob>(apiPath, {
              responseType: "blob",
              signal: controller.signal,
            })
            .then((response) => {
              const blobUrl = URL.createObjectURL(response.data);
              blobUrls.push(blobUrl);
              img.src = blobUrl;
            })
            .catch(() => {
              // Extract the original URL from the proxy query string for fallback
              try {
                const params = new URLSearchParams(src.split("?")[1]);
                const originalUrl = params.get("url");
                if (originalUrl) {
                  img.src = originalUrl;
                  return;
                }
              } catch {
                // ignore parse errors
              }
              img.src = src;
            });
        });
      },
      { rootMargin: "200px" },
    );

    el.querySelectorAll<HTMLImageElement>("img").forEach((img) => {
      // Support re-mount (React StrictMode): check data-proxy-src first
      const proxySrc = img.dataset.proxySrc;
      const src = proxySrc || img.getAttribute("src");
      if (!src || !src.startsWith("/api/proxy/image")) return;

      // Stash the proxy URL and use placeholder to preserve dimensions
      if (!proxySrc) {
        img.dataset.proxySrc = src;
        img.src = PLACEHOLDER;
      }
      img.setAttribute("loading", "lazy");
      observer.observe(img);
    });

    return () => {
      observer.disconnect();
      controller.abort();
      blobUrls.forEach(URL.revokeObjectURL);
    };
  }, [clean]);

  return (
    <div
      ref={ref}
      className={className}
      style={style}
      // Feed-supplied markup: ExternalLinkGuard treats links in here as untrusted
      // even when it is set to "article content only".
      {...{ [UNTRUSTED_CONTENT_ATTR]: "" }}
      dangerouslySetInnerHTML={{ __html: clean }}
    />
  );
}
