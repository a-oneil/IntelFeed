/**
 * ReportDocument — a report's sections drawn as one readable document.
 *
 * Shared by the report builder's Document view and the public shared-report
 * page, so both show the same thing: a heading per section, the narrative as
 * markdown, and data sections (observables, threat surface, TTPs, references,
 * timeline, CVEs, entities) as tables shape-detected the same way the markdown
 * exporter does.
 */

import { EntityLinkedMarkdown } from "@/components/EntityLinkedMarkdown";
import type { EntityScanMatch } from "@/hooks/useEntityScan";
import styles from "./ReportDocument.module.css";

export interface ReportDocSection {
  name: string;
  title: string;
  type: string; // "narrative" | "data"
  body: string;
  items: Record<string, unknown>[];
}

interface Props {
  sections: ReportDocSection[];
  /**
   * Markdown written outside any section, drawn first with no heading. It is
   * the whole document for a template with no sections.
   */
  freeText?: string;
  /** Link entity mentions to their profiles (needs a signed-in session). */
  linkEntities?: boolean;
  /**
   * Entity matches computed server-side (the public page): the mentions are
   * highlighted from these, with no scan and no profile navigation.
   */
  entityMatches?: EntityScanMatch[];
  /**
   * Draw the sections straight on the page, like an article, instead of on
   * the builder's bordered sheet.
   */
  frameless?: boolean;
  /**
   * Text for a section with nothing in it. When omitted, empty sections are
   * left out — the public page shows what was written, not what wasn't.
   */
  emptyText?: (section: ReportDocSection) => string;
}

const cell = (v: unknown) => (Array.isArray(v) ? v.join(", ") : v == null ? "" : String(v));

/** Reference URLs are analyst/AI-written text; on the public page only web links get an anchor. */
function webHref(v: unknown): string | null {
  const s = typeof v === "string" ? v.trim() : "";
  return /^https?:\/\//i.test(s) ? s : null;
}

/** Data-section rows rendered as a real table, shape-detected the same way
 *  the markdown exporter does (observables, threat surface, TTPs, refs...). */
export function SectionItemsTable({ items }: { items: Record<string, unknown>[] }) {
  const first = items[0] || {};

  if ("kind" in first && "value" in first) {
    return (
      <div className={styles.docTableWrap}>
        <table className={styles.docTable}>
          <thead><tr><th>Kind</th><th>Value</th><th>Confidence</th><th>Attribution</th><th>Last seen</th></tr></thead>
          <tbody>
            {items.map((it, i) => (
              <tr key={i}>
                <td>{cell(it.kind)}</td>
                <td className={styles.docMono}>{cell(it.value)}</td>
                <td>{typeof it.confidence === "number" ? `${Math.round((it.confidence as number) * 100)}%` : ""}</td>
                <td>{cell(it.claimed_by)}</td>
                <td>{cell(it.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  if ("matched_regions" in first) {
    return (
      <div className={styles.docTableWrap}>
        <table className={styles.docTable}>
          <thead><tr><th>Entity</th><th>Type</th><th>Regions</th><th>Verticals</th><th>Entries</th><th>Victims</th></tr></thead>
          <tbody>
            {items.map((it, i) => (
              <tr key={i}>
                <td><b>{cell(it.name)}</b></td>
                <td>{cell(it.subtype || (it.entity_type === "threat_actor" ? "actor" : it.entity_type))}</td>
                <td>{cell(it.matched_regions) || "—"}</td>
                <td>{cell(it.matched_sectors) || "—"}</td>
                <td>{cell(it.entry_count)}</td>
                <td>{cell(it.victim_count) || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  if ("technique_id" in first) {
    return (
      <div className={styles.docTableWrap}>
        <table className={styles.docTable}>
          <thead><tr><th>Technique</th><th>Name</th><th>Tactic</th></tr></thead>
          <tbody>
            {items.map((it, i) => (
              <tr key={i}>
                <td className={styles.docMono}>{cell(it.technique_id)}</td>
                <td>{cell(it.name)}</td>
                <td>{cell(it.tactic)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  if ("url" in first && "title" in first) {
    return (
      <ul className={styles.docList}>
        {items.map((it, i) => (
          <li key={i}>
            {webHref(it.url) ? (
              <a href={webHref(it.url)!} target="_blank" rel="noopener noreferrer">{cell(it.title) || cell(it.url)}</a>
            ) : (
              <span>{cell(it.title) || cell(it.url)}</span>
            )}
          </li>
        ))}
      </ul>
    );
  }
  if ("date" in first && "title" in first) {
    return (
      <ul className={styles.docList}>
        {items.map((it, i) => (
          <li key={i}>
            <span className={styles.docMono}>{cell(it.date)?.slice(0, 10) || "?"}</span>: {cell(it.title)}
          </li>
        ))}
      </ul>
    );
  }
  if ("cve_id" in first) {
    return (
      <div className={styles.docTableWrap}>
        <table className={styles.docTable}>
          <thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr></thead>
          <tbody>
            {items.map((it, i) => (
              <tr key={i}>
                <td className={styles.docMono}>{cell(it.cve_id)}</td>
                <td>{cell(it.severity)}</td>
                <td>{cell(it.cvss_score)}</td>
                <td>{String(it.description || "").slice(0, 160)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  return (
    <ul className={styles.docList}>
      {items.map((it, i) => (
        <li key={i}>
          <b>{cell(it.name)}</b>
          {it.aliases ? ` (${cell(it.aliases)})` : ""}
          {it.malware_type ? ` (${cell(it.malware_type)})` : ""}
        </li>
      ))}
    </ul>
  );
}

export function ReportDocument({
  sections,
  freeText,
  linkEntities = true,
  entityMatches,
  frameless = false,
  emptyText,
}: Props) {
  return (
    <div className={frameless ? styles.docPlain : styles.docSurface}>
      {freeText && freeText.trim() && (
        <section className={styles.docSection} data-untrusted-content="">
          <div className={styles.docProse}>
            <EntityLinkedMarkdown
              text={freeText}
              enabled={linkEntities}
              matches={entityMatches}
              readOnly={!!entityMatches}
            />
          </div>
        </section>
      )}
      {sections.map((sec) => {
        const body = sec.body || "";
        const items = Array.isArray(sec.items) ? sec.items : [];
        const empty = !body && items.length === 0;
        if (empty && !emptyText) return null;
        return (
          <section key={sec.name} className={styles.docSection} data-untrusted-content="">
            <h2 className={styles.docHeading}>{sec.title || sec.name}</h2>
            {body && (
              <div className={styles.docProse}>
                <EntityLinkedMarkdown
                  text={body}
                  enabled={linkEntities}
                  matches={entityMatches}
                  readOnly={!!entityMatches}
                />
              </div>
            )}
            {items.length > 0 && <SectionItemsTable items={items} />}
            {empty && emptyText && <p className={styles.docEmpty}>{emptyText(sec)}</p>}
          </section>
        );
      })}
    </div>
  );
}
