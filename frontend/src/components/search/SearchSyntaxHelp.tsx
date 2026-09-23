import { EXAMPLE_QUERIES, FIELD_GROUPS } from "./queryFields";
import styles from "./SearchSyntaxHelp.module.css";

interface Props {
  /**
   * `"panel"` is the strip that drops in over the results when the toolbar's
   * `?` is on: its own ground and a bottom rule, flush under the toolbar.
   * `"card"` is the standalone block the empty state shows, enclosed on all
   * four sides because nothing is stacked against it.
   */
  variant?: "panel" | "card";
  /** When given, every token becomes a button that appends itself to the query. */
  onInsert?: (token: string) => void;
  /** When given, the example queries become one-click runs. */
  onRunExample?: (query: string) => void;
}

export function SearchSyntaxHelp({ variant = "panel", onInsert, onRunExample }: Props) {
  return (
    <div className={variant === "card" ? styles.card : styles.panel}>
      <div className={styles.title}>Query language</div>

      <div className={styles.groups}>
        {FIELD_GROUPS.map((group) => (
          <div key={group.label} className={styles.group}>
            <div className={styles.groupLabel}>
              {/* Only entity groups carry a colour — the palette is the
                  workbench's entity vocabulary, and Articles or Operators are
                  not entities. Groups are one-per-entity so the colour can sit
                  on the heading instead of on every token beneath it. */}
              {group.accent && <span className={styles.groupRule} style={{ background: group.accent }} />}
              {group.label}
            </div>
            <dl className={styles.fields}>
              {group.fields.map(({ token, hint }) => (
                <div key={token} className={styles.field}>
                  <dt>
                    {onInsert ? (
                      <button
                        type="button"
                        className={styles.token}
                        onClick={() => onInsert(token)}
                        title={`Add ${token} to the search`}
                      >
                        {token}
                      </button>
                    ) : (
                      <code className={styles.token}>{token}</code>
                    )}
                  </dt>
                  <dd className={styles.hint}>{hint}</dd>
                </div>
              ))}
            </dl>
          </div>
        ))}
      </div>

      <div className={styles.examples}>
        <span className={styles.examplesLabel}>Try</span>
        {EXAMPLE_QUERIES.map((q) =>
          onRunExample ? (
            <button key={q} type="button" className={styles.example} onClick={() => onRunExample(q)}>
              {q}
            </button>
          ) : (
            <code key={q} className={styles.example}>
              {q}
            </code>
          ),
        )}
      </div>
    </div>
  );
}
