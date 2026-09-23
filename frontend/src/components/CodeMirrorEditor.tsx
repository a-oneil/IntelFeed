import { useRef, useEffect, useCallback } from "react";
import { EditorView, keymap, lineNumbers, highlightActiveLine } from "@codemirror/view";
import { markdown, markdownLanguage } from "@codemirror/lang-markdown";
import { tags } from "@lezer/highlight";
import { EditorState, Prec } from "@codemirror/state";
import { yaml } from "@codemirror/lang-yaml";
import { sql } from "@codemirror/lang-sql";
import { StreamLanguage } from "@codemirror/language";
import { oneDark } from "@codemirror/theme-one-dark";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { searchKeymap, highlightSelectionMatches } from "@codemirror/search";
import { bracketMatching, indentOnInput, syntaxHighlighting, defaultHighlightStyle, HighlightStyle } from "@codemirror/language";
import { linter, type Diagnostic } from "@codemirror/lint";
import type { RuleValidationError } from "@/api/types";
import styles from "./CodeMirrorEditor.module.css";

interface CodeMirrorEditorProps {
  value: string;
  onChange?: (value: string) => void;
  language: string;
  readOnly?: boolean;
  validationErrors?: RuleValidationError[];
  height?: string;
  /** Prose mode: markdown/free text, not code — drops line numbers and
   *  active-line highlight so reports don't read like source files. */
  prose?: boolean;
}

// Lightweight stream-based language mode for Snort/Suricata rules
const snortSuricataMode: Parameters<typeof StreamLanguage.define>[0] = {
  token(stream) {
    if (stream.match(/^#.*/)) return "comment";
    if (stream.match(/^(alert|log|pass|drop|reject|sdrop)\b/)) return "keyword";
    if (stream.match(/^(tcp|udp|icmp|ip|http|dns|tls|ssh|smtp|ftp)\b/)) return "typeName";
    if (stream.match(/^(msg|content|sid|rev|classtype|priority|flow|reference|metadata|pcre|nocase|depth|offset|distance|within|fast_pattern|threshold)\s*:/))
      return "propertyName";
    if (stream.match(/^"[^"]*"/)) return "string";
    if (stream.match(/^\d+\.\d+\.\d+\.\d+(\/\d+)?/)) return "number";
    if (stream.match(/^\$\w+/)) return "variableName";
    if (stream.match(/^[();!<>-]+/)) return "operator";
    stream.next();
    return null;
  },
};

// Lightweight stream-based language mode for YARA rules
const yaraMode: Parameters<typeof StreamLanguage.define>[0] = {
  token(stream) {
    if (stream.match(/^\/\/.*/)) return "comment";
    if (stream.match(/^\/\*[\s\S]*?\*\//)) return "comment";
    if (stream.match(/^(rule|meta|strings|condition|import|include|private|global)\b/)) return "keyword";
    if (stream.match(/^(all|any|of|them|at|in|for|and|or|not|contains|matches|icontains|startswith|endswith|iequals|true|false)\b/)) return "keyword";
    if (stream.match(/^(uint8|uint16|uint32|int8|int16|int32|filesize|entrypoint)\b/)) return "typeName";
    if (stream.match(/^"[^"]*"/)) return "string";
    if (stream.match(/^\{[\s0-9a-fA-F?[\]|()-]+\}/)) return "string";
    if (stream.match(/^\/[^/]*\//)) return "string";
    if (stream.match(/^\$\w*/)) return "variableName";
    if (stream.match(/^#\w*/)) return "variableName";
    if (stream.match(/^@\w*/)) return "variableName";
    if (stream.match(/^0x[0-9a-fA-F]+/)) return "number";
    if (stream.match(/^\d+/)) return "number";
    if (stream.match(/^[={}():,]/)) return "operator";
    stream.next();
    return null;
  },
};

// Lightweight stream-based language mode for SPL (Splunk Search Processing Language)
const splMode: Parameters<typeof StreamLanguage.define>[0] = {
  token(stream) {
    if (stream.match(/^`[^`]*`/)) return "comment";
    if (stream.match(/^(search|where|eval|stats|table|rename|fields|sort|head|tail|top|rare|dedup|rex|replace|fillnull|lookup|inputlookup|outputlookup|append|join|transaction|chart|timechart|bin|bucket|spath|mvexpand|makemv|multikv|addinfo|addtotals|eventstats|streamstats|collect|return|outputcsv|sendemail)\b/i))
      return "keyword";
    if (stream.match(/^(count|sum|avg|min|max|values|list|dc|earliest|latest|stdev|perc\d+|range|first|last)\s*\(/))
      return "typeName";
    if (stream.match(/^(index|sourcetype|source|host|splunk_server|earliest|latest|_time|_raw)\b/)) return "propertyName";
    if (stream.match(/^(AND|OR|NOT|AS|BY|OVER|OUTPUT)\b/)) return "keyword";
    if (stream.match(/^"[^"]*"/)) return "string";
    if (stream.match(/^\d+/)) return "number";
    if (stream.match(/^\|/)) return "operator";
    if (stream.match(/^[=!<>]+/)) return "operator";
    stream.next();
    return null;
  },
};

// Lightweight stream-based language mode for KQL (Kusto Query Language)
const kqlMode: Parameters<typeof StreamLanguage.define>[0] = {
  token(stream) {
    if (stream.match(/^\/\/.*/)) return "comment";
    if (stream.match(/^(where|project|extend|summarize|join|union|let|render|take|limit|top|sort|order|by|asc|desc|on|kind|leftouter|innerunique|count|distinct|has|contains|startswith|endswith|matches|regex|in|between|ago|now|bin|toscalar|iff|iif|case|pack|parse|mv-expand|mv-apply|lookup|datatable|print|invoke|evaluate|set|alias|restrict|access|search|find|union|external_data)\b/))
      return "keyword";
    if (stream.match(/^(count|sum|avg|min|max|dcount|make_set|make_list|arg_max|arg_min|percentile|stdev|variance|countif|sumif|avgif|dcountif|any|take_any)\s*\(/))
      return "typeName";
    if (stream.match(/^(and|or|not)\b/)) return "keyword";
    if (stream.match(/^"[^"]*"/)) return "string";
    if (stream.match(/^'[^']*'/)) return "string";
    if (stream.match(/^\d+[dhms]?\b/)) return "number";
    if (stream.match(/^[|=!<>~]+/)) return "operator";
    stream.next();
    return null;
  },
};


/* Prose mode (reports, analyst writing): markdown parsing plus document
   typography — headings sized and weighted, syntax marks dimmed, body face
   instead of mono — so writing a report doesn't feel like editing source. */
const proseHighlight = HighlightStyle.define([
  { tag: tags.heading1, fontSize: "1.35em", fontWeight: "700", color: "var(--text-primary)" },
  { tag: tags.heading2, fontSize: "1.2em", fontWeight: "700", color: "var(--text-primary)" },
  { tag: tags.heading3, fontSize: "1.08em", fontWeight: "600", color: "var(--text-primary)" },
  { tag: tags.strong, fontWeight: "700" },
  { tag: tags.emphasis, fontStyle: "italic" },
  { tag: tags.monospace, fontFamily: "var(--font-mono)", fontSize: "0.92em" },
  { tag: tags.link, color: "var(--accent)", textDecoration: "underline" },
  { tag: tags.url, color: "var(--accent)" },
  { tag: tags.quote, fontStyle: "italic", opacity: "0.85" },
  { tag: tags.processingInstruction, opacity: "0.45" },
  { tag: tags.contentSeparator, opacity: "0.45" },
]);

const proseTheme = EditorView.theme({
  ".cm-content": {
    fontFamily: "var(--font-body)",
    fontSize: "14px",
    lineHeight: "1.7",
    padding: "18px 22px",
    maxWidth: "78ch",
  },
  ".cm-line": { padding: "0" },
});

function getLanguageExtension(language: string) {
  switch (language) {
    case "sigma":
      return yaml();
    case "splunk_spl":
      return StreamLanguage.define(splMode);
    case "kql":
      return StreamLanguage.define(kqlMode);
    case "elastic_ql":
    case "crowdstrike_ql":
      return sql();
    case "snort_suricata":
      return StreamLanguage.define(snortSuricataMode);
    case "yara":
      return StreamLanguage.define(yaraMode);
    default:
      return [];
  }
}

export default function CodeMirrorEditor({
  value,
  onChange,
  language,
  readOnly = false,
  validationErrors = [],
  height = "400px",
  prose = false,
}: CodeMirrorEditorProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  // Convert validation errors to CM6 diagnostics
  const errorsRef = useRef(validationErrors);
  errorsRef.current = validationErrors;

  const createLinter = useCallback(() => {
    return linter(() => {
      const diagnostics: Diagnostic[] = [];
      for (const err of errorsRef.current) {
        const line = err.line ?? 1;
        const view = viewRef.current;
        if (!view) continue;
        const doc = view.state.doc;
        if (line < 1 || line > doc.lines) continue;
        const lineInfo = doc.line(line);
        diagnostics.push({
          from: lineInfo.from,
          to: lineInfo.to,
          severity: err.severity === "error" ? "error" : "warning",
          message: err.message,
        });
      }
      return diagnostics;
    });
  }, []);

  useEffect(() => {
    if (!containerRef.current) return;

    const extensions = [
      ...(prose
        ? [
            markdown({ base: markdownLanguage }),
            Prec.high(syntaxHighlighting(proseHighlight)),
            Prec.high(proseTheme),
          ]
        : [lineNumbers(), highlightActiveLine()]),
      bracketMatching(),
      indentOnInput(),
      highlightSelectionMatches(),
      history(),
      keymap.of([...defaultKeymap, ...historyKeymap, ...searchKeymap]),
      syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
      oneDark,
      getLanguageExtension(language),
      createLinter(),
      EditorView.lineWrapping,
      EditorView.updateListener.of((update) => {
        if (update.docChanged) {
          onChangeRef.current?.(update.state.doc.toString());
        }
      }),
    ];

    if (readOnly) {
      extensions.push(EditorState.readOnly.of(true));
    }

    const state = EditorState.create({
      doc: value,
      extensions,
    });

    const view = new EditorView({
      state,
      parent: containerRef.current,
    });

    viewRef.current = view;

    return () => {
      view.destroy();
      viewRef.current = null;
    };
    // Only re-create on language/readOnly change, not on every value change
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [language, readOnly, createLinter, prose]);

  // Sync external value changes without recreating the editor
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    const currentValue = view.state.doc.toString();
    if (value !== currentValue) {
      view.dispatch({
        changes: { from: 0, to: currentValue.length, insert: value },
      });
    }
  }, [value]);

  // Force re-lint when validation errors change
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    // Trigger a re-lint by dispatching a no-op transaction
    view.dispatch({});
  }, [validationErrors]);

  return (
    <div
      ref={containerRef}
      className={styles.editor}
      style={{ height }}
    />
  );
}
