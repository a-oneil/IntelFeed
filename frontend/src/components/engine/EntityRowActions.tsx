/**
 * EntityRowActions — the per-row "⋯" entity-management menu the review
 * queues share (Proposals, Remove links, Reclassify), so an analyst can fix
 * the entity a proposal is about without pivoting to its profile: merge it
 * into another, rename it, add an alias, convert its type, or delete it and
 * put its names on the do-not-recreate list. The same actions as the New
 * entities lens, for any catalogue type the queues surface.
 *
 * Rendered as a fixed-position popover so it escapes the table's scroll
 * clipping. Every change invalidates the review, extraction and engine
 * caches, and the proposals about a deleted entity are cleared server-side.
 */

import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import api from "@/api/client";
import { EntityMergeIntoModal } from "@/components/EntityMergeIntoModal";
import { confirmDialog, promptDialog } from "@/utils/dialog";
import { getEntityLabel } from "@/utils/entityTheme";

import styles from "./EntityRowActions.module.css";

// entity_type → REST slug of the per-type profile endpoints.
const SLUGS: Record<string, string> = {
  threat_actor: "threat-actors",
  malware: "malware",
  tool: "tools",
  vendor: "vendors",
  product: "products",
  country: "countries",
  cve: "cves",
  ttp: "ttps",
};
const MERGEABLE = new Set(["threat_actor", "malware", "tool"]);
const NAMEABLE = new Set(["threat_actor", "malware", "tool", "vendor", "product"]);
// /entities/convert moves any of these into any other.
const CONVERT_TARGETS: { key: string; needsIdentifier?: "cve" | "ttp" }[] = [
  { key: "threat_actor" },
  { key: "malware" },
  { key: "tool" },
  { key: "vendor" },
  { key: "product" },
  { key: "country" },
  { key: "cve", needsIdentifier: "cve" },
  { key: "ttp", needsIdentifier: "ttp" },
];
const CONVERTIBLE = new Set(CONVERT_TARGETS.map((t) => t.key));
// Types the delete endpoint accepts (observables have their own ledger actions).
const DELETABLE = new Set(["threat_actor", "malware", "tool", "vendor", "product", "country", "cve", "ttp"]);

function errMsg(err: unknown, fallback: string): string {
  const detail = (err as { response?: { data?: { message?: string; detail?: string } } })?.response?.data;
  return detail?.message ?? detail?.detail ?? (err as Error)?.message ?? fallback;
}

export function EntityRowActions({
  entityType,
  entityId,
  name,
  aliases,
  disabled,
  onChanged,
}: {
  entityType: string;
  entityId: string;
  name: string;
  /** Current aliases when the caller has them; fetched from the profile otherwise. */
  aliases?: string[];
  disabled?: boolean;
  /** Called after any change (merge, rename, alias, convert, delete). */
  onChanged?: () => void;
}) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [convertOpen, setConvertOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const [mergeOpen, setMergeOpen] = useState(false);
  const btnRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = () => {
      setOpen(false);
      setConvertOpen(false);
    };
    const onDown = (e: MouseEvent) => {
      if (menuRef.current?.contains(e.target as Node) || btnRef.current?.contains(e.target as Node)) return;
      close();
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    // Any scroll shifts the anchor — close rather than track.
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [open]);

  const slug = SLUGS[entityType];
  const canMerge = MERGEABLE.has(entityType);
  const canName = NAMEABLE.has(entityType);
  const canConvert = CONVERTIBLE.has(entityType);
  const canDelete = DELETABLE.has(entityType);
  if (!slug || (!canMerge && !canName && !canConvert && !canDelete)) return null;

  function changed() {
    qc.invalidateQueries({ queryKey: ["hygiene"] });
    qc.invalidateQueries({ queryKey: ["extraction"] });
    qc.invalidateQueries({ queryKey: ["engine"] });
    qc.invalidateQueries({ queryKey: ["entity-links"] });
    qc.invalidateQueries({ queryKey: ["relationships"] });
    onChanged?.();
  }

  function toggle() {
    if (!open && btnRef.current) {
      const r = btnRef.current.getBoundingClientRect();
      setPos({ top: r.bottom + 4, left: r.right });
    }
    setConvertOpen(false);
    setOpen((o) => !o);
  }

  function run(fn: () => void | Promise<void>) {
    setOpen(false);
    setConvertOpen(false);
    void fn();
  }

  async function rename() {
    const next = await promptDialog({
      title: "Rename entity",
      message: `Rename "${name}" to:`,
      defaultValue: name,
      confirmLabel: "Rename",
    });
    if (!next || next === name) return;
    try {
      await api.put(`/entities/${slug}/${entityId}`, { name: next });
      toast.success(`Renamed to "${next}"`);
      changed();
    } catch (err) {
      toast.error(errMsg(err, "Rename failed"));
    }
  }

  async function addAlias() {
    const alias = await promptDialog({
      title: "Add alias",
      message: `Add an alias to "${name}":`,
      confirmLabel: "Add alias",
    });
    if (!alias) return;
    try {
      let existing = aliases;
      if (!existing) {
        const { data } = await api.get<{ aliases?: string[] }>(`/entities/${slug}/${entityId}`);
        existing = data.aliases ?? [];
      }
      if (existing.some((a) => a.toLowerCase() === alias.toLowerCase())) {
        toast.info(`"${alias}" is already an alias`);
        return;
      }
      await api.put(`/entities/${slug}/${entityId}`, { aliases: [...existing, alias] });
      toast.success(`Added alias "${alias}"`);
      changed();
    } catch (err) {
      toast.error(errMsg(err, "Failed to add alias"));
    }
  }

  async function convert(target: (typeof CONVERT_TARGETS)[number]) {
    let targetIdentifier: string | undefined;
    if (target.needsIdentifier) {
      const answer = await promptDialog({
        title: target.needsIdentifier === "cve" ? "CVE ID" : "ATT&CK technique ID",
        message:
          target.needsIdentifier === "cve"
            ? "Enter the CVE ID for the new record (e.g. CVE-2024-1234):"
            : "Enter the ATT&CK technique ID for the new record (e.g. T1059 or T1059.001):",
        placeholder: target.needsIdentifier === "cve" ? "CVE-2024-1234" : "T1059.001",
      });
      if (!answer) return;
      targetIdentifier = answer;
    }
    const label = getEntityLabel(target.key);
    if (
      !(await confirmDialog({
        title: "Convert entity",
        message: `Convert "${name}" to ${label}? Entry links and relationships migrate to the new entity, and every pending proposal about it is settled.`,
        confirmLabel: "Convert",
        destructive: true,
      }))
    )
      return;
    try {
      await api.post("/entities/convert", {
        entity_id: entityId,
        target_type: target.key,
        ...(targetIdentifier ? { target_identifier: targetIdentifier } : {}),
      });
      toast.success(`Converted to ${label}`);
      changed();
    } catch (err) {
      toast.error(errMsg(err, "Conversion failed"));
    }
  }

  async function remove() {
    const denies = entityType !== "country";
    if (
      !(await confirmDialog({
        title: `Delete "${name}"`,
        message:
          `"${name}" is deleted with all its article links and relationships, and every pending proposal about it is cleared.` +
          (denies ? " Its name and aliases go on the do-not-recreate list, so the extractor and the autolinker won't mint it again." : "") +
          " This cannot be undone.",
        confirmLabel: "Delete",
        destructive: true,
      }))
    )
      return;
    try {
      const { data } = await api.post<{ deleted: number; denied: number }>("/engine/extraction/delete", {
        entity_type: entityType,
        ids: [entityId],
        deny: denies,
      });
      if (data.deleted) toast.success(denies ? `Deleted "${name}" and denylisted its names` : `Deleted "${name}"`);
      else toast.message("Nothing was deleted — already gone");
      changed();
    } catch (err) {
      toast.error(errMsg(err, "Delete failed"));
    }
  }

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        className={styles.trigger}
        title={`Manage ${name}`}
        aria-label={`Manage ${name}`}
        aria-haspopup="menu"
        aria-expanded={open}
        disabled={disabled}
        onClick={toggle}
      >
        ⋯
      </button>
      {open && pos && (
        <div ref={menuRef} className={styles.menu} style={{ top: pos.top, left: pos.left }} role="menu">
          {canMerge && (
            <button type="button" className={styles.item} role="menuitem" onClick={() => run(() => setMergeOpen(true))}>
              Merge into…
            </button>
          )}
          {canName && (
            <>
              <button type="button" className={styles.item} role="menuitem" onClick={() => run(rename)}>
                Rename…
              </button>
              <button type="button" className={styles.item} role="menuitem" onClick={() => run(addAlias)}>
                Add alias…
              </button>
            </>
          )}
          {canConvert && (
            <button type="button" className={styles.item} aria-expanded={convertOpen} onClick={() => setConvertOpen((o) => !o)}>
              Convert type <span className="caret-glyph">{convertOpen ? "▾" : "▸"}</span>
            </button>
          )}
          {convertOpen && (
            <div className={styles.submenu}>
              {CONVERT_TARGETS.filter((t) => t.key !== entityType).map((t) => (
                <button key={t.key} type="button" className={styles.item} role="menuitem" onClick={() => run(() => convert(t))}>
                  {getEntityLabel(t.key)}
                </button>
              ))}
            </div>
          )}
          {canDelete && (
            <button type="button" className={`${styles.item} ${styles.danger}`} role="menuitem" onClick={() => run(remove)}>
              {entityType === "country" ? "Delete entity" : "Delete + never recreate"}
            </button>
          )}
        </div>
      )}
      {mergeOpen && (
        <EntityMergeIntoModal
          entityType={entityType}
          keeperId={entityId}
          keeperName={name}
          onClose={() => setMergeOpen(false)}
          onMerged={changed}
        />
      )}
    </>
  );
}
