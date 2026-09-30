import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import { useExternalLinkSettings } from "@/hooks/useExternalLinkSettings";
import { useExternalLinkStore } from "@/stores/externalLinkStore";
import type { ExternalLinkInfo } from "@/utils/externalLinks";
import { defangObservable } from "@/utils/observables";

import styles from "./ExternalLinkModal.module.css";

async function copy(text: string, label: string) {
  try {
    await navigator.clipboard.writeText(text);
    toast.success(`${label} copied`);
  } catch {
    toast.error("Couldn't copy to the clipboard");
  }
}

/**
 * The interstitial itself: where the link goes (host first, since that is what
 * an analyst needs to read), the full URL in a copyable block, and a loud banner
 * when the visible text names a different host than the href.
 *
 * Focus starts on Cancel, not Open — the point of the dialog is a beat to look,
 * and a reflexive Enter after activating the link should not sail through it.
 */
export function ExternalLinkModal({ info }: { info: ExternalLinkInfo }) {
  const trapRef = useFocusTrap<HTMLDivElement>();
  const cancelRef = useRef<HTMLButtonElement>(null);
  const release = useExternalLinkStore((s) => s.release);
  const trustForSession = useExternalLinkStore((s) => s.trustForSession);
  const { canSave, trustHost } = useExternalLinkSettings();
  const [remember, setRemember] = useState(false);

  // Declared after useFocusTrap so this runs second and wins the initial focus.
  useEffect(() => {
    cancelRef.current?.focus();
  }, []);

  // The entry list and reader bind j/k/o/Enter/Escape/... on window/document and
  // only skip text inputs, so a focused dialog button would otherwise also open
  // the selected article (Enter) or close the reader behind us (Escape). Keys
  // are swallowed in the capture phase, except Tab, which the focus trap needs.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        release();
      } else if (e.key !== "Tab") {
        e.stopPropagation();
      }
    };
    document.addEventListener("keydown", onKeyDown, true);
    return () => document.removeEventListener("keydown", onKeyDown, true);
  }, [release]);

  // Trusting a host from a link that is lying about it would be a strange thing
  // to offer, and wouldn't skip the prompt next time anyway.
  const canRemember = info.mismatch === null && !info.notes.some((n) => n.id === "userinfo");

  const open = () => {
    // Navigate first, synchronously: awaiting a network save before window.open
    // can cost the click its user-activation, and Safari then blocks the popup.
    release();
    if (info.newTab) {
      window.open(info.url, "_blank", "noopener,noreferrer");
    } else {
      window.location.assign(info.url);
    }

    if (!remember || !canRemember) return;
    // Trust for this page load straight away so a second click can't race the save.
    trustForSession(info.host);
    if (canSave) {
      trustHost(info.host).catch(() => {
        toast.error("Couldn't save that preference — it will only last until you close this tab");
      });
    }
  };

  return (
    <div className={styles.overlay} onClick={release}>
      <div
        className={styles.modal}
        ref={trapRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="external-link-title"
        onClick={(e) => e.stopPropagation()}
      >
        <h3 id="external-link-title" className={styles.title}>
          You&apos;re leaving IntelFeed
        </h3>

        <div className={styles.host} data-testid="external-link-host">
          {info.host}
        </div>

        {info.mismatch && (
          <div className={styles.danger} role="alert">
            <strong>The link text and destination don&apos;t match.</strong> The text names{" "}
            <code>{info.mismatch.claimedHost}</code>, but the link goes to{" "}
            <code>{info.mismatch.actualHost}</code>.
          </div>
        )}

        {info.notes.map((note) => (
          <div key={note.id} className={styles.warning}>
            {note.message}
          </div>
        ))}

        {info.text && (
          <p className={styles.linkText}>
            Link text: <span>&ldquo;{info.text}&rdquo;</span>
          </p>
        )}

        <code className={styles.url} data-testid="external-link-url">
          {info.url}
        </code>

        {canRemember && (
          <label className={styles.remember}>
            <input
              type="checkbox"
              checked={remember}
              onChange={(e) => setRemember(e.target.checked)}
            />
            <span>
              Don&apos;t ask again for <code>{info.host}</code>
              {!canSave && " (until you close this tab)"}
            </span>
          </label>
        )}

        <div className={styles.actions}>
          <button ref={cancelRef} type="button" className={styles.secondaryBtn} onClick={release}>
            Cancel
          </button>
          <button
            type="button"
            className={styles.secondaryBtn}
            onClick={() => copy(info.url, "Link")}
          >
            Copy link
          </button>
          <button
            type="button"
            className={styles.secondaryBtn}
            onClick={() => copy(defangObservable("url", info.url), "Defanged link")}
          >
            Copy defanged
          </button>
          <button type="button" className={styles.primaryBtn} onClick={open}>
            Open link
          </button>
        </div>
      </div>
    </div>
  );
}
