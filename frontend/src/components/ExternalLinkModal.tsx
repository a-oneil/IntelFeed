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

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") release();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [release]);

  // Trusting a host from a link that is lying about it would be a strange thing
  // to offer, and wouldn't skip the prompt next time anyway.
  const canRemember = info.mismatch === null && !info.notes.some((n) => n.id === "userinfo");

  const open = async () => {
    if (remember && canRemember) {
      if (canSave) {
        try {
          await trustHost(info.host);
        } catch {
          toast.error("Couldn't save that preference — trusting it for this session only");
          trustForSession(info.host);
        }
      } else {
        trustForSession(info.host);
      }
    }
    release();
    if (info.newTab) {
      window.open(info.url, "_blank", "noopener,noreferrer");
    } else {
      window.location.assign(info.url);
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
