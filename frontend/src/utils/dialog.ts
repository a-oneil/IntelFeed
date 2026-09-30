/**
 * App-styled replacements for `window.confirm` / `alert` / `prompt`.
 *
 * The native dialogs are unstyled, unthemeable, sit outside the app's focus and
 * keyboard handling, and — in the reader — are visually indistinguishable from
 * a dialog a hostile page could have raised. These render the app's own modal
 * instead, through the same `<DialogHost />` that lives in `GlobalModals`.
 *
 * They are plain functions rather than a hook so non-React callers (utils,
 * event handlers, store actions) can use them, mirroring
 * `useExternalLinkStore.getState().hold(...)`. The tradeoff is that they are
 * asynchronous where the native ones block, so every call site must `await`.
 *
 * If no host is mounted (unit tests that render a component in isolation), the
 * promise would never settle, so calls fall back to a safe default instead.
 */
import { useDialogStore, type DialogRequest } from "@/stores/dialogStore";

let nextId = 0;

/** Set by <DialogHost /> while mounted. */
let hostMounted = false;
export function setDialogHostMounted(mounted: boolean) {
  hostMounted = mounted;
}

type Options = Omit<DialogRequest, "id" | "kind" | "resolve" | "message"> & { message: string };

function enqueue(kind: DialogRequest["kind"], opts: Options): Promise<boolean | string | null> {
  if (!hostMounted) {
    // Deny rather than hang: a confirm returns false, a prompt returns null,
    // an alert resolves. Never silently approve a destructive action.
    return Promise.resolve(kind === "confirm" ? false : kind === "prompt" ? null : true);
  }
  return new Promise((resolve) => {
    useDialogStore.getState().push({ ...opts, id: ++nextId, kind, resolve });
  });
}

/** Replaces `confirm()`. Resolves true only if the analyst confirms. */
export async function confirmDialog(opts: string | Options): Promise<boolean> {
  const result = await enqueue("confirm", typeof opts === "string" ? { message: opts } : opts);
  return result === true;
}

/** Replaces `alert()`. Resolves once acknowledged. */
export async function alertDialog(opts: string | Options): Promise<void> {
  await enqueue("alert", typeof opts === "string" ? { message: opts } : opts);
}

/** Replaces `prompt()`. Resolves the trimmed answer, or null if cancelled. */
export async function promptDialog(opts: string | Options): Promise<string | null> {
  const result = await enqueue("prompt", typeof opts === "string" ? { message: opts } : opts);
  return typeof result === "string" ? result : null;
}
