import { create } from "zustand";

export type DialogKind = "confirm" | "alert" | "prompt";

export interface DialogRequest {
  id: number;
  kind: DialogKind;
  /** Short heading. Defaults per kind when omitted. */
  title?: string;
  /** Body text. Newlines are preserved, so native-style messages carry over. */
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Red confirm button, and focus starts on Cancel rather than Confirm. */
  destructive?: boolean;
  /** prompt only. */
  defaultValue?: string;
  placeholder?: string;
  /** prompt only: an empty answer cannot be submitted. Defaults to true. */
  required?: boolean;
  resolve: (value: boolean | string | null) => void;
}

interface DialogState {
  /** FIFO. Only the head is rendered; the rest wait their turn. */
  queue: DialogRequest[];
  push: (req: DialogRequest) => void;
  /** Resolves the request and drops it, ignoring ids already settled. */
  settle: (id: number, value: boolean | string | null) => void;
}

export const useDialogStore = create<DialogState>((set, get) => ({
  queue: [],
  push: (req) => set((s) => ({ queue: [...s.queue, req] })),
  settle: (id, value) => {
    const req = get().queue.find((r) => r.id === id);
    if (!req) return;
    set((s) => ({ queue: s.queue.filter((r) => r.id !== id) }));
    req.resolve(value);
  },
}));
