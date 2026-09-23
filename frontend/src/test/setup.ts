import { vi } from "vitest";
import "@testing-library/jest-dom";

// jsdom in this Vitest configuration ships a `localStorage` proxy whose
// Storage methods (`setItem`, `getItem`, etc.) are undefined, breaking
// zustand's persist middleware. Replace it with a working in-memory shim.
{
  const memory = new Map<string, string>();
  const storage: Storage = {
    getItem: (k) => (memory.has(k) ? memory.get(k)! : null),
    setItem: (k, v) => {
      memory.set(k, String(v));
    },
    removeItem: (k) => {
      memory.delete(k);
    },
    clear: () => memory.clear(),
    key: (i) => Array.from(memory.keys())[i] ?? null,
    get length() {
      return memory.size;
    },
  };
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    writable: true,
    value: storage,
  });
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    writable: true,
    value: storage,
  });
}

// Mock window.matchMedia for jsdom. Everything is false except hover/pointer
// capability: jsdom stands in for a desktop browser, and hover cards skip
// rendering entirely on a coarse pointer (see useHasHover).
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: /\bhover:\s*hover\b|\bpointer:\s*fine\b/.test(query),
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
});

// Mock URL.createObjectURL / revokeObjectURL for jsdom
if (typeof URL.createObjectURL === "undefined") {
  URL.createObjectURL = () => "blob:mock";
}
if (typeof URL.revokeObjectURL === "undefined") {
  URL.revokeObjectURL = () => {};
}

// Mock HTMLMediaElement.play/pause for jsdom
window.HTMLMediaElement.prototype.play = vi.fn().mockResolvedValue(undefined);
window.HTMLMediaElement.prototype.pause = vi.fn();

// Mock IntersectionObserver for jsdom
class MockIntersectionObserver {
  readonly root = null;
  readonly rootMargin = "";
  readonly thresholds: ReadonlyArray<number> = [];
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords(): IntersectionObserverEntry[] { return []; }
}
Object.defineProperty(window, "IntersectionObserver", {
  writable: true,
  value: MockIntersectionObserver,
});
