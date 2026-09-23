import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  // react-draggable (used by react-grid-layout for widget drag/resize) reads
  // `process.env.DRAGGABLE_DEBUG` in its hot path. Vite auto-defines NODE_ENV but
  // not this, so `process` is undefined in the browser and handleDragStart threw
  // `process is not defined` before starting any drag — silently breaking all
  // widget move/resize. Define it (applies to dev and prod builds).
  define: {
    "process.env.DRAGGABLE_DEBUG": "false",
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    sourcemap: false,
    rollupOptions: {
      output: {
        // Vite 8 (rolldown) only supports the function form of manualChunks.
        manualChunks(id: string) {
          if (!id.includes("node_modules")) return undefined;
          if (/node_modules\/(react|react-dom|react-router-dom)\//.test(id)) return "vendor-react";
          if (id.includes("node_modules/@tanstack/react-query/")) return "vendor-tanstack";
          if (id.includes("node_modules/@tiptap/") || id.includes("node_modules/lowlight/")) return "vendor-tiptap";
          if (/node_modules\/(zustand|axios|dompurify)\//.test(id)) return "vendor-misc";
          return undefined;
        },
      },
    },
  },
  server: {
    port: 3000,
    host: true,
    allowedHosts: ["localhost", "127.0.0.1"],
    proxy: {
      "/api": {
        target: process.env.VITE_API_URL || "http://localhost:8000",
        changeOrigin: true,
      },
      "/docs": {
        target: process.env.VITE_API_URL || "http://localhost:8000",
        changeOrigin: true,
      },
      "/redoc": {
        target: process.env.VITE_API_URL || "http://localhost:8000",
        changeOrigin: true,
      },
      "/openapi.json": {
        target: process.env.VITE_API_URL || "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: { modules: { classNameStrategy: "non-scoped" } },
    // tests/e2e is Playwright's (see playwright.config.ts testDir). Vitest
    // would otherwise collect those specs and fail on the @playwright/test
    // import, which is not a dependency of the unit-test run.
    exclude: ["**/node_modules/**", "**/dist/**", "tests/e2e/**"],
    // Each worker starts its own jsdom. Unbounded on a 16-core box that is
    // ~15 of them, which exhausts the dev container's memory and leaves most
    // files reporting "Timeout waiting for worker to respond" instead of
    // running at all. The Docker VM has ~7.6GB shared with celery/redis/
    // meilisearch, so free memory routinely dips under 1GB — 4 workers still
    // flaked right after a memory-hungry `pnpm build`. Two costs ~6s on a
    // ~15s suite and leaves enough headroom to be reliable.
    maxWorkers: 2,
  },
});
