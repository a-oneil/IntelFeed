import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { execSync } from "child_process";
import fs from "fs";

/**
 * HEAD's short SHA read directly from a `.git` directory, without a git binary.
 *
 * For the dev container: `docker-compose.dev.yml` bind-mounts the repo's `.git` read-only so this file has something to read, and node:alpine ships no git. Returns "" for anything it does not recognize; the caller falls back.
 */
function shaFromGitDir(dir: string): string {
  try {
    const head = fs.readFileSync(path.join(dir, "HEAD"), "utf8").trim();
    // Detached HEAD stores the SHA itself rather than a ref.
    if (!head.startsWith("ref: ")) return head.slice(0, 8);
    const ref = head.slice(5).trim();
    const loose = path.join(dir, ref);
    if (fs.existsSync(loose)) {
      return fs.readFileSync(loose, "utf8").trim().slice(0, 8);
    }
    // A fresh clone has no loose ref for its branch — it lives in packed-refs.
    const packed = fs.readFileSync(path.join(dir, "packed-refs"), "utf8");
    const line = packed.split("\n").find((l) => l.endsWith(` ${ref}`));
    return line ? line.slice(0, 8) : "";
  } catch {
    return "";
  }
}

/**
 * The build stamp, from whichever source is available.
 *
 * Three environments, checked in descending order of precision:
 *
 *  1. A production image build: compose passes VITE_* build args filled by scripts/ops/version.sh, because `.git` sits above the build context and is also excluded by .dockerignore.
 *  2. A host build or `pnpm dev`: no build arg, but the checkout is here, so run git and get tags too.
 *  3. The dev container: no build arg, no git binary, but `.git` is mounted read-only at /app/.git, so read the SHA from it directly.
 *
 * Only if all three fail does it report "dev".
 */
function buildStamp() {
  const git = (cmd: string) => {
    try {
      return execSync(`git ${cmd}`, { stdio: ["ignore", "pipe", "ignore"] })
        .toString()
        .trim();
    } catch {
      return "";
    }
  };
  const mountedSha = () => shaFromGitDir(path.resolve(__dirname, ".git"));
  // Compose and both Dockerfiles default the arg to the literal "dev", so an unstamped build arrives as a truthy placeholder. Treat it as unset, or it short-circuits the chain and the later sources are never tried.
  const arg = (v?: string) => (v && v !== "dev" ? v : "");

  const envVersion = arg(process.env.VITE_APP_VERSION);
  // `--match='v*'` for the same reason scripts/ops/version.sh uses it: the repo also tags APK releases as `android-v<version>`, and an unfiltered describe reports whichever tag is nearest, which made the footer show the Android app's version. The two must match, or a dev build and an image build give the same commit different names.
  const gitVersion = envVersion ? "" : git("describe --tags --always --dirty --match='v*'");
  const version = envVersion || gitVersion || mountedSha() || "dev";

  return {
    version,
    sha:
      arg(process.env.VITE_GIT_SHA) ||
      git("rev-parse --short=8 HEAD") ||
      mountedSha(),
    builtAt: arg(process.env.VITE_BUILD_TIME) || new Date().toISOString(),
    // Which of the three sources was used, so the running app can tell whether a mismatch with the server is meaningful. Only "env" is: there the bundle and its stamp come from the same image build, so a mismatch means the browser has an older bundle. Under "git" the stamp is fixed at dev-server start while HMR keeps the code current, so a mismatch is normal and means nothing.
    source: envVersion ? "env" : version === "dev" ? "none" : "git",
  };
}

const stamp = buildStamp();

export default defineConfig({
  plugins: [react()],
  // react-draggable (used by react-grid-layout for widget drag/resize) reads `process.env.DRAGGABLE_DEBUG` in its hot path. Vite auto-defines NODE_ENV but not this, so without the define `process` is undefined in the browser and handleDragStart throws `process is not defined` before starting any drag, breaking all widget move/resize without a visible error. Defined here for dev and prod builds.
  define: {
    "process.env.DRAGGABLE_DEBUG": "false",
    __APP_VERSION__: JSON.stringify(stamp.version),
    __GIT_SHA__: JSON.stringify(stamp.sha),
    __BUILD_TIME__: JSON.stringify(stamp.builtAt),
    __STAMP_SOURCE__: JSON.stringify(stamp.source),
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
          if (/node_modules\/(zustand|axios|dompurify)\//.test(id)) return "vendor-misc";
          return undefined;
        },
      },
    },
  },
  server: {
    port: 3000,
    host: true,
    // The dev container bind-mounts the repo's .git here for the build stamp. Watching it would fire HMR on every fetch, commit and index write.
    watch: { ignored: ["**/.git/**"] },
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
    // tests/e2e is Playwright's (see playwright.config.ts testDir). Vitest would otherwise collect those specs and fail on the @playwright/test import, which is not a dependency of the unit-test run.
    exclude: ["**/node_modules/**", "**/dist/**", "tests/e2e/**"],
    // Each worker starts its own jsdom. Unbounded on a 16-core machine that is ~15 of them, which exhausts the dev container's memory and leaves most files reporting "Timeout waiting for worker to respond" instead of running. The Docker VM has ~7.6GB shared with celery/redis/meilisearch, so free memory often drops under 1GB, and 4 workers still failed intermittently right after a memory-hungry `pnpm build`. Two workers cost ~6s on a ~15s suite and leave enough headroom to be reliable.
    maxWorkers: 2,
  },
});
