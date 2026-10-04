import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { execSync } from "child_process";
import fs from "fs";

/**
 * HEAD's short SHA read straight out of a `.git` directory — no git binary.
 *
 * For the dev container: `docker-compose.dev.yml` bind-mounts the repo's `.git`
 * read-only so this file has something to read, and node:alpine ships no git.
 * Returns "" for anything it does not recognise; the caller falls back.
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
 * The build stamp, from whichever source can actually see it.
 *
 * Three environments, three answers, in descending order of precision:
 *
 *  1. A production image build: compose passes VITE_* build args filled by
 *     scripts/ops/version.sh, because `.git` sits above the build context and
 *     is .dockerignore'd on top of that.
 *  2. A host build or `pnpm dev`: no build arg, but the checkout is right
 *     here, so ask git properly and get tags with it.
 *  3. The dev container: no build arg, no git binary, but `.git` is mounted
 *     read-only at /app/.git — read the SHA out of it by hand.
 *
 * Only if all three miss does it report "dev".
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
  // Compose and both Dockerfiles default the arg to the literal "dev", so an
  // unstamped build arrives as a truthy placeholder. Treat it as "nobody knew"
  // or it short-circuits the chain and the later sources never get a turn.
  const arg = (v?: string) => (v && v !== "dev" ? v : "");

  const envVersion = arg(process.env.VITE_APP_VERSION);
  // `--match='v*'` for the same reason scripts/ops/version.sh carries it: the
  // repo also tags APK releases as `android-v<version>`, and an unfiltered
  // describe reports whichever tag is nearest — which is how the footer came to
  // show the Android app's version. The two must agree or a dev build and an
  // image build disagree about what the same commit is called.
  const gitVersion = envVersion ? "" : git("describe --tags --always --dirty --match='v*'");
  const version = envVersion || gitVersion || mountedSha() || "dev";

  return {
    version,
    sha:
      arg(process.env.VITE_GIT_SHA) ||
      git("rev-parse --short=8 HEAD") ||
      mountedSha(),
    builtAt: arg(process.env.VITE_BUILD_TIME) || new Date().toISOString(),
    // Which of the three sources won, so the running app can tell whether a
    // disagreement with the server is meaningful. Only "env" is: there the
    // bundle and its stamp were produced by the same image build, so a
    // mismatch means the browser is holding an older bundle. Under "git" the
    // stamp is frozen at dev-server start while HMR keeps the code current,
    // so a mismatch is routine and says nothing.
    source: envVersion ? "env" : version === "dev" ? "none" : "git",
  };
}

const stamp = buildStamp();

export default defineConfig({
  plugins: [react()],
  // react-draggable (used by react-grid-layout for widget drag/resize) reads
  // `process.env.DRAGGABLE_DEBUG` in its hot path. Vite auto-defines NODE_ENV but
  // not this, so `process` is undefined in the browser and handleDragStart threw
  // `process is not defined` before starting any drag — silently breaking all
  // widget move/resize. Define it (applies to dev and prod builds).
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
    // The dev container bind-mounts the repo's .git here for the build stamp.
    // Watching it would fire HMR on every fetch, commit and index write.
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
