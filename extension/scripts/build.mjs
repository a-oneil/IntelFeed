// Build one unpacked directory and one zip per browser from the same source:
//   dist/chrome/   dist/intelfeed-extension-chrome-<version>.zip  (Chrome, Edge, Brave…)
//   dist/firefox/  dist/intelfeed-extension-firefox-<version>.zip
// Only the manifest differs. Needs `zip` on PATH (present on macOS and the CI runner).

import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");
const base = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8"));

// Firefox runs MV3 background code as an event page, not a service worker,
// and needs a fixed add-on id for signing and for storage to survive updates.
const GECKO_ID = "intelfeed@a-oneil.github.io";

const manifests = {
  chrome: base,
  firefox: (() => {
    const { minimum_chrome_version: _, ...m } = structuredClone(base);
    m.background = { scripts: [base.background.service_worker], type: "module" };
    m.browser_specific_settings = {
      gecko: {
        id: GECKO_ID,
        strict_min_version: "142.0",
        // Data sent to the server: sign-in details, the content of pages you send,
        // and, when the page features are on, the address and visible text of each page you open.
        data_collection_permissions: { required: ["authenticationInfo", "websiteContent", "browsingActivity"] },
      },
    };
    return m;
  })(),
};

rmSync(dist, { recursive: true, force: true });
for (const [browser, manifest] of Object.entries(manifests)) {
  const out = join(dist, browser);
  mkdirSync(out, { recursive: true });
  cpSync(join(root, "src"), join(out, "src"), { recursive: true });
  cpSync(join(root, "icons"), join(out, "icons"), { recursive: true });
  writeFileSync(join(out, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  const zip = join(dist, `intelfeed-extension-${browser}-${base.version}.zip`);
  execFileSync("zip", ["-qrX", zip, "."], { cwd: out });
  console.log(zip);
}
