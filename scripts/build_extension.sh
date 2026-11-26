#!/bin/zsh
# Builds a new browser-extension version: bumps "version" in extension/manifest.json, runs
# the unit tests and writes one zip per browser to extension/dist/. Commit the bump and merge
# it to main: CI then publishes the release extension-v<version> with both builds attached
# (see docs/browser-extension.md).
#
#   scripts/build_extension.sh            # 1.0.x -> 1.0.x+1
#   scripts/build_extension.sh --minor    # 1.x.y -> 1.x+1.0
#   scripts/build_extension.sh --major    # x.y.z -> x+1.0.0
#   scripts/build_extension.sh --no-bump  # test and build the current version
#
# To try a build without a release: load extension/dist/chrome/ unpacked in Chrome or Edge,
# or extension/dist/firefox/manifest.json from about:debugging in Firefox.
#
# Host-side: needs node (22+) and zip. Run from anywhere in the checkout.
set -e
EXT="$(cd "$(dirname "$0")/../extension" && pwd)"
cd "$EXT"

part=patch
case "$1" in
  --major) part=major ;;
  --minor) part=minor ;;
  --no-bump) part= ;;
  "") ;;
  *) echo "usage: $0 [--major|--minor|--no-bump]" >&2; exit 2 ;;
esac

if [[ -n "$part" ]]; then
  node -e '
    const fs = require("fs");
    const m = JSON.parse(fs.readFileSync("manifest.json", "utf8"));
    let [a, b, c] = m.version.split(".").map(Number);
    if (process.argv[1] === "major") [a, b, c] = [a + 1, 0, 0];
    else if (process.argv[1] === "minor") [b, c] = [b + 1, 0];
    else c += 1;
    m.version = `${a}.${b}.${c}`;
    fs.writeFileSync("manifest.json", JSON.stringify(m, null, 2) + "\n");
    console.log(`Version ${m.version}`);
  ' "$part"
fi

npm test --silent
npm run build --silent
