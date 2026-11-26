import assert from "node:assert/strict";
import { test } from "node:test";

import { compareVersions, latestRelease } from "../src/lib/version.js";

test("versions compare numerically", () => {
  assert.equal(compareVersions("1.0.10", "1.0.9"), 1);
  assert.equal(compareVersions("1.2.0", "1.10.0"), -1);
  assert.equal(compareVersions("2.0.0", "2.0.0"), 0);
});

test("the newest extension release wins; app, draft and prerelease tags are ignored", () => {
  const releases = [
    { tag_name: "android-v1.9", html_url: "a" },
    { tag_name: "extension-v1.0.2", html_url: "x102" },
    { tag_name: "extension-v1.1.0", html_url: "x110", prerelease: true },
    { tag_name: "extension-v1.0.10", html_url: "x1010" },
    { tag_name: "extension-v1.0.9", html_url: "x109", draft: true },
  ];
  assert.deepEqual(latestRelease(releases), { version: "1.0.10", url: "x1010" });
  assert.equal(latestRelease([]), null);
});
