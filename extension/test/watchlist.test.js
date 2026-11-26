import assert from "node:assert/strict";
import { test } from "node:test";

import { watchState } from "../src/lib/watchlist.js";

test("Watch is offered only when it would not replace another mode", () => {
  assert.deepEqual(watchState("malware", undefined), { watchable: true, watched: false });
  assert.deepEqual(watchState("malware", "watch"), { watchable: true, watched: true });
  assert.deepEqual(watchState("vendor", "stack"), { watchable: false, watched: false });
  assert.deepEqual(watchState("threat_actor", "mute"), { watchable: false, watched: false });
  assert.deepEqual(watchState("ttp", undefined), { watchable: false, watched: false });
});
