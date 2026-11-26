import assert from "node:assert/strict";
import { test } from "node:test";

import { addFailed, enqueue, isRetryable, MAX_FAILED, MAX_ITEMS } from "../src/lib/outbox.js";

test("network errors and proxy errors are retryable, refusals are not", () => {
  assert.equal(isRetryable(new TypeError("Failed to fetch")), true);
  assert.equal(isRetryable({ status: 503 }), true);
  assert.equal(isRetryable({ status: 422 }), false);
  assert.equal(isRetryable(new Error("other")), false);
});

test("enqueue keeps the page, oldest first", () => {
  let q = [];
  ({ queue: q } = enqueue(q, { kind: "page", body: { url: "https://a.example/1", html: "<p>1</p>", title: "One" } }, 1));
  ({ queue: q } = enqueue(q, { kind: "link", body: { url: "https://a.example/2" } }, 2));
  assert.deepEqual(
    q.map((i) => [i.kind, i.url, i.title, i.queuedAt]),
    [
      ["page", "https://a.example/1", "One", 1],
      ["link", "https://a.example/2", "https://a.example/2", 2],
    ],
  );
});

test("a page too big for the queue is kept as a link without its HTML", () => {
  const big = "x".repeat(9 * 1000 * 1000);
  const { queue, downgraded } = enqueue([], { kind: "page", body: { url: "https://a.example/big", html: big, note: "n" } });
  assert.equal(downgraded, true);
  assert.equal(queue[0].kind, "link");
  assert.equal(queue[0].body.html, undefined);
  assert.equal(queue[0].body.note, "n");
});

test("a full queue refuses", () => {
  const q = Array.from({ length: MAX_ITEMS }, (_, i) => ({ kind: "link", body: { url: `https://a.example/${i}` } }));
  assert.throws(() => enqueue(q, { kind: "link", body: { url: "https://a.example/x" } }), /already waiting/);
});

test("the failed list keeps only the newest", () => {
  let failed = [];
  for (let i = 0; i < MAX_FAILED + 3; i++) failed = addFailed(failed, { title: `t${i}`, url: `u${i}` }, "no", i);
  assert.equal(failed.length, MAX_FAILED);
  assert.equal(failed.at(-1).title, `t${MAX_FAILED + 2}`);
});
