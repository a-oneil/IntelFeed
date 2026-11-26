import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

// A stand-in for chrome.storage.local, enough for lib/store.js.
let data;
globalThis.chrome = {
  storage: {
    local: {
      get: async (keys) => Object.fromEntries(keys.filter((k) => k in data).map((k) => [k, data[k]])),
      set: async (patch) => Object.assign(data, patch),
      remove: async (keys) => keys.forEach((k) => delete data[k]),
    },
  },
};

const api = await import("../src/lib/api.js");

let calls;
function serve(routes) {
  calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(url);
    calls.push({ path: u.pathname, auth: init.headers?.Authorization, body: init.body && JSON.parse(init.body) });
    const [status, body] = routes(u.pathname, init);
    return new Response(status === 204 ? null : JSON.stringify(body), { status });
  };
}

beforeEach(() => {
  data = {};
});

test("normalizeServer trims and refuses non-http", () => {
  assert.equal(api.normalizeServer(" https://intel.example.com/ "), "https://intel.example.com");
  assert.equal(api.normalizeServer("http://10.0.0.5:3001/intel/"), "http://10.0.0.5:3001/intel");
  assert.throws(() => api.normalizeServer("ftp://x"));
  assert.throws(() => api.normalizeServer("intel.example.com"));
  assert.equal(api.originPattern("http://10.0.0.5:3001/intel"), "http://10.0.0.5/*");
  assert.equal(api.originPattern("https://intel.example.com"), "https://intel.example.com/*");
});

test("sign in keeps the session, never the password", async () => {
  serve(() => [200, { access_token: "a1", refresh_token: "r1" }]);
  await api.signIn("https://intel.example.com/", "ana", "s3cret");
  assert.deepEqual(data, { server: "https://intel.example.com", username: "ana", access: "a1", refresh: "r1" });
  assert.ok(!JSON.stringify(data).includes("s3cret"));
});

test("a 401 refreshes once and repeats the request", async () => {
  Object.assign(data, { server: "https://s", access: "old", refresh: "r1" });
  serve((path, init) => {
    if (path === "/api/auth/refresh") return [200, { access_token: "new", refresh_token: "r2" }];
    return init.headers.Authorization === "Bearer new" ? [200, { ok: 1 }] : [401, { detail: "expired" }];
  });
  assert.deepEqual(await api.request("/api/auth/me"), { ok: 1 });
  assert.deepEqual(
    calls.map((c) => c.path),
    ["/api/auth/me", "/api/auth/refresh", "/api/auth/me"],
  );
  assert.equal(data.refresh, "r2");
});

test("parallel 401s share one refresh (refresh tokens rotate)", async () => {
  Object.assign(data, { server: "https://s", access: "old", refresh: "r1" });
  serve((path, init) => {
    if (path === "/api/auth/refresh") return [200, { access_token: "new", refresh_token: "r2" }];
    return init.headers.Authorization === "Bearer new" ? [200, {}] : [401, {}];
  });
  await Promise.all([api.request("/a"), api.request("/b"), api.request("/c")]);
  assert.equal(calls.filter((c) => c.path === "/api/auth/refresh").length, 1);
});

test("a refused refresh signs out", async () => {
  Object.assign(data, { server: "https://s", access: "old", refresh: "r1", username: "ana" });
  serve((path) => (path === "/api/auth/refresh" ? [401, { detail: "revoked" }] : [401, {}]));
  await assert.rejects(api.request("/api/auth/me"), api.NotSignedIn);
  assert.deepEqual(data, { server: "https://s", username: "ana" });
});

test("server errors carry the app's code and message", async () => {
  Object.assign(data, { server: "https://s", access: "a", refresh: "r" });
  serve(() => [422, { error: { code: "extraction_failed", message: "The page has no readable text" } }]);
  await assert.rejects(api.request("/x", { method: "POST", body: {} }), (err) => {
    assert.equal(err.status, 422);
    assert.equal(err.code, "extraction_failed");
    assert.equal(err.message, "The page has no readable text");
    return true;
  });
});

test("raw mode returns a 404 instead of throwing", async () => {
  Object.assign(data, { server: "https://s", access: "a", refresh: "r" });
  serve(() => [404, { error: { code: "not_found", message: "No entry for this URL" } }]);
  const res = await api.request("/api/entries/ingest/lookup", { query: { url: "https://x" }, raw: true });
  assert.equal(res.status, 404);
});

test("a refresh that lost the race to another one does not sign out", async () => {
  Object.assign(data, { server: "https://s", access: "old", refresh: "r1", username: "ana" });
  serve((path, init) => {
    if (path === "/api/auth/refresh") {
      // Someone else renewed the session while this refresh was in flight.
      Object.assign(data, { access: "new", refresh: "r2" });
      return [401, { detail: "Refresh token has been revoked" }];
    }
    return init.headers.Authorization === "Bearer new" ? [200, { ok: 1 }] : [401, {}];
  });
  assert.deepEqual(await api.request("/api/auth/me"), { ok: 1 });
  assert.equal(data.refresh, "r2");
});

test("a request whose token was already replaced retries without refreshing", async () => {
  Object.assign(data, { server: "https://s", access: "old", refresh: "r1" });
  serve((path, init) => {
    if (path === "/api/auth/refresh") return [500, {}];
    if (init.headers.Authorization === "Bearer old") {
      data.access = "new"; // renewed elsewhere between the send and the 401
      return [401, {}];
    }
    return [200, { ok: 1 }];
  });
  assert.deepEqual(await api.request("/x"), { ok: 1 });
  assert.equal(calls.filter((c) => c.path === "/api/auth/refresh").length, 0);
});

test("request sends a FormData as-is and carries error details", async () => {
  data = { server: "https://intel.example.com", access: "a1", refresh: "r1" };
  let seen;
  globalThis.fetch = async (url, init = {}) => {
    seen = init;
    return new Response(
      JSON.stringify({ error: { code: "duplicate", message: "Already ingested", details: [{ entry_id: "e1" }] } }),
      { status: 409 },
    );
  };
  const form = new FormData();
  form.append("url", "https://x.example/a.pdf");
  await assert.rejects(
    api.request("/api/entries/ingest/pdf", { method: "POST", form }),
    (err) => err.status === 409 && err.details[0].entry_id === "e1",
  );
  assert.equal(seen.body, form);
  assert.equal(seen.headers["Content-Type"], undefined);
});

test("unlessSignedOut falls back on any failure except being signed out", async () => {
  const offline = Promise.reject(new TypeError("Failed to fetch"));
  assert.equal(await api.unlessSignedOut(offline, (err) => `fallback: ${err.message}`), "fallback: Failed to fetch");
  const refused = Promise.reject(new api.ApiError(422, "validation_error", "URL too long"));
  assert.equal(await api.unlessSignedOut(refused, () => null), null);
  assert.equal(await api.unlessSignedOut(Promise.resolve(7), () => 0), 7);
  await assert.rejects(api.unlessSignedOut(Promise.reject(new api.NotSignedIn()), () => null), api.NotSignedIn);
});
