// The IntelFeed API client. Runs only in the background worker: every page of
// the extension asks the worker (messages.js), so there is one fetcher and one
// refresh in flight at a time. Refresh tokens rotate — two contexts refreshing
// with the same token would have the second one refused and sign the user out.
//
// Requests leave from the worker, which holds host permission for the
// server's origin (granted on the options page), so the server needs no CORS
// entry for the extension.

import * as store from "./store.js";

export class NotSignedIn extends Error {
  constructor(message = "Not signed in") {
    super(message);
    this.name = "NotSignedIn";
  }
}

export class ApiError extends Error {
  constructor(status, code, message, details = []) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

/** "https://intel.example.com/" → "https://intel.example.com"; throws on anything but http(s). */
export function normalizeServer(input) {
  let url;
  try {
    url = new URL(String(input || "").trim());
  } catch {
    throw new Error("Enter the server address, for example https://intel.example.com.");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("The server address must start with https:// or http://.");
  }
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

/**
 * The match pattern host permission is requested for. Without the port:
 * Firefox ignores a port in a match pattern, so `http://localhost:3001/*`
 * reports as granted but never applies, and every request fails CORS
 * (bugzilla.mozilla.org/show_bug.cgi?id=1362809). Chrome treats a pattern
 * without a port as any port, so both browsers grant the same thing.
 */
export function originPattern(server) {
  const { protocol, hostname } = new URL(server);
  return `${protocol}//${hostname}/*`;
}

async function errorFrom(resp) {
  let code = "http_error";
  let message = `${resp.status} ${resp.statusText}`.trim();
  let details = [];
  try {
    const body = await resp.json();
    if (body?.error) {
      code = body.error.code || code;
      message = body.error.message || message;
      details = Array.isArray(body.error.details) ? body.error.details : [];
    } else if (typeof body?.detail === "string") {
      message = body.detail;
    }
  } catch {
    // not JSON
  }
  return new ApiError(resp.status, code, message, details);
}

async function post(server, path, body, access) {
  const headers = { "Content-Type": "application/json" };
  if (access) headers.Authorization = `Bearer ${access}`;
  return fetch(`${server}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
}

export async function signIn(serverInput, username, password) {
  const server = normalizeServer(serverInput);
  const resp = await post(server, "/api/auth/login", { username, password });
  if (!resp.ok) throw await errorFrom(resp);
  const tokens = await resp.json();
  await store.save({ server, username, access: tokens.access_token, refresh: tokens.refresh_token });
  return { server, username };
}

export async function signOut() {
  const { server, access, refresh } = await store.load();
  if (server && access) {
    try {
      await post(server, "/api/auth/logout", { refresh_token: refresh }, access);
    } catch {
      // offline or already expired: forgetting the tokens is what matters
    }
  }
  await store.clearSession();
}

let refreshing = null;

// Every extension context that might refresh (the worker, and in Firefox an
// event page that can be restarted) shares this lock, so only one refresh
// token is ever in flight.
const withLock = (fn) => (globalThis.navigator?.locks ? navigator.locks.request("intelfeed-refresh", fn) : fn());

/**
 * Trade the refresh token for a new pair. Refresh tokens are single-use: a
 * second refresh with the same token is refused. So this runs one at a time,
 * skips the trade when the access token that failed has already been replaced,
 * and only signs out when the token the server refused is still the current one.
 */
export function refreshSession(failedAccess) {
  refreshing ??= withLock(async () => {
    const { server, access, refresh } = await store.load();
    if (!server || !refresh) throw new NotSignedIn();
    if (failedAccess && access && access !== failedAccess) return; // already renewed
    const resp = await post(server, "/api/auth/refresh", { refresh_token: refresh });
    if (resp.status === 401 || resp.status === 403) {
      const now = await store.load();
      if (now.refresh && now.refresh !== refresh) return; // renewed while this one was in flight
      await store.clearSession();
      throw new NotSignedIn("You have been signed out because your session expired. Sign in again in the extension settings.");
    }
    if (!resp.ok) throw await errorFrom(resp);
    const tokens = await resp.json();
    await store.save({ access: tokens.access_token, refresh: tokens.refresh_token });
  }).finally(() => {
    refreshing = null;
  });
  return refreshing;
}

/**
 * An authenticated request. On a 401 the session is refreshed once and the
 * request repeated. Resolves to the parsed JSON body (null for 204), or to
 * `{status, body}` when `raw` is set. `form` (a FormData) is sent as
 * multipart instead of `body`.
 */
export async function request(path, { method = "GET", query, body, form, raw = false } = {}) {
  let sentWith = null;
  const send = async () => {
    const { server, access } = await store.load();
    if (!server || !access) throw new NotSignedIn();
    sentWith = access;
    const url = new URL(`${server}${path}`);
    for (const [key, value] of Object.entries(query || {})) url.searchParams.set(key, value);
    const headers = { Authorization: `Bearer ${access}` };
    if (form) return fetch(url, { method, headers, body: form });
    if (body !== undefined) headers["Content-Type"] = "application/json";
    return fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  };

  let resp = await send();
  if (resp.status === 401) {
    await refreshSession(sentWith);
    resp = await send();
  }
  if (!resp.ok && !(raw && resp.status === 404)) throw await errorFrom(resp);
  const parsed = resp.status === 204 ? null : await resp.json();
  return raw ? { status: resp.status, body: parsed } : parsed;
}

/** `promise`'s value; when it fails for any reason except being signed out, `fallback(err)`. */
export async function unlessSignedOut(promise, fallback) {
  try {
    return await promise;
  } catch (err) {
    if (err instanceof NotSignedIn) throw err;
    return fallback(err);
  }
}
