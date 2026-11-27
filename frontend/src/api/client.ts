import axios, { AxiosError, InternalAxiosRequestConfig } from "axios";
import { toast } from "sonner";
import { selectIsVisitor, useAuthStore } from "@/stores/authStore";

export interface ApiError {
  error: {
    code: string;
    message: string;
    details: Array<{ field?: string; message: string; code: string }>;
  };
}

const api = axios.create({
  baseURL: "/api",
  headers: { "Content-Type": "application/json" },
  timeout: 15000,
});

// Shared refresh promise to deduplicate concurrent refresh attempts
let refreshPromise: Promise<string | null> | null = null;

function decodeJwtPayload(token: string): { exp?: number } | null {
  try {
    const part = token.split(".")[1];
    if (!part) return null;
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

function isTokenExpiringSoon(token: string): boolean {
  const payload = decodeJwtPayload(token);
  if (!payload?.exp) return true;
  const expiresAt = payload.exp * 1000;
  // Refresh if less than 5 minutes remaining
  return expiresAt - Date.now() < 5 * 60 * 1000;
}

function isTokenExpired(token: string): boolean {
  const payload = decodeJwtPayload(token);
  if (!payload?.exp) return true;
  return payload.exp * 1000 <= Date.now();
}

function doRefresh(): Promise<string | null> {
  if (!refreshPromise) {
    refreshPromise = refreshAccessToken().finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
}

/** Whether the instance is browsable without an account. Asked of the server when the answer isn't known yet (a cold load whose refresh failed before registration-status came back) or when `recheck` is set: a 401 with no tokens may mean an admin just switched the mode off. */
let lastModeCheck = 0;
async function publicModeNow(recheck = false): Promise<boolean> {
  const store = useAuthStore.getState();
  if (store.publicReadOnlyKnown && !recheck) return store.publicReadOnly;
  if (recheck && Date.now() - lastModeCheck < 30_000) return store.publicReadOnly;
  lastModeCheck = Date.now();
  try {
    const { data } = await axios.get("/api/auth/registration-status");
    store.setPublicReadOnly(!!data.public_read_only_enabled);
    return !!data.public_read_only_enabled;
  } catch {
    return store.publicReadOnly;
  }
}

async function refreshAccessToken(): Promise<string | null> {
  const refreshToken = useAuthStore.getState().refreshToken;
  if (!refreshToken) return null;
  try {
    const { data } = await axios.post("/api/auth/refresh", {
      refresh_token: refreshToken,
    });
    useAuthStore.getState().setTokens(data.access_token, data.refresh_token);
    return data.access_token as string;
  } catch (err) {
    // Only hard-logout on an explicit 401 or 403 rejection (revoked/expired refresh token). Transient network errors should not wipe the session.
    const status = (err as { response?: { status?: number } })?.response?.status;
    if (status === 401 || status === 403) {
      const publicReadOnly = await publicModeNow();
      useAuthStore.getState().logout();
      if (publicReadOnly) {
        // The instance is browsable without an account: go back to the public view, not the login page.
        window.location.assign("/");
        return null;
      }
      // Hard navigation, not a router push: logout() clears the persisted per-account keys, but the in-memory Zustand stores still hold the old account's workspace state and would write those keys straight back on the next set(). A full reload is what the logout buttons do, and it is the only thing that drops that state.
      window.location.assign("/login");
    }
    return null;
  }
}

// Public auth endpoints that must NOT carry a bearer token (they issue or precede one). Everything else under /auth (me, me/password, logout) is authenticated and needs the token attached like any other request. The list names paths rather than matching the whole "/auth/" prefix, because the prefix left PUT /auth/me without a token, so it got a 401 on every call and only recovered through the response-interceptor retry.
const PUBLIC_AUTH_PATHS = [
  "/auth/login",
  "/auth/register",
  "/auth/refresh",
  "/auth/registration-status",
];

// The read-only POSTs a visitor may send (the server allows the same set in core/public_access.py: ANONYMOUS_READ_POSTS plus ANONYMOUS_READ_POST_TEMPLATES).
const VISITOR_READ_POSTS = [
  "/entries/intel-counts",
  "/entries/resolve-names",
  "/intelligence/resolve-names",
  "/glossary/detect",
  "/autolink/scan",
  // Relationship counts for the entity tables (POST only for the long id list).
  "/entity-relationships/signals/",
];

export class ReadOnlyViewError extends Error {
  constructor() {
    super("This view is read-only.");
    this.name = "ReadOnlyViewError";
  }
}

let lastReadOnlyToast = 0;

/** A visitor's write never leaves the browser: the server would refuse it anyway. */
function refuseVisitorWrite(config: InternalAxiosRequestConfig): boolean {
  const method = (config.method || "get").toLowerCase();
  if (method === "get" || method === "head" || method === "options") return false;
  if (!selectIsVisitor(useAuthStore.getState())) return false;
  if (PUBLIC_AUTH_PATHS.some((p) => config.url?.includes(p))) return false;
  if (VISITOR_READ_POSTS.some((p) => config.url?.startsWith(p))) return false;
  if (/^\/entities\/[^/]+\/context-values$/.test(config.url || "")) return false;
  return true;
}

// Add auth token to requests — proactively refresh if expired or expiring soon
api.interceptors.request.use(async (config: InternalAxiosRequestConfig) => {
  if (refuseVisitorWrite(config)) {
    console.debug("Read-only view: refused", config.method?.toUpperCase(), config.url);
    // Controls that write are hidden for visitors, so reaching this means one was missed: show one quiet toast instead of a stack of error toasts.
    if (Date.now() - lastReadOnlyToast > 10_000) {
      lastReadOnlyToast = Date.now();
      toast("This view is read-only.");
    }
    throw new ReadOnlyViewError();
  }
  if (PUBLIC_AUTH_PATHS.some((p) => config.url?.includes(p))) return config;

  const { accessToken, refreshToken } = useAuthStore.getState();
  if (accessToken && !isTokenExpiringSoon(accessToken)) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  } else if (refreshToken) {
    const newToken = await doRefresh();
    if (newToken) {
      config.headers.Authorization = `Bearer ${newToken}`;
    } else if (accessToken && !isTokenExpired(accessToken)) {
      config.headers.Authorization = `Bearer ${accessToken}`;
    }
  }
  return config;
});

// Refresh the token and retry once on 401; reject a 429 without retrying
api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError<ApiError>) => {
    const original = error.config;

    // Rate limited — reject immediately, don't retry (prevents request storms)
    if (error.response?.status === 429) {
      return Promise.reject(error);
    }

    if (
      error.response?.status === 401 &&
      original &&
      !original.url?.includes("/auth/refresh") &&
      !(original as unknown as Record<string, boolean>)._retry
    ) {
      (original as unknown as Record<string, boolean>)._retry = true;
      const newToken = await doRefresh();
      if (newToken) {
        original.headers.Authorization = `Bearer ${newToken}`;
        return api(original);
      }
      // A visitor was refused: the mode may just have been switched off. If so, the store updates and the route guard sends them to the login page instead of leaving a half-loaded app.
      const store = useAuthStore.getState();
      if (!store.accessToken && store.publicReadOnly) void publicModeNow(true);
    }
    return Promise.reject(error);
  }
);

export default api;
