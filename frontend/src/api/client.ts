import axios, { AxiosError, InternalAxiosRequestConfig } from "axios";
import { useAuthStore } from "@/stores/authStore";

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

function isTokenExpiringSoon(token: string): boolean {
  try {
    const payload = JSON.parse(atob(token.split(".")[1]));
    const expiresAt = payload.exp * 1000;
    // Refresh if less than 5 minutes remaining
    return expiresAt - Date.now() < 5 * 60 * 1000;
  } catch {
    return true;
  }
}

function doRefresh(): Promise<string | null> {
  if (!refreshPromise) {
    refreshPromise = refreshAccessToken().finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
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
    // Only hard-logout on explicit 401 rejection (revoked/expired refresh token).
    // Transient network errors should not wipe the session.
    const status = (err as { response?: { status?: number } })?.response?.status;
    if (status === 401 || status === 403) {
      useAuthStore.getState().logout();
      // Hard navigation, not a router push: logout() clears the persisted
      // per-account keys, but the in-memory Zustand stores still hold the old
      // account's workspace state and would write those keys straight back on
      // the next set(). A full reload is what the logout buttons do, and it is
      // the only thing that actually drops that state.
      window.location.assign("/login");
    }
    return null;
  }
}

// Public auth endpoints that must NOT carry a bearer token (they issue or
// precede one). Everything else under /auth (me, me/password, logout) is
// authenticated and needs the token attached like any other request — matching
// the whole "/auth/" prefix here previously left PUT /auth/me tokenless, so it
// 401'd on every call and only recovered via the response-interceptor retry.
const PUBLIC_AUTH_PATHS = [
  "/auth/login",
  "/auth/register",
  "/auth/refresh",
  "/auth/registration-status",
  "/auth/invite-code",
];

// Add auth token to requests — proactively refresh if expired or expiring soon
api.interceptors.request.use(async (config: InternalAxiosRequestConfig) => {
  if (PUBLIC_AUTH_PATHS.some((p) => config.url?.includes(p))) return config;

  const { accessToken, refreshToken } = useAuthStore.getState();
  if (accessToken && !isTokenExpiringSoon(accessToken)) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  } else if (refreshToken) {
    const newToken = await doRefresh();
    if (newToken) {
      config.headers.Authorization = `Bearer ${newToken}`;
    }
  }
  return config;
});

// Handle token refresh on 401 and rate-limit backoff on 429
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
    }
    return Promise.reject(error);
  }
);

export default api;
