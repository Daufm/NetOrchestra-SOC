let accessToken = null;
let csrfToken = null;
let refreshInFlight = null;

function readCookie(name) {
  const prefix = `${name}=`;
  return document.cookie
    .split("; ")
    .find((cookie) => cookie.startsWith(prefix))
    ?.slice(prefix.length) || null;
}

export function setAuthTokens({ access_token, csrf_token } = {}) {
  accessToken = access_token || null;
  if (csrf_token) csrfToken = csrf_token;
}

export function clearAuthTokens() {
  accessToken = null;
  csrfToken = null;
}

export function getAccessToken() {
  return accessToken;
}

async function parseResponse(response) {
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const message = body?.error?.message || `Request failed (${response.status})`;
    const error = new Error(message);
    error.status = response.status;
    error.body = body;
    throw error;
  }
  return body;
}

async function refresh() {
  if (!csrfToken) csrfToken = readCookie("neto_csrf");
  if (!refreshInFlight) {
    refreshInFlight = fetch("/api/auth/refresh", {
      method: "POST",
      credentials: "include",
      headers: csrfToken ? { "X-CSRF-Token": csrfToken } : {},
    })
      .then(parseResponse)
      .then((body) => {
        setAuthTokens(body);
        return body;
      })
      .finally(() => {
        refreshInFlight = null;
      });
  }
  return refreshInFlight;
}

export async function refreshAccessToken() {
  return refresh();
}

export async function apiFetch(path, options = {}, canRefresh = true) {
  const headers = new Headers(options.headers);
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
  const csrf = csrfToken || readCookie("neto_csrf");
  if (csrf && !headers.has("X-CSRF-Token")) {
    headers.set("X-CSRF-Token", csrf);
  }
  if (options.body && !headers.has("Content-Type") && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(path, { ...options, headers, credentials: "include" });
  if (response.status === 401 && canRefresh) {
    await refresh();
    return apiFetch(path, options, false);
  }
  return parseResponse(response);
}

export async function apiDownload(path, options = {}, canRefresh = true) {
  const headers = new Headers(options.headers);
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
  const response = await fetch(path, { ...options, headers, credentials: "include" });
  if (response.status === 401 && canRefresh) {
    await refresh();
    return apiDownload(path, options, false);
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.error?.message || `Request failed (${response.status})`);
  }
  return response;
}

export async function getAuthStatus() {
  return apiFetch("/api/auth/status", {}, false);
}

export async function login(username, password) {
  const body = await apiFetch("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  }, false);
  setAuthTokens(body);
  return body;
}

export async function register({ username, password, email, bootstrapToken }) {
  const headers = { "Content-Type": "application/json" };
  if (bootstrapToken) headers["X-Bootstrap-Token"] = bootstrapToken;
  return parseResponse(await fetch("/api/auth/register", {
    method: "POST",
    credentials: "include",
    headers,
    body: JSON.stringify({
      username,
      password,
      ...(email ? { email } : {}),
    }),
  }));
}

export async function adminListUsers() {
  return apiFetch("/api/auth/admin/users");
}

export async function adminCreateUser(payload) {
  return apiFetch("/api/auth/admin/users", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function adminUpdateUser(userId, payload) {
  return apiFetch(`/api/auth/admin/users/${userId}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export async function adminResetPassword(userId, newPassword) {
  return apiFetch("/api/auth/admin/reset-password", {
    method: "POST",
    body: JSON.stringify({ user_id: userId, new_password: newPassword }),
  });
}

export async function changePassword(currentPassword, newPassword) {
  const response = await fetch("/api/auth/change-password", {
    method: "POST",
    credentials: "include",
    headers: {
      Authorization: accessToken ? `Bearer ${accessToken}` : "",
      "Content-Type": "application/json",
      ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
    },
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
  if (!response.ok) return parseResponse(response);
}

export async function logout() {
  const csrf = csrfToken || readCookie("neto_csrf");
  try {
    await apiFetch(
      "/api/auth/logout",
      {
        method: "POST",
        headers: csrf ? { "X-CSRF-Token": csrf } : {},
      },
      false
    );
  } catch (err) {
    console.warn("Logout request failed:", err);
  } finally {
    clearAuthTokens();
    document.cookie = "neto_csrf=; path=/; max-age=0; expires=Thu, 01 Jan 1970 00:00:00 GMT";
  }
}
