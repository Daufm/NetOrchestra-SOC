import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { apiFetch, changePassword as changePasswordRequest, clearAuthTokens, login as loginRequest, logout as logoutRequest, setAuthTokens } from "../api/client.js";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiFetch("/api/auth/me")
      .then((body) => setUser(body.user || body))
      .catch(() => {
        clearAuthTokens();
        setUser(null);
      })
      .finally(() => setLoading(false));
  }, []);

  const value = useMemo(() => ({
    user,
    loading,
    async login(username, password) {
      const body = await loginRequest(username, password);
      setUser(body.user);
      return body;
    },
    async refresh() {
      const body = await apiFetch("/api/auth/refresh", { method: "POST" });
      setAuthTokens(body);
      setUser(body.user);
      return body;
    },
    async changePassword(currentPassword, newPassword) {
      await changePasswordRequest(currentPassword, newPassword);
      clearAuthTokens();
      const body = await loginRequest(user.username, newPassword);
      setUser(body.user);
      return body;
    },
    async logout() {
      await logoutRequest();
      setUser(null);
    },
  }), [loading, user]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}
