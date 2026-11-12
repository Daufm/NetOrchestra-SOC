import { useEffect, useState } from "react";
import { AlertCircle, ShieldCheck, UserPlus } from "lucide-react";
import { useAuth } from "../state/AuthContext.jsx";
import { getAuthStatus } from "../api/client.js";

export default function Login({ onRegister }) {
  const { login } = useAuth();
  const [form, setForm] = useState({ username: "", password: "" });
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [authStatus, setAuthStatus] = useState(null);

  useEffect(() => {
    let active = true;
    getAuthStatus()
      .then((status) => {
        if (active) setAuthStatus(status);
      })
      .catch(() => {
        // If error fetching status, fail closed (no public register)
      });
    return () => {
      active = false;
    };
  }, []);

  async function submit(event) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await login(form.username, form.password);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="min-h-screen flex items-center justify-center p-6">
      <form onSubmit={submit} className="w-full max-w-md rounded-lg border border-soc-border bg-soc-card p-8 shadow-neon">
        <div className="flex items-center gap-3">
          <ShieldCheck className="text-soc-neon" aria-hidden="true" />
          <h1 className="font-mono text-lg text-soc-neon">NETORCHESTRA // SOC</h1>
        </div>
        <p className="mt-3 text-sm text-slate-400">Sign in to the network forensics console.</p>
        <label className="mt-6 block text-sm" htmlFor="username">Username</label>
        <input
          id="username"
          className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2"
          value={form.username}
          onChange={(event) => setForm({ ...form, username: event.target.value })}
          autoComplete="username"
          required
        />
        <label className="mt-4 block text-sm" htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2"
          value={form.password}
          onChange={(event) => setForm({ ...form, password: event.target.value })}
          autoComplete="current-password"
          required
        />
        {error && <p className="mt-4 rounded border border-red-500/50 bg-red-950/30 p-3 text-sm text-red-300" role="alert">{error}</p>}
        <button
          className="mt-6 w-full rounded bg-soc-neon px-4 py-2 font-semibold text-soc-bg disabled:cursor-not-allowed disabled:opacity-50"
          disabled={submitting}
          type="submit"
        >
          {submitting ? "Authenticating..." : "Sign in"}
        </button>

        {authStatus?.bootstrap_mode && (
          <div className="mt-5 rounded-lg border border-yellow-500/40 bg-yellow-950/20 p-3.5 text-xs text-yellow-300">
            <div className="flex items-center gap-1.5 font-semibold text-yellow-400">
              <AlertCircle size={15} /> System Not Initialized
            </div>
            <p className="mt-1 text-slate-400 text-[11px]">
              No accounts exist yet. Use your deployment bootstrap token to initialize the primary administrator account.
            </p>
            <button
              type="button"
              onClick={onRegister}
              className="mt-3 w-full rounded border border-soc-neon bg-soc-neon/10 py-2 text-xs font-semibold text-soc-neon hover:bg-soc-neon/20 transition flex items-center justify-center gap-1.5"
            >
              <UserPlus size={14} /> Initialize Administrator Account
            </button>
          </div>
        )}

        {!authStatus?.bootstrap_mode && authStatus?.allow_registration && (
          <button
            type="button"
            onClick={onRegister}
            className="mt-3 w-full rounded border border-soc-border px-4 py-2 text-sm text-slate-300 hover:border-soc-neon"
          >
            Create account
          </button>
        )}

        {authStatus && !authStatus.bootstrap_mode && !authStatus.allow_registration && (
          <p className="mt-4 text-center text-xs text-slate-500">
            Self-registration is disabled. Accounts must be provisioned by a SOC Administrator.
          </p>
        )}
      </form>
    </main>
  );
}
