import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { useAuth } from "../state/AuthContext.jsx";

export default function Login({ onRegister }) {
  const { login } = useAuth();
  const [form, setForm] = useState({ username: "", password: "" });
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

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
        <button type="button" onClick={onRegister} className="mt-3 w-full rounded border border-soc-border px-4 py-2 text-sm text-slate-300 hover:border-soc-neon">
          Create account
        </button>
      </form>
    </main>
  );
}
