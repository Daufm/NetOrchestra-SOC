import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { register } from "../api/client.js";

export default function Register({ onBack }) {
  const [form, setForm] = useState({
    username: "",
    email: "",
    password: "",
    confirmPassword: "",
    bootstrapToken: "",
  });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [submitting, setSubmitting] = useState(false);

  function update(event) {
    setForm({ ...form, [event.target.name]: event.target.value });
  }

  async function submit(event) {
    event.preventDefault();
    setError("");
    setSuccess("");
    if (form.password !== form.confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    setSubmitting(true);
    try {
      const user = await register(form);
      setSuccess(`Account ${user.username} created. You can now sign in.`);
      setForm((previous) => ({ ...previous, password: "", confirmPassword: "", bootstrapToken: "" }));
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
          <h1 className="font-mono text-lg text-soc-neon">INITIALIZE OPERATOR</h1>
        </div>
        <p className="mt-3 text-sm text-slate-400">Create the first administrator or a viewer account when public registration is enabled.</p>
        <label className="mt-5 block text-sm" htmlFor="register-username">Username</label>
        <input id="register-username" name="username" value={form.username} onChange={update} autoComplete="username" required className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2" />
        <label className="mt-4 block text-sm" htmlFor="register-email">Email <span className="text-slate-500">(optional)</span></label>
        <input id="register-email" name="email" type="email" value={form.email} onChange={update} autoComplete="email" className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2" />
        <label className="mt-4 block text-sm" htmlFor="register-password">Password</label>
        <input id="register-password" name="password" type="password" minLength="12" value={form.password} onChange={update} autoComplete="new-password" required className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2" />
        <label className="mt-4 block text-sm" htmlFor="register-confirm-password">Confirm password</label>
        <input id="register-confirm-password" name="confirmPassword" type="password" minLength="12" value={form.confirmPassword} onChange={update} autoComplete="new-password" required className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2" />
        <label className="mt-4 block text-sm" htmlFor="bootstrap-token">Bootstrap token <span className="text-slate-500">(first admin only)</span></label>
        <input id="bootstrap-token" name="bootstrapToken" type="password" value={form.bootstrapToken} onChange={update} autoComplete="off" className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2" />
        {error && <p className="mt-4 rounded border border-red-500/50 bg-red-950/30 p-3 text-sm text-red-300" role="alert">{error}</p>}
        {success && <p className="mt-4 rounded border border-soc-neon/50 bg-soc-deep/30 p-3 text-sm text-soc-neon" role="status">{success}</p>}
        <button className="mt-6 w-full rounded bg-soc-neon px-4 py-2 font-semibold text-soc-bg disabled:opacity-50" disabled={submitting} type="submit">
          {submitting ? "Creating account..." : "Create account"}
        </button>
        <button type="button" onClick={onBack} className="mt-3 w-full rounded border border-soc-border px-4 py-2 text-sm text-slate-300 hover:border-soc-neon">
          Back to sign in
        </button>
      </form>
    </main>
  );
}
