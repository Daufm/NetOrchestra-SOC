import { useState } from "react";
import { KeyRound, LogOut, ShieldCheck } from "lucide-react";

export default function ChangePassword({ username, onSubmit, onLogout }) {
  const [form, setForm] = useState({ currentPassword: "", newPassword: "", confirmPassword: "" });
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  function update(event) {
    setForm((previous) => ({ ...previous, [event.target.name]: event.target.value }));
  }

  async function submit(event) {
    event.preventDefault();
    setError("");
    if (form.newPassword !== form.confirmPassword) {
      setError("New passwords do not match.");
      return;
    }
    setSubmitting(true);
    try {
      await onSubmit(form.currentPassword, form.newPassword);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="min-h-screen flex items-center justify-center p-6">
      <form onSubmit={submit} className="w-full max-w-md rounded-lg border border-soc-border bg-soc-card p-8 shadow-neon">
        <div className="flex items-center gap-3"><ShieldCheck className="text-soc-neon" aria-hidden="true" /><h1 className="font-mono text-lg text-soc-neon">SECURE OPERATOR ACCOUNT</h1></div>
        <p className="mt-4 text-sm text-slate-400">A password change is required before continuing as <span className="text-soc-neon">{username}</span>.</p>
        <label className="mt-6 block text-sm" htmlFor="current-password">Current password</label>
        <input id="current-password" name="currentPassword" type="password" autoComplete="current-password" value={form.currentPassword} onChange={update} required className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2" />
        <label className="mt-4 block text-sm" htmlFor="new-password">New password</label>
        <input id="new-password" name="newPassword" type="password" minLength="12" autoComplete="new-password" value={form.newPassword} onChange={update} required className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2" />
        <label className="mt-4 block text-sm" htmlFor="confirm-password">Confirm new password</label>
        <input id="confirm-password" name="confirmPassword" type="password" minLength="12" autoComplete="new-password" value={form.confirmPassword} onChange={update} required className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2" />
        {error && <p className="mt-4 rounded border border-red-500/50 bg-red-950/30 p-3 text-sm text-red-300" role="alert">{error}</p>}
        <button disabled={submitting} className="mt-6 flex w-full items-center justify-center gap-2 rounded bg-soc-neon px-4 py-2 font-semibold text-soc-bg disabled:opacity-50" type="submit"><KeyRound size={16} />{submitting ? "Updating..." : "Change password"}</button>
        <button type="button" onClick={onLogout} className="mt-3 flex w-full items-center justify-center gap-2 rounded border border-soc-border px-4 py-2 text-sm text-slate-300 hover:border-soc-neon"><LogOut size={15} /> Sign out</button>
      </form>
    </main>
  );
}
