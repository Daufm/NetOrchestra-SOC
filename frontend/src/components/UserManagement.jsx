import { useEffect, useState } from "react";
import { Shield, UserPlus } from "lucide-react";
import { adminCreateUser, adminListUsers, adminResetPassword, adminUpdateUser } from "../api/client.js";

export default function UserManagement() {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ username: "", email: "", password: "", role: "ANALYST" });
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function load() {
    try { setUsers(await adminListUsers()); } catch (requestError) { setError(requestError.message); }
  }
  useEffect(() => { load(); }, []);

  async function create(event) {
    event.preventDefault();
    try {
      await adminCreateUser(form);
      setForm({ username: "", email: "", password: "", role: "ANALYST" });
      setMessage("User created. They must change the temporary password at first login.");
      setError("");
      await load();
    } catch (requestError) { setError(requestError.message); }
  }

  async function changeRole(user, role) {
    try { await adminUpdateUser(user.id, { role }); setMessage(`${user.username} role updated.`); await load(); }
    catch (requestError) { setError(requestError.message); }
  }

  async function toggle(user) {
    try { await adminUpdateUser(user.id, { is_active: !user.is_active }); setMessage(`${user.username} ${user.is_active ? "disabled" : "enabled"}.`); await load(); }
    catch (requestError) { setError(requestError.message); }
  }

  async function reset(user) {
    const password = window.prompt(`New temporary password for ${user.username} (minimum 12 characters):`);
    if (!password) return;
    try { await adminResetPassword(user.id, password); setMessage(`Password reset for ${user.username}.`); setError(""); }
    catch (requestError) { setError(requestError.message); }
  }

  return (
    <section className="mt-4 rounded-lg border border-soc-border bg-soc-card p-5">
      <div className="flex items-center gap-2"><Shield size={18} className="text-soc-neon" /><h2 className="font-semibold">User management</h2></div>
      <form onSubmit={create} className="mt-4 grid gap-3 rounded border border-soc-border bg-soc-bg p-4 sm:grid-cols-2 lg:grid-cols-5">
        <input required placeholder="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} className="rounded border border-soc-border bg-soc-card px-3 py-2 text-sm" />
        <input type="email" placeholder="Email (optional)" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} className="rounded border border-soc-border bg-soc-card px-3 py-2 text-sm" />
        <input required minLength={12} type="password" placeholder="Temporary password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} className="rounded border border-soc-border bg-soc-card px-3 py-2 text-sm" />
        <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })} className="rounded border border-soc-border bg-soc-card px-3 py-2 text-sm"><option>ANALYST</option><option>VIEWER</option></select>
        <button className="flex items-center justify-center gap-2 rounded bg-soc-neon px-3 py-2 text-sm font-semibold text-soc-bg" type="submit"><UserPlus size={15} /> Create user</button>
      </form>
      {message && <p className="mt-3 text-sm text-soc-neon" role="status">{message}</p>}
      {error && <p className="mt-3 text-sm text-red-300" role="alert">{error}</p>}
      <div className="mt-4 overflow-x-auto"><table className="w-full text-left text-sm"><thead className="text-xs uppercase text-slate-500"><tr><th className="p-2">User</th><th className="p-2">Role</th><th className="p-2">Status</th><th className="p-2">Actions</th></tr></thead><tbody>{users.map((user) => <tr className="border-t border-soc-border" key={user.id}><td className="p-2">{user.username}<span className="block text-xs text-slate-500">{user.email || "No email"}</span></td><td className="p-2"><select value={user.role} onChange={(e) => changeRole(user, e.target.value)} className="rounded border border-soc-border bg-soc-bg px-2 py-1 text-xs"><option>ADMIN</option><option>ANALYST</option><option>VIEWER</option></select></td><td className={`p-2 text-xs ${user.is_active ? "text-soc-neon" : "text-red-300"}`}>{user.is_active ? "Active" : "Disabled"}</td><td className="flex flex-wrap gap-2 p-2"><button type="button" onClick={() => toggle(user)} className="rounded border border-soc-border px-2 py-1 text-xs">{user.is_active ? "Disable" : "Enable"}</button><button type="button" onClick={() => reset(user)} className="rounded border border-soc-border px-2 py-1 text-xs">Reset password</button></td></tr>)}</tbody></table></div>
    </section>
  );
}
