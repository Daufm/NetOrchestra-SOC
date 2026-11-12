import { useEffect, useMemo, useState } from "react";
import { Download, Search, ShieldAlert } from "lucide-react";
import { apiFetch, getAccessToken } from "../api/client.js";

const severities = ["critical", "high", "medium", "low"];
const statuses = ["open", "triaged", "false_positive", "confirmed"];
const severityStyles = {
  critical: "border-red-500/60 bg-red-950/30 text-red-300",
  high: "border-orange-500/60 bg-orange-950/30 text-orange-300",
  medium: "border-yellow-500/60 bg-yellow-950/30 text-yellow-300",
  low: "border-sky-500/60 bg-sky-950/30 text-sky-300",
};

function queryString(filters) {
  return new URLSearchParams(Object.entries(filters).filter(([, value]) => value !== "")).toString();
}

export default function ThreatGrid({ profiles }) {
  const [filters, setFilters] = useState({ q: "", severity: "", status: "", profile: "", sort: "detected_at", dir: "desc" });
  const [page, setPage] = useState({ items: [], total: 0, limit: 25, offset: 0 });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const pages = useMemo(() => Math.max(1, Math.ceil(page.total / page.limit)), [page]);
  const currentPage = Math.floor(page.offset / page.limit) + 1;

  useEffect(() => {
    let active = true;
    setLoading(true);
    apiFetch(`/api/findings?${queryString({ ...filters, limit: page.limit, offset: page.offset })}`)
      .then((body) => {
        if (active) {
          setPage((previous) => ({ ...previous, ...body }));
          setError("");
        }
      })
      .catch((requestError) => active && setError(requestError.message))
      .finally(() => active && setLoading(false));
    return () => { active = false; };
  }, [filters, page.limit, page.offset]);

  function updateFilter(event) {
    setFilters({ ...filters, [event.target.name]: event.target.value });
    setPage((previous) => ({ ...previous, offset: 0 }));
  }

  async function triage(id, status) {
    try {
      await apiFetch(`/api/findings/${id}`, { method: "PATCH", body: JSON.stringify({ status }) });
      setPage((previous) => ({
        ...previous,
        items: previous.items.map((item) => item.id === id ? { ...item, status } : item),
      }));
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  async function exportFindings(format) {
    try {
      const response = await fetch(`/api/findings/export?${queryString({ ...filters, format })}`, {
        credentials: "include",
        headers: getAccessToken() ? { Authorization: `Bearer ${getAccessToken()}` } : {},
      });
      if (!response.ok) throw new Error(`Export failed (${response.status})`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `findings.${format}`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  return (
    <section className="mt-4 rounded-lg border border-soc-border bg-soc-card p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2"><ShieldAlert className="text-soc-neon" size={18} /><h2 className="font-semibold">Threat findings</h2></div>
        <div className="flex gap-2">
          <button type="button" onClick={() => exportFindings("csv")} className="flex items-center gap-2 rounded border border-soc-border px-3 py-2 text-xs hover:border-soc-neon"><Download size={14} /> CSV</button>
          <button type="button" onClick={() => exportFindings("json")} className="flex items-center gap-2 rounded border border-soc-border px-3 py-2 text-xs hover:border-soc-neon"><Download size={14} /> JSON</button>
        </div>
      </div>
      <div className="mt-4 grid gap-2 md:grid-cols-5">
        <label className="relative md:col-span-2"><span className="sr-only">Search findings</span><Search className="absolute left-3 top-2.5 text-slate-500" size={16} /><input name="q" value={filters.q} onChange={updateFilter} placeholder="Search title, rule, IP..." className="w-full rounded border border-soc-border bg-soc-bg py-2 pl-9 pr-3 text-sm" /></label>
        <select name="severity" value={filters.severity} onChange={updateFilter} className="rounded border border-soc-border bg-soc-bg px-3 py-2 text-sm"><option value="">All severity</option>{severities.map((value) => <option key={value}>{value}</option>)}</select>
        <select name="status" value={filters.status} onChange={updateFilter} className="rounded border border-soc-border bg-soc-bg px-3 py-2 text-sm"><option value="">All status</option>{statuses.map((value) => <option key={value}>{value}</option>)}</select>
        <select name="profile" value={filters.profile} onChange={updateFilter} className="rounded border border-soc-border bg-soc-bg px-3 py-2 text-sm"><option value="">All profiles</option>{profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.label}</option>)}</select>
      </div>
      {error && <p className="mt-3 text-sm text-red-300" role="alert">{error}</p>}
      <div className="mt-4 overflow-x-auto">
        <table className="w-full min-w-[780px] text-left text-sm">
          <thead className="border-b border-soc-border text-xs uppercase text-slate-500"><tr><th className="px-3 py-3">Severity</th><th className="px-3 py-3">Finding</th><th className="px-3 py-3">Source / destination</th><th className="px-3 py-3">Confidence</th><th className="px-3 py-3">Status</th><th className="px-3 py-3">Action</th></tr></thead>
          <tbody>
            {loading && <tr><td className="px-3 py-6 text-slate-500" colSpan="6">Loading findings...</td></tr>}
            {!loading && page.items.length === 0 && <tr><td className="px-3 py-6 text-slate-500" colSpan="6">No findings match the current filters.</td></tr>}
            {!loading && page.items.map((finding) => (
              <tr className="border-b border-soc-border/60 align-top" key={finding.id}>
                <td className="px-3 py-3"><span className={`rounded border px-2 py-1 text-xs uppercase ${severityStyles[finding.severity] || severityStyles.low}`}>{finding.severity}</span></td>
                <td className="max-w-sm px-3 py-3"><p className="font-medium text-slate-100">{finding.title}</p><p className="mt-1 text-xs text-slate-500">{finding.rule_id} · {finding.profile_id}</p><p className="mt-2 text-xs text-slate-400">{finding.explanation}</p></td>
                <td className="px-3 py-3 font-mono text-xs text-slate-400">{finding.src_ip || "—"}:{finding.src_port || "—"}<br />→ {finding.dst_ip || "—"}:{finding.dst_port || "—"}</td>
                <td className="px-3 py-3 font-mono text-soc-neon">{(finding.confidence * 100).toFixed(0)}%</td>
                <td className="px-3 py-3 text-xs text-slate-300">{finding.status}</td>
                <td className="px-3 py-3"><select aria-label={`Update status for ${finding.title}`} value={finding.status} onChange={(event) => triage(finding.id, event.target.value)} className="rounded border border-soc-border bg-soc-bg px-2 py-1 text-xs"><option value={finding.status}>{finding.status}</option>{statuses.filter((status) => status !== finding.status).map((status) => <option key={status}>{status}</option>)}</select></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-4 flex items-center justify-between text-sm text-slate-400">
        <span>Page {currentPage} of {pages} · {page.total.toLocaleString()} findings</span>
        <div className="flex gap-2"><button type="button" disabled={page.offset === 0} onClick={() => setPage({ ...page, offset: Math.max(0, page.offset - page.limit) })} className="rounded border border-soc-border px-3 py-1 disabled:opacity-40">Previous</button><button type="button" disabled={currentPage >= pages} onClick={() => setPage({ ...page, offset: page.offset + page.limit })} className="rounded border border-soc-border px-3 py-1 disabled:opacity-40">Next</button></div>
      </div>
    </section>
  );
}
