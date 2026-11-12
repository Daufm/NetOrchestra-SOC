import { useEffect, useState } from "react";
import {
  ShieldAlert,
  FileCheck2,
  Server,
  Activity,
  Layers,
  TrendingUp,
  FileText,
  UserCheck,
  CheckCircle2,
  Clock,
  HardDrive,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { apiFetch } from "../api/client.js";
import { formatBytes } from "../utils/format.js";

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#94a3b8",
};

export default function ViewerDashboard({ stats, onOpenDiskMetrics }) {
  const [jobs, setJobs] = useState([]);
  const [findings, setFindings] = useState([]);
  const [disk, setDisk] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    async function loadData() {
      try {
        setLoading(true);
        const [jobsRes, findingsRes, diskRes] = await Promise.allSettled([
          apiFetch("/api/jobs?limit=50&offset=0"),
          apiFetch("/api/findings?limit=50&sort=detected_at&dir=desc"),
          apiFetch("/api/metrics/disk"),
        ]);
        if (active) {
          if (jobsRes.status === "fulfilled") {
            setJobs(jobsRes.value?.items || []);
          }
          if (findingsRes.status === "fulfilled") {
            setFindings(findingsRes.value?.items || []);
          }
          if (diskRes.status === "fulfilled") {
            setDisk(diskRes.value);
          }
          setError("");
        }
      } catch (err) {
        if (active) setError(err.message);
      } finally {
        if (active) setLoading(false);
      }
    }
    loadData();
    const timer = setInterval(loadData, 20000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  // Compute metrics from real jobs data
  const completedJobs = jobs.filter((j) => j.status === "completed").length;
  const totalBytes = jobs.reduce((acc, j) => acc + (j.bytes_captured || 0), 0);
  const uploadJobs = jobs.filter((j) => j.mode === "upload");
  const remoteJobs = jobs.filter((j) => j.mode === "stream");
  const monitoredHosts = new Set(
    remoteJobs.map((j) => j.target_host).filter(Boolean)
  );

  // Severity data for charts
  const sevCounts = stats?.findings_by_severity || {};
  const pieData = Object.entries(sevCounts).map(([name, value]) => ({
    name: name.toUpperCase(),
    value: Number(value),
    color: SEVERITY_COLORS[name] || "#00ff66",
  }));

  // Jobs mode distribution
  const modeData = [
    { name: "PCAP Uploads", count: uploadJobs.length },
    { name: "Remote Captures", count: remoteJobs.length },
  ];

  return (
    <div className="space-y-6">
      {/* Executive Welcome / Scope Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-soc-border bg-gradient-to-r from-soc-card via-soc-card to-soc-deep/30 p-6 shadow-lg">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-soc-neon">
            <span className="inline-block h-2 w-2 rounded-full bg-soc-neon animate-pulse" />
            Executive Oversight Dashboard
          </div>
          <h1 className="mt-1 text-2xl font-bold tracking-tight text-white">
            Forensic & Threat Intelligence Overview
          </h1>
          <p className="mt-1 text-xs text-slate-400">
            Read-only analytical posture: forensic evidence acquisitions, monitored hosts, and threat metrics.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="rounded-lg border border-soc-border bg-black/40 px-4 py-2 text-right">
            <div className="text-[10px] font-mono uppercase text-slate-500">Security Posture</div>
            <div className="font-mono text-sm font-semibold text-soc-neon">ACTIVE DEFENSE</div>
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded border border-red-500/50 bg-red-950/30 p-3 text-xs text-red-300">
          {error}
        </div>
      )}

      {/* KPI Stat Cards (5 columns) */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <div className="rounded-xl border border-soc-border bg-soc-card p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs uppercase font-medium">Analyzed Packets</span>
            <Layers className="text-soc-neon" size={18} />
          </div>
          <p className="mt-3 font-mono text-3xl font-bold text-white">
            {(stats?.packets_total ?? 0).toLocaleString()}
          </p>
          <div className="mt-2 text-[11px] text-slate-400">
            Across <span className="text-slate-200 font-mono">{formatBytes(totalBytes)}</span> evidence
          </div>
        </div>

        <div className="rounded-xl border border-soc-border bg-soc-card p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs uppercase font-medium">Threat Findings</span>
            <ShieldAlert className="text-red-400" size={18} />
          </div>
          <p className="mt-3 font-mono text-3xl font-bold text-red-400">
            {(stats?.findings_total ?? 0).toLocaleString()}
          </p>
          <div className="mt-2 text-[11px] text-slate-400">
            High/Critical: <span className="font-mono text-red-300 font-semibold">
              {(Number(sevCounts.critical || 0) + Number(sevCounts.high || 0)).toLocaleString()}
            </span>
          </div>
        </div>

        <div className="rounded-xl border border-soc-border bg-soc-card p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs uppercase font-medium">Analyzed PCAP Artifacts</span>
            <FileCheck2 className="text-soc-neon" size={18} />
          </div>
          <p className="mt-3 font-mono text-3xl font-bold text-white">
            {(stats?.evidence_total ?? 0).toLocaleString()}
          </p>
          <div className="mt-2 text-[11px] text-slate-400">
            {completedJobs} completed investigations
          </div>
        </div>

        <div className="rounded-xl border border-soc-border bg-soc-card p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs uppercase font-medium">Monitored Servers</span>
            <Server className="text-blue-400" size={18} />
          </div>
          <p className="mt-3 font-mono text-3xl font-bold text-blue-400">
            {monitoredHosts.size > 0 ? monitoredHosts.size : "Active"}
          </p>
          <div className="mt-2 text-[11px] text-slate-400">
            Authorized remote targets & hosts
          </div>
        </div>

        <div
          onClick={onOpenDiskMetrics}
          className="rounded-xl border border-soc-border bg-soc-card p-5 cursor-pointer transition hover:border-soc-neon/50 group"
          title="Click to view detailed disk and storage metrics"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs uppercase font-medium">Storage Pool</span>
            <HardDrive className="text-soc-neon group-hover:scale-110 transition" size={18} />
          </div>
          <p className="mt-3 font-mono text-3xl font-bold text-white">
            {disk ? formatBytes(disk.evidence_dir_bytes || 0) : "..."}
          </p>
          <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
            <span>{disk ? `${formatBytes(disk.available_bytes || 0)} free` : "Checking storage..."}</span>
            <span
              className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-mono uppercase font-semibold ${
                disk?.is_low_space
                  ? "bg-red-950/60 text-red-400 border border-red-500/40"
                  : "bg-soc-neon/10 text-soc-neon border border-soc-neon/30"
              }`}
            >
              {disk?.is_low_space ? "LOW" : "OK"}
            </span>
          </div>
        </div>
      </div>

      {/* Storage Health & Air-Gapped Appliance Status Banner */}
      {disk && (
        <div className="rounded-xl border border-soc-border/80 bg-black/40 p-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-soc-neon/10 p-2.5 text-soc-neon border border-soc-neon/20">
                <HardDrive size={20} />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-white text-sm">Forensic Storage & Appliance Status</span>
                  <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-300 border border-soc-border">
                    Air-Gapped LAN Safe
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Appliance disk: <span className="font-mono text-slate-200">{formatBytes(disk.used_bytes)}</span> used of <span className="font-mono text-slate-200">{formatBytes(disk.total_bytes)}</span> ({disk.used_percent}% utilization) &bull; <span className="font-mono text-soc-neon">{disk.evidence_file_count}</span> sealed evidence PCAPs stored.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <div className="hidden sm:block w-40">
                <div className="flex justify-between text-[10px] font-mono text-slate-400 mb-1">
                  <span>Disk usage</span>
                  <span className={disk.is_low_space ? "text-red-400 font-bold" : "text-soc-neon"}>{disk.used_percent}%</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      disk.is_low_space ? "bg-red-500" : disk.used_percent > 75 ? "bg-yellow-400" : "bg-soc-neon"
                    }`}
                    style={{ width: `${Math.min(100, disk.used_percent)}%` }}
                  />
                </div>
              </div>

              {onOpenDiskMetrics && (
                <button
                  type="button"
                  onClick={onOpenDiskMetrics}
                  className="rounded border border-soc-border px-3 py-1.5 font-mono text-xs text-slate-300 transition hover:border-soc-neon hover:text-soc-neon flex items-center gap-1.5"
                >
                  Storage details &rarr;
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Visual Analytics Row: Threat Severity Pie + Capture Acquisition Bar */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Severity Distribution */}
        <div className="rounded-xl border border-soc-border bg-soc-card p-6">
          <div className="flex items-center justify-between border-b border-soc-border/60 pb-3">
            <div className="flex items-center gap-2">
              <TrendingUp size={16} className="text-soc-neon" />
              <h2 className="text-sm font-semibold text-white">Threat Severity Distribution</h2>
            </div>
            <span className="font-mono text-[10px] uppercase text-slate-500">Telemetry</span>
          </div>
          <div className="mt-4 flex flex-col items-center sm:flex-row">
            <div className="h-48 w-full sm:w-1/2">
              {pieData.length === 0 || pieData.every((d) => d.value === 0) ? (
                <div className="flex h-full items-center justify-center text-xs text-slate-500 font-mono">
                  No threat findings recorded
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={45}
                      outerRadius={70}
                      paddingAngle={3}
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#070b11",
                        borderColor: "#162235",
                        borderRadius: "8px",
                        fontSize: "12px",
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
            <div className="mt-4 w-full space-y-2 sm:mt-0 sm:w-1/2 sm:pl-4">
              {Object.entries(SEVERITY_COLORS).map(([sev, color]) => {
                const count = sevCounts[sev] || 0;
                return (
                  <div key={sev} className="flex items-center justify-between text-xs font-mono">
                    <span className="flex items-center gap-2 uppercase text-slate-400">
                      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
                      {sev}
                    </span>
                    <span className="font-semibold text-white">{Number(count).toLocaleString()}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Capture Acquisition Breakdown */}
        <div className="rounded-xl border border-soc-border bg-soc-card p-6">
          <div className="flex items-center justify-between border-b border-soc-border/60 pb-3">
            <div className="flex items-center gap-2">
              <Activity size={16} className="text-soc-neon" />
              <h2 className="text-sm font-semibold text-white">Forensic Acquisition Channels</h2>
            </div>
            <span className="font-mono text-[10px] uppercase text-slate-500">Source Types</span>
          </div>
          <div className="mt-4 h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={modeData} layout="vertical" margin={{ top: 10, right: 30, left: 40, bottom: 5 }}>
                <XAxis type="number" stroke="#64748b" fontSize={11} />
                <YAxis dataKey="name" type="category" stroke="#94a3b8" fontSize={11} width={110} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#070b11",
                    borderColor: "#162235",
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                />
                <Bar dataKey="count" fill="#00ff66" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-2 flex justify-between text-[11px] font-mono text-slate-400">
            <span>Direct PCAP uploads: <strong className="text-white">{uploadJobs.length}</strong></span>
            <span>Remote captures: <strong className="text-white">{remoteJobs.length}</strong></span>
          </div>
        </div>
      </div>

      {/* Forensic Investigations & Analysed Files Table */}
      <div className="rounded-xl border border-soc-border bg-soc-card p-6">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-soc-border/60 pb-4">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <FileText className="text-soc-neon" size={18} />
              Recent Forensic Investigations & Analyzed Files
            </h2>
            <p className="mt-1 text-xs text-slate-400">
              Verified chain of custody: analyzed capture files, timestamps, analysts in charge, and detected indicators.
            </p>
          </div>
          <span className="font-mono text-xs text-slate-500">
            {jobs.length} INVESTIGATIONS LOGGED
          </span>
        </div>

        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-soc-border/80 bg-slate-900/60 font-mono uppercase text-slate-400">
              <tr>
                <th className="px-4 py-3">Job ID / File</th>
                <th className="px-4 py-3">Source & Target</th>
                <th className="px-4 py-3">Investigated By</th>
                <th className="px-4 py-3">Packets & Size</th>
                <th className="px-4 py-3">Threats Flagged</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border/40 font-mono text-slate-300">
              {loading && (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500">
                    Loading analyzed investigation reports...
                  </td>
                </tr>
              )}
              {!loading && jobs.length === 0 && (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500">
                    No forensic capture records found.
                  </td>
                </tr>
              )}
              {!loading &&
                jobs.slice(0, 15).map((j) => (
                  <tr key={j.id} className="hover:bg-slate-900/40 transition">
                    <td className="px-4 py-3 font-semibold text-white">
                      <div className="flex items-center gap-2">
                        <span className="text-soc-neon">{j.id.slice(0, 8)}</span>
                        {j.original_filename && (
                          <span className="truncate max-w-[150px] text-[11px] text-slate-400" title={j.original_filename}>
                            ({j.original_filename})
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {j.mode === "stream" ? (
                        <span className="text-blue-300">Remote: {j.target_host} ({j.remote_interface})</span>
                      ) : (
                        <span className="text-slate-400">Uploaded PCAP</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center gap-1 rounded bg-black/40 px-2 py-0.5 text-[11px] text-slate-200 border border-soc-border">
                        <UserCheck size={12} className="text-soc-neon" />
                        {j.created_by_username || j.created_by?.slice(0, 8) || "Analyst"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div>{(j.packet_count || 0).toLocaleString()} pkts</div>
                      <div className="text-[10px] text-slate-500">{formatBytes(j.bytes_captured || 0)}</div>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`font-semibold ${
                          (j.findings_count || 0) > 0 ? "text-red-400" : "text-slate-500"
                        }`}
                      >
                        {j.findings_count || 0} findings
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`rounded px-2 py-0.5 text-[10px] uppercase font-semibold ${
                          j.status === "completed"
                            ? "bg-soc-neon/10 text-soc-neon border border-soc-neon/30"
                            : j.status === "failed"
                            ? "bg-red-950/40 text-red-400 border border-red-500/30"
                            : "bg-yellow-950/40 text-yellow-300 border border-yellow-500/30"
                        }`}
                      >
                        {j.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-500 text-[11px]">
                      {new Date(j.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Latest Security Findings Feed */}
      <div className="rounded-xl border border-soc-border bg-soc-card p-6">
        <div className="flex items-center justify-between border-b border-soc-border/60 pb-4">
          <div className="flex items-center gap-2">
            <ShieldAlert size={18} className="text-red-400" />
            <h2 className="text-base font-bold text-white">Latest Detected Threat Findings</h2>
          </div>
          <span className="font-mono text-xs text-slate-500">
            {findings.length} RECORDED THREATS
          </span>
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {findings.slice(0, 6).map((f) => (
            <div
              key={f.id}
              className="rounded-lg border border-soc-border/80 bg-black/30 p-4 transition hover:border-soc-border hover:bg-black/50"
            >
              <div className="flex items-center justify-between">
                <span
                  className="rounded px-2 py-0.5 text-[10px] font-mono font-bold uppercase tracking-wider"
                  style={{
                    backgroundColor: `${SEVERITY_COLORS[f.severity]}20`,
                    color: SEVERITY_COLORS[f.severity],
                    border: `1px solid ${SEVERITY_COLORS[f.severity]}40`,
                  }}
                >
                  {f.severity}
                </span>
                <span className="font-mono text-[10px] text-slate-500">
                  {f.confidence}% Confidence
                </span>
              </div>
              <h3 className="mt-2 text-xs font-semibold text-white line-clamp-1">{f.title}</h3>
              <p className="mt-1 text-[11px] text-slate-400 line-clamp-2">{f.description}</p>
              <div className="mt-3 flex items-center justify-between border-t border-soc-border/40 pt-2 text-[10px] font-mono text-slate-500">
                <span>{f.src_ip || "Any"} &rarr; {f.dst_ip || "Any"}</span>
                <span>{new Date(f.detected_at).toLocaleTimeString()}</span>
              </div>
            </div>
          ))}
          {findings.length === 0 && (
            <div className="col-span-full py-8 text-center text-xs font-mono text-slate-500">
              No threat indicators flagged yet.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
