import { useEffect, useState } from "react";
import {
  HardDrive,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  FolderOpen,
  FileCheck,
  ShieldCheck,
  Database,
  ArrowLeft,
} from "lucide-react";
import { apiFetch } from "../api/client.js";
import { formatBytes } from "../utils/format.js";

export default function DiskMetricsModal({ onBack }) {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchDisk = async () => {
    try {
      setLoading(true);
      const data = await apiFetch("/api/metrics/disk");
      setMetrics(data);
      setError("");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDisk();
    const interval = setInterval(fetchDisk, 10000);
    return () => clearInterval(interval);
  }, []);

  const total = metrics?.total_bytes || 0;
  const available = metrics?.available_bytes || 0;
  const used = metrics?.used_bytes || 0;
  const usedPercent = metrics?.used_percent || 0;
  const evidenceBytes = metrics?.evidence_dir_bytes || 0;
  const fileCount = metrics?.evidence_file_count || 0;
  const isLowSpace = metrics?.is_low_space || false;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-soc-border bg-soc-card p-5">
        <div className="flex items-center gap-3">
          {onBack && (
            <button
              onClick={onBack}
              type="button"
              className="flex items-center gap-1.5 rounded border border-soc-border px-2.5 py-1 text-xs text-slate-300 transition hover:border-soc-neon hover:text-soc-neon"
            >
              <ArrowLeft size={14} /> Back
            </button>
          )}
          <HardDrive className={isLowSpace ? "text-red-400" : "text-soc-neon"} size={22} />
          <div>
            <h1 className="text-lg font-bold text-white flex items-center gap-2">
              Forensic Storage & Disk Metrics
              {isLowSpace ? (
                <span className="rounded bg-red-950/60 px-2 py-0.5 text-[10px] font-mono font-bold text-red-300 border border-red-500/40">
                  LOW SPACE ALERT (&lt;10%)
                </span>
              ) : (
                <span className="rounded bg-soc-neon/10 px-2 py-0.5 text-[10px] font-mono text-soc-neon border border-soc-neon/30">
                  HEALTHY
                </span>
              )}
            </h1>
            <p className="mt-0.5 text-xs text-slate-400">
              Live capacity and usage monitoring for the sealed evidence volume: <code className="text-slate-300 font-mono">{metrics?.evidence_dir || "/var/lib/netorchestra/evidence"}</code>
            </p>
          </div>
        </div>

        <button
          onClick={fetchDisk}
          disabled={loading}
          type="button"
          className="flex items-center gap-1.5 rounded border border-soc-border bg-black/40 px-3 py-1.5 text-xs font-mono text-slate-300 transition hover:border-soc-neon hover:text-soc-neon"
        >
          <RefreshCw size={13} className={loading ? "animate-spin text-soc-neon" : ""} /> Refresh
        </button>
      </div>

      {error && (
        <div className="rounded border border-red-500/50 bg-red-950/30 p-3 text-xs text-red-300">
          {error}
        </div>
      )}

      {/* Main Storage Bar & Breakdown */}
      <div className="rounded-xl border border-soc-border bg-soc-card p-6">
        <div className="flex items-center justify-between">
          <span className="text-xs uppercase font-mono text-slate-400">Filesystem Volume Usage</span>
          <span className="font-mono text-sm font-bold text-white">
            {usedPercent}% Used ({formatBytes(used)} / {formatBytes(total)})
          </span>
        </div>

        {/* Progress Bar */}
        <div className="mt-3 h-4 w-full overflow-hidden rounded-full bg-black/60 p-0.5 border border-soc-border">
          <div
            className={`h-full rounded-full transition-all duration-500 ${
              usedPercent > 90
                ? "bg-red-500"
                : usedPercent > 75
                ? "bg-yellow-400"
                : "bg-soc-neon shadow-neon"
            }`}
            style={{ width: `${Math.min(usedPercent, 100)}%` }}
          />
        </div>

        <div className="mt-3 flex justify-between text-xs font-mono text-slate-400">
          <span>Available Free: <strong className="text-soc-neon">{formatBytes(available)}</strong></span>
          <span>Used: <strong className="text-slate-200">{formatBytes(used)}</strong></span>
          <span>Total Pool: <strong className="text-slate-200">{formatBytes(total)}</strong></span>
        </div>
      </div>

      {/* Detail Stat Cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-soc-border bg-soc-card p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs uppercase font-medium">Captured Evidence Files</span>
            <FolderOpen className="text-soc-neon" size={18} />
          </div>
          <p className="mt-3 font-mono text-3xl font-bold text-white">
            {fileCount.toLocaleString()}
          </p>
          <div className="mt-2 text-[11px] text-slate-400">
            Total files in evidence storage
          </div>
        </div>

        <div className="rounded-xl border border-soc-border bg-soc-card p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs uppercase font-medium">Total PCAP Storage</span>
            <FileCheck className="text-blue-400" size={18} />
          </div>
          <p className="mt-3 font-mono text-3xl font-bold text-blue-400">
            {formatBytes(evidenceBytes)}
          </p>
          <div className="mt-2 text-[11px] text-slate-400">
            Sealed original PCAP/PCAPNG evidence
          </div>
        </div>

        <div className="rounded-xl border border-soc-border bg-soc-card p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs uppercase font-medium">Free Headroom</span>
            <CheckCircle2 className="text-soc-neon" size={18} />
          </div>
          <p className="mt-3 font-mono text-3xl font-bold text-soc-neon">
            {formatBytes(available)}
          </p>
          <div className="mt-2 text-[11px] text-slate-400">
            Safe for continuous acquisitions
          </div>
        </div>

        <div className="rounded-xl border border-soc-border bg-soc-card p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs uppercase font-medium">Exhaustion Safety Guard</span>
            <ShieldCheck className="text-yellow-400" size={18} />
          </div>
          <p className="mt-3 font-mono text-xl font-bold text-yellow-400">
            10% Safe Cutoff
          </p>
          <div className="mt-2 text-[11px] text-slate-400">
            Auto-aborts captures before disk fills
          </div>
        </div>
      </div>

      {/* Internal Banking / Air-Gapped Deployment Info */}
      <div className="rounded-xl border border-soc-border bg-soc-card p-6">
        <h2 className="text-sm font-semibold text-white flex items-center gap-2">
          <Database size={16} className="text-soc-neon" />
          Air-Gapped & Banking LAN Storage Architecture
        </h2>
        <div className="mt-3 space-y-2 text-xs text-slate-400 leading-relaxed">
          <p>
            • <strong>Internal Enterprise LAN:</strong> No external Cloudflare, proxy, or internet dependencies are required. NetOrchestra operates fully self-contained within internal financial networks and air-gapped security enclaves.
          </p>
          <p>
            • <strong>Automated Capture Protection:</strong> Active captures continuously monitor filesystem metrics every 5 seconds. If disk capacity falls below 10% or free space drops under 1 GiB, the streaming runner gracefully stops the remote process and seals the recorded PCAP to prevent corrupted files and database halts.
          </p>
          <p>
            • <strong>Tamper-Proof Sealing:</strong> Captured evidence files are written strictly to the mounted volume, verified with SHA-256 digests, and permanently set to mode <code>0400</code>.
          </p>
        </div>
      </div>
    </div>
  );
}
