import { useCallback, useEffect, useState } from "react";
import { CheckCircle, Download, Eye, Layers, Search } from "lucide-react";
import { apiDownload, apiFetch } from "../api/client.js";
import { formatBytes } from "../utils/format.js";

const packetFilters = [
  ["unexpected-protocols", "Unexpected protocols", "Telnet, FTP, IRC, and Tor"],
  ["non-standard-ports", "Non-standard ports", "HTTP/SSH/FTP on unusual ports"],
  ["top-talkers", "Top talkers / high transfer", "Large packets sent to external IPs"],
  ["dns-tunneling", "DNS tunneling", "Long names and TXT/NULL queries"],
  ["dga", "DGA / NXDOMAIN", "Failed DNS responses"],
  ["c2-beaconing", "C2 beaconing", "External repeated-connection candidates"],
  ["suspicious-user-agents", "Suspicious HTTP user-agents", "curl, Python, PowerShell, or empty"],
  ["anomalous-tls", "Anomalous TLS certificates", "Self-signed, expired, or default issuers"],
  ["network-scans", "Internal scans", "SYN/ARP scan candidates"],
  ["lateral-movement", "Lateral movement", "SMB, RDP, or WinRM internally"],
  ["malicious-downloads", "Malicious file downloads", "Executables, scripts, and archives"],
  ["web-attacks", "Web application attacks", "Injection and traversal indicators"],
  ["cleartext-credentials", "Cleartext credentials", "Credential indicators in plaintext protocols"],
  ["asymmetric-flows", "Asymmetric data flows", "Large internal-to-external transfers"],
];

function hexDump(value) {
  if (!value) return "";
  const raw = Array.isArray(value) ? value : String(value).match(/.{1,2}/g) || [];
  return raw.map((byte, index) => `${index.toString(16).padStart(4, "0")}  ${byte}`).join("\n");
}

export default function PacketInspector({ initialJobId = "" }) {
  const [jobs, setJobs] = useState([]);
  const [jobId, setJobId] = useState("");
  const [job, setJob] = useState(null);
  const [captureBackend, setCaptureBackend] = useState("");
  const [packets, setPackets] = useState({ items: [], total: 0 });
  const [protocols, setProtocols] = useState(null);
  const [packet, setPacket] = useState(null);
  const [frame, setFrame] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("");
  const [error, setError] = useState("");
  const [evidence, setEvidence] = useState([]);
  const [verification, setVerification] = useState({});
  const [autoResults, setAutoResults] = useState([]);
  const [autoRunning, setAutoRunning] = useState(false);

  useEffect(() => {
    if (initialJobId) setJobId(initialJobId);
  }, [initialJobId]);

  useEffect(() => {
    apiFetch("/api/jobs?limit=50&offset=0").then((body) => setJobs(body.items || [])).catch((requestError) => setError(requestError.message));
  }, []);

  useEffect(() => {
    if (!jobId) return undefined;
    let active = true;
    Promise.all([
      apiFetch(`/api/jobs/${jobId}`),
      apiFetch(`/api/jobs/${jobId}/packets?limit=50&offset=0`),
      apiFetch(`/api/jobs/${jobId}/protocols`),
      apiFetch(`/api/jobs/${jobId}/evidence`),
    ]).then(([jobBody, packetBody, protocolBody, evidenceBody]) => {
      if (!active) return;
      setJob(jobBody.job);
      setCaptureBackend(jobBody.capture_backend || "");
      setPackets(packetBody);
      setProtocols(protocolBody);
      setEvidence((evidenceBody.items || []).map((item) => item.artifact));
      setVerification(Object.fromEntries((evidenceBody.items || []).map((item) => [
        item.artifact.evidence_id,
        item.last_verification
          ? { ok: item.last_verification.matches_original, at: item.last_verification.at }
          : null,
      ])));
      setPacket(null);
      setAutoResults([]);
    }).catch((requestError) => active && setError(requestError.message));
    return () => { active = false; };
  }, [jobId]);

  const runAllFilters = useCallback(async (selectedJobId = jobId) => {
    if (!selectedJobId) return;
    setAutoRunning(true);
    const results = await Promise.all(packetFilters.map(async ([value, label, description]) => {
      try {
        const body = await apiFetch(`/api/jobs/${selectedJobId}/packets?limit=1&offset=0&filter=${value}`);
        return { value, label, description, total: body.total, status: "complete" };
      } catch (requestError) {
        return { value, label, description, total: 0, status: "error", error: requestError.message };
      }
    }));
    setAutoResults(results);
    setAutoRunning(false);
  }, [jobId]);

  useEffect(() => {
    if (!jobId || !job) return undefined;
    if (["completed", "failed", "cancelled"].includes(job.status)) {
      runAllFilters(jobId);
      return undefined;
    }
    const timer = setInterval(async () => {
      try {
        const body = await apiFetch(`/api/jobs/${jobId}`);
        setJob(body.job);
      } catch (requestError) {
        setError(requestError.message);
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [job, jobId, runAllFilters]);

  async function search(event) {
    event.preventDefault();
    if (!jobId) return;
    await loadPackets(filter, query);
  }

  async function loadPackets(selectedFilter = filter, searchQuery = query) {
    if (!jobId) {
      setError("Select a capture job before applying a packet filter.");
      return;
    }
    try {
      const params = new URLSearchParams({ limit: "50", offset: "0" });
      if (searchQuery.trim()) params.set("q", searchQuery.trim());
      if (selectedFilter) params.set("filter", selectedFilter);
      const body = await apiFetch(`/api/jobs/${jobId}/packets?${params}`);
      setPackets(body);
      // Synchronize autoResults with the fresh total so button count and packet list never disagree
      if (selectedFilter && !searchQuery.trim()) {
        setAutoResults((previous) =>
          previous.map((item) =>
            item.value === selectedFilter ? { ...item, total: body.total, status: "complete" } : item
          )
        );
      }
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  async function inspect(frameNumber) {
    try {
      setPacket(await apiFetch(`/api/jobs/${jobId}/packets/${frameNumber}`));
      setFrame(String(frameNumber));
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  async function verify(evidenceId) {
    try {
      const result = await apiFetch(`/api/jobs/${jobId}/evidence/${evidenceId}/verify`, { method: "POST" });
      setVerification((previous) => ({
        ...previous,
        [evidenceId]: { ok: result.verified, at: new Date().toISOString() },
      }));
      setError(result.verified ? "" : "Evidence integrity verification failed. The stored file hash does not match the original.");
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  function download(item) {
    apiDownload(`/api/jobs/${jobId}/evidence/${item.evidence_id}/download`)
      .then(async (response) => {
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = item.original_filename || "capture.pcap";
        link.click();
        URL.revokeObjectURL(url);
      })
      .catch((requestError) => setError(requestError.message));
  }

  return (
    <section className="mt-4 rounded-lg border border-soc-border bg-soc-card p-5">
      <div className="flex items-center gap-2"><Eye size={18} className="text-soc-neon" /><h2 className="font-semibold">Packet investigation</h2></div>
      <div className="mt-4 rounded border border-soc-neon/30 bg-soc-deep/20 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="font-semibold text-soc-neon">Predefined packet filters</h3>
            <p className="mt-1 text-xs text-slate-400">All 14 methods run automatically after a capture is selected.</p>
          </div>
          <span className="font-mono text-xs text-slate-500">
            {autoRunning ? "RUNNING ALL METHODS..." : autoResults.length === packetFilters.length ? "AUTO ANALYSIS COMPLETE" : `${packetFilters.length} ANALYSIS METHODS`}
          </span>
        </div>
        <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {packetFilters.map(([value, label, description]) => {
            const result = autoResults.find((item) => item.value === value);
            return (
            <button
              type="button"
              key={value}
              disabled={!jobId || autoRunning}
              onClick={() => { setFilter(value); loadPackets(value, query); }}
              className={`rounded border px-3 py-2 text-left text-xs transition ${filter === value ? "border-soc-neon bg-soc-neon/10 text-soc-neon" : "border-soc-border text-slate-300 hover:border-soc-neon"} disabled:cursor-not-allowed disabled:opacity-40`}
            >
              <span className="block font-semibold">{label}</span>
              <span className="mt-1 block text-slate-500">{description}</span>
              <span className={`mt-2 block font-mono ${result?.status === "error" ? "text-red-300" : "text-soc-neon"}`}>
                {autoRunning && !result ? "SCANNING..." : result?.status === "error" ? "ERROR" : `${result?.total ?? "—"} candidate packets`}
              </span>
            </button>
            );
          })}
        </div>
      </div>
      <label className="mt-4 block text-sm">Capture job
        <select value={jobId} onChange={(event) => setJobId(event.target.value)} className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2">
          <option value="">Select a job</option>
          {jobs.map((item) => <option key={item.id} value={item.id}>{item.id.slice(0, 8)} · {item.mode} · {item.status}</option>)}
        </select>
      </label>
      {error && <p className="mt-3 text-sm text-red-300" role="alert">{error}</p>}
      {job && (
        <>
          <div className="mt-4 grid gap-3 sm:grid-cols-5">
            {[
              ["Status", job.status],
              ["Backend", job.mode === "stream" ? (captureBackend || "tcpdump") : "upload"],
              ["Packets", job.packet_count.toLocaleString()],
              ["Bytes", formatBytes(job.bytes_captured)],
              ["Findings", job.findings_count.toLocaleString()],
            ].map(([label, value]) => (
              <div className="rounded border border-soc-border bg-soc-bg p-3" key={label}>
                <p className="text-xs uppercase text-slate-500">{label}</p>
                <p className="mt-1 font-mono text-soc-neon">{value}</p>
              </div>
            ))}
          </div>
          <div className="mt-4 grid gap-4 lg:grid-cols-[1fr_2fr]">
            <div className="rounded border border-soc-border p-4">
              <div className="flex items-center gap-2"><Layers size={16} className="text-soc-neon" /><h3 className="text-sm font-semibold">Protocols</h3></div>
              <div className="mt-3 space-y-2">{protocols?.by_protocol?.map((item) => <div className="flex justify-between text-xs" key={item.protocol}><span>{item.protocol}</span><span className="font-mono text-soc-neon">{item.packets}</span></div>)}</div>
            </div>
            <div className="rounded border border-soc-border p-4">
              <form onSubmit={search} className="space-y-2">
                <div className="flex gap-2"><div className="relative flex-1"><Search className="absolute left-3 top-2.5 text-slate-500" size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search DNS, HTTP host/URI, TLS SNI..." className="w-full rounded border border-soc-border bg-soc-bg py-2 pl-9 pr-3 text-sm" /></div><button className="rounded bg-soc-neon px-4 py-2 text-sm font-semibold text-soc-bg" type="submit">Search</button></div>
                <div className="flex gap-2">
                  <select
                    value={filter}
                    onChange={(event) => {
                      const val = event.target.value;
                      setFilter(val);
                      loadPackets(val, query);
                    }}
                    className="min-w-0 flex-1 rounded border border-soc-border bg-soc-bg px-3 py-2 text-xs"
                  >
                    <option value="">All packet traffic</option>
                    {packetFilters.map(([value, label, description]) => <option value={value} key={value}>{label} — {description}</option>)}
                  </select>
                  {filter && <button type="button" onClick={() => { setFilter(""); setQuery(""); loadPackets("", ""); }} className="rounded border border-soc-border px-3 py-2 text-xs text-slate-400 hover:border-soc-neon">Clear</button>}
                </div>
              </form>
              <div className="mt-3 max-h-80 overflow-y-auto">{packets.items.map((item) => <button type="button" className={`block w-full border-b border-soc-border/60 px-2 py-3 text-left hover:bg-soc-deep/30 ${String(item.frame_number) === frame ? "bg-soc-deep/40" : ""}`} onClick={() => inspect(item.frame_number)} key={item.frame_number}><div className="flex justify-between text-xs"><span className="font-mono text-soc-neon">#{item.frame_number}</span><span>{item.top_protocol || item.transport || "unknown"} · {item.frame_length} B</span></div><p className="mt-1 truncate text-xs text-slate-400">{item.src_ip || "—"} → {item.dst_ip || "—"} {item.dns_query || item.http_host || item.tls_sni || ""}</p></button>)}</div>
            </div>
          </div>
          {packet && <div className="mt-4 rounded border border-soc-border p-4"><h3 className="font-semibold text-soc-neon">Frame #{frame}</h3><pre className="mt-3 max-h-96 overflow-auto rounded bg-soc-bg p-3 text-xs text-slate-300">{JSON.stringify(packet, null, 2)}</pre><pre className="mt-3 max-h-64 overflow-auto rounded bg-black p-3 font-mono text-xs text-soc-neon">{hexDump(packet.layers?.frame_raw?.[0]) || "Raw bytes unavailable"}</pre></div>}
          {evidence.length > 0 && <div className="mt-4 rounded border border-soc-border p-4"><h3 className="font-semibold">Evidence</h3><div className="mt-3 space-y-2">{evidence.map((item) => {
            const result = verification[item.evidence_id];
            return <div className="flex flex-wrap items-center justify-between gap-2 text-sm" key={item.evidence_id}>
              <div><span className="font-mono text-xs text-slate-400">{item.original_filename} · {formatBytes(item.size_bytes)}</span>{result && <p className={`mt-1 text-xs ${result.ok ? "text-soc-neon" : "text-red-300"}`}>{result.ok ? `Integrity verified ${new Date(result.at).toLocaleTimeString()}` : "Integrity verification failed"}</p>}</div>
              <span className="flex gap-2"><button type="button" onClick={() => verify(item.evidence_id)} className="flex items-center gap-1 rounded border border-soc-border px-2 py-1 text-xs hover:border-soc-neon"><CheckCircle size={13} /> Verify</button><button type="button" onClick={() => download(item)} className="flex items-center gap-1 rounded border border-soc-border px-2 py-1 text-xs hover:border-soc-neon"><Download size={13} /> Download</button></span>
            </div>;
          })}</div></div>}
        </>
      )}
    </section>
  );
}
