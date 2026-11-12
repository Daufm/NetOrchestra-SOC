import { Activity, Wifi, WifiOff } from "lucide-react";
import { useLiveEvents } from "../hooks/useLiveEvents.js";

const eventLabels = {
  job_started: "JOB STARTED",
  job_progress: "CAPTURE PROGRESS",
  packet_detected: "PACKET DETECTED",
  threat_detected: "THREAT DETECTED",
  capture_stopped: "CAPTURE STOPPED",
  job_completed: "JOB COMPLETED",
  job_failed: "JOB FAILED",
  cleanup_completed: "CLEANUP COMPLETE",
};

const eventColors = {
  threat_detected: "text-red-300",
  job_failed: "text-red-300",
  job_completed: "text-soc-neon",
  capture_stopped: "text-yellow-300",
};

function formatEvent(event) {
  const label = eventLabels[event.type] || event.type.replaceAll("_", " ").toUpperCase();
  const backend = event.data?.backend ? `[${event.data.backend}] ` : "";
  const detail = event.data?.phase || event.data?.reason || event.data?.message || "";
  const text = detail ? `${label} · ${backend}${detail}` : (backend ? `${label} · ${backend}` : label);
  return text;
}

export default function LiveActivity({ onResync, onEvent }) {
  const { events, status } = useLiveEvents(onResync, onEvent);
  const connected = status === "online";
  return (
    <section className="mt-4 rounded-lg border border-soc-border bg-soc-card p-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2"><Activity size={18} className="text-soc-neon" /><h2 className="font-semibold">Live activity</h2></div>
        <span className={`flex items-center gap-2 text-xs uppercase ${connected ? "text-soc-neon" : "text-slate-500"}`}>
          {connected ? <Wifi size={14} /> : <WifiOff size={14} />} {status}
        </span>
      </div>
      <div className="mt-3 max-h-52 overflow-y-auto font-mono text-xs">
        {events.length === 0 && <p className="text-slate-500">Waiting for live events...</p>}
        {events.map((event) => (
          <div className="flex gap-3 border-b border-soc-border/50 py-2" key={event.id}>
            <time className="text-slate-600">{new Date(event.ts).toLocaleTimeString()}</time>
            <span className={eventColors[event.type] || "text-slate-300"}>{formatEvent(event)}</span>
            <span className="ml-auto text-slate-600">{event.job_id.slice(0, 8)}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
