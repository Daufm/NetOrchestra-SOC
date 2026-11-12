import { createElement } from "react";
import { Activity, AlertTriangle, Database, FileSearch, Radio } from "lucide-react";

const cards = [
  ["jobs_total", "Jobs", Activity],
  ["jobs_active", "Active", Radio],
  ["packets_total", "Packets", Database],
  ["findings_total", "Findings", AlertTriangle],
  ["evidence_total", "Evidence", FileSearch],
];

export default function MetricsRibbon({ stats, loading }) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
      {cards.map(([key, label, IconComponent]) => (
        <article className="rounded-lg border border-soc-border bg-soc-card p-4" key={key}>
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs uppercase tracking-wide">{label}</span>
            {createElement(IconComponent, { size: 16, className: "text-soc-neon", "aria-hidden": true })}
          </div>
          <p className="mt-3 font-mono text-2xl text-slate-100">
            {loading ? "..." : (stats?.[key] ?? 0).toLocaleString()}
          </p>
        </article>
      ))}
    </div>
  );
}
