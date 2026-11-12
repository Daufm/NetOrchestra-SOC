import { useEffect, useState } from "react";
import { BookOpen, FileText, Search, Shield, Cpu, Database, Terminal, KeyRound, ArrowLeft, RefreshCw } from "lucide-react";
import { apiFetch } from "../api/client.js";
import { MarkdownViewer } from "./MarkdownViewer.jsx";

const CATEGORY_ICONS = {
  Design: Cpu,
  Reference: Terminal,
  Detection: Shield,
  Security: Shield,
  Data: Database,
  Worker: Terminal,
  Operations: KeyRound,
};

export default function DocumentationViewer({ onBack }) {
  const [docs, setDocs] = useState([]);
  const [selectedId, setSelectedId] = useState("architecture");
  const [docDetail, setDocDetail] = useState(null);
  const [loadingList, setLoadingList] = useState(true);
  const [loadingDoc, setLoadingDoc] = useState(false);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");

  // Load catalog list
  useEffect(() => {
    let active = true;
    async function fetchList() {
      setLoadingList(true);
      try {
        const data = await apiFetch("/api/docs");
        if (active) {
          setDocs(data || []);
          if (data && data.length > 0) {
            setSelectedId((current) => current || data[0].id);
          }
        }
      } catch (err) {
        if (active) setError(`Failed to load documentation catalog: ${err.message}`);
      } finally {
        if (active) setLoadingList(false);
      }
    }
    fetchList();
    return () => {
      active = false;
    };
  }, []);

  // Load document content whenever selectedId changes
  useEffect(() => {
    if (!selectedId) return;
    let active = true;
    async function fetchDoc() {
      setLoadingDoc(true);
      setError("");
      try {
        const detail = await apiFetch(`/api/docs/${selectedId}`);
        if (active) {
          setDocDetail(detail);
        }
      } catch (err) {
        if (active) setError(`Failed to load document '${selectedId}': ${err.message}`);
      } finally {
        if (active) setLoadingDoc(false);
      }
    }
    fetchDoc();
    return () => {
      active = false;
    };
  }, [selectedId]);

  const filteredDocs = docs.filter((d) => {
    const term = search.toLowerCase();
    return (
      d.title.toLowerCase().includes(term) ||
      d.description.toLowerCase().includes(term) ||
      d.category.toLowerCase().includes(term) ||
      d.filename.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-4">
      {/* Top Banner & Navigation */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-soc-border bg-soc-card p-4">
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
          <BookOpen className="text-soc-neon" size={22} />
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white">System Documentation</h1>
            <p className="text-xs text-slate-400">
              In-depth architecture, threat detection logic, API specifications, and operational manuals.
            </p>
          </div>
        </div>

        {/* Search Bar */}
        <div className="relative w-full sm:w-64">
          <Search size={14} className="absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search documentation..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded border border-soc-border bg-black/40 py-1.5 pl-8 pr-3 text-xs text-slate-200 placeholder-slate-500 focus:border-soc-neon focus:outline-none"
          />
        </div>
      </div>

      {error && (
        <div className="rounded border border-red-500/50 bg-red-950/30 p-3 text-xs text-red-300">
          {error}
        </div>
      )}

      {/* Main 2-Column Layout */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-4">
        {/* Left Sidebar: Document List */}
        <div className="space-y-2 lg:col-span-1">
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Available Guides</div>
          <div className="space-y-1.5">
            {loadingList && (
              <div className="p-4 text-center text-xs text-slate-500 font-mono flex items-center justify-center gap-2">
                <RefreshCw size={14} className="animate-spin text-soc-neon" /> Loading catalog...
              </div>
            )}
            {!loadingList && filteredDocs.length === 0 && (
              <div className="rounded border border-soc-border/60 bg-black/20 p-4 text-center text-xs text-slate-500">
                No matching documents found
              </div>
            )}
            {filteredDocs.map((doc) => {
              const Icon = CATEGORY_ICONS[doc.category] || FileText;
              const isSelected = selectedId === doc.id;
              return (
                <button
                  key={doc.id}
                  onClick={() => setSelectedId(doc.id)}
                  type="button"
                  className={`w-full rounded-md border text-left p-3 transition ${
                    isSelected
                      ? "border-soc-neon bg-soc-neon/10 text-white shadow-neon"
                      : "border-soc-border/80 bg-soc-card/70 text-slate-300 hover:border-soc-border hover:bg-soc-card hover:text-white"
                  }`}
                >
                  <div className="flex items-center justify-between text-xs font-semibold">
                    <span className="flex items-center gap-1.5 truncate">
                      <Icon size={14} className={isSelected ? "text-soc-neon" : "text-slate-400"} />
                      {doc.title}
                    </span>
                    <span className="rounded bg-black/50 px-1.5 py-0.5 text-[9px] font-mono text-slate-400 uppercase">
                      {doc.category}
                    </span>
                  </div>
                  <p className="mt-1 text-[11px] leading-snug text-slate-400 line-clamp-2">{doc.description}</p>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right Content Area: Markdown Viewer */}
        <div className="rounded-lg border border-soc-border bg-soc-card p-6 lg:col-span-3">
          {loadingDoc ? (
            <div className="flex h-64 items-center justify-center gap-2 text-xs font-mono text-soc-neon">
              <RefreshCw size={16} className="animate-spin" /> Rendering document...
            </div>
          ) : docDetail ? (
            <div>
              <div className="mb-6 flex flex-wrap items-center justify-between border-b border-soc-border/80 pb-4">
                <div>
                  <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-wider text-slate-400">
                    <span>{docDetail.category}</span>
                    <span>/</span>
                    <span className="text-soc-neon">{docDetail.filename}</span>
                  </div>
                  <h2 className="mt-1 text-xl font-bold text-white">{docDetail.title}</h2>
                </div>
                <div className="mt-2 sm:mt-0 font-mono text-[11px] text-slate-500">
                  NetOrchestra-SOC Knowledge Base
                </div>
              </div>

              <div className="prose prose-invert max-w-none">
                <MarkdownViewer content={docDetail.content} />
              </div>
            </div>
          ) : (
            <div className="flex h-64 flex-col items-center justify-center text-slate-500">
              <FileText size={32} className="mb-2 text-slate-600" />
              <p className="text-xs font-mono">Select a document from the left navigation panel</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
