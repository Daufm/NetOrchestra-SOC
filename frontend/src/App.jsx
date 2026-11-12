import { Activity, BookOpen, HardDrive, LogOut, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "./api/client.js";
import CaptureControls from "./components/CaptureControls.jsx";
import MetricsRibbon from "./components/MetricsRibbon.jsx";
import ThreatGrid from "./components/ThreatGrid.jsx";
import PacketInspector from "./components/PacketInspector.jsx";
import LiveActivity from "./components/LiveActivity.jsx";
import { useAuth } from "./state/AuthContext.jsx";
import Login from "./pages/Login.jsx";
import Register from "./pages/Register.jsx";
import UserManagement from "./components/UserManagement.jsx";
import ChangePassword from "./pages/ChangePassword.jsx";
import DocumentationViewer from "./components/DocumentationViewer.jsx";
import ViewerDashboard from "./components/ViewerDashboard.jsx";
import DiskMetricsModal from "./components/DiskMetricsModal.jsx";

export default function App() {
  const { user, loading, logout, changePassword } = useAuth();
  const [stats, setStats] = useState(null);
  const [profiles, setProfiles] = useState([]);
  const [dataError, setDataError] = useState("");
  const [showRegister, setShowRegister] = useState(false);
  const [showUserManagement, setShowUserManagement] = useState(false);
  const [showDocs, setShowDocs] = useState(false);
  const [showDiskMetrics, setShowDiskMetrics] = useState(false);
  const [selectedJobId, setSelectedJobId] = useState("");
  const [dataVersion, setDataVersion] = useState(0);
  const handleResync = useCallback(() => window.location.reload(), []);
  const handleLiveEvent = useCallback((event) => {
    if (["job_started", "job_progress", "threat_detected", "capture_stopped", "job_completed", "job_failed"].includes(event.type)) {
      setDataVersion((version) => version + 1);
    }
  }, []);
  useEffect(() => {
    if (!user) return undefined;
    let active = true;
    async function load() {
      try {
        const [statsResponse, profilesResponse] = await Promise.all([apiFetch("/api/stats"), apiFetch("/api/profiles")]);
        if (active) {
          setStats(statsResponse);
          setProfiles(profilesResponse.items || []);
          setDataError("");
        }
      } catch (error) {
        if (active) setDataError(error.message);
      }
    }
    load();
    const timer = setInterval(load, 15000);
    return () => { active = false; clearInterval(timer); };
  }, [dataVersion, user]);
  if (loading) return <main className="min-h-screen flex items-center justify-center text-soc-neon">Loading console...</main>;
  if (!user) return showRegister
    ? <Register onBack={() => setShowRegister(false)} />
    : <Login onRegister={() => setShowRegister(true)} />;
  if (user.must_change_password) return <ChangePassword username={user.username} onSubmit={changePassword} onLogout={logout} />;

  return (
    <main className="min-h-screen">
      <header className="border-b border-soc-border bg-soc-card px-6 py-4">
        <div className="mx-auto flex max-w-7xl items-center justify-between">
          <div className="flex items-center gap-3">
            <ShieldCheck className="text-soc-neon" aria-hidden="true" />
            <span className="font-mono text-soc-neon">NETORCHESTRA // SOC</span>
          </div>
          <div className="flex items-center gap-4 text-sm">
            <button
              onClick={() => {
                setShowDiskMetrics((visible) => !visible);
                if (!showDiskMetrics) {
                  setShowDocs(false);
                  setShowUserManagement(false);
                }
              }}
              className={`flex items-center gap-1.5 rounded border px-3 py-1.5 text-xs font-mono transition ${
                showDiskMetrics
                  ? "border-soc-neon bg-soc-neon/10 text-soc-neon"
                  : "border-soc-border text-slate-400 hover:border-soc-neon hover:text-soc-neon"
              }`}
              type="button"
            >
              <HardDrive size={14} /> Storage & disk
            </button>
            <button
              onClick={() => {
                setShowDocs((visible) => !visible);
                if (!showDocs) {
                  setShowUserManagement(false);
                  setShowDiskMetrics(false);
                }
              }}
              className={`flex items-center gap-1.5 rounded border px-3 py-1.5 text-xs font-mono transition ${
                showDocs
                  ? "border-soc-neon bg-soc-neon/10 text-soc-neon"
                  : "border-soc-border text-slate-400 hover:border-soc-neon hover:text-soc-neon"
              }`}
              type="button"
            >
              <BookOpen size={14} /> Documentation
            </button>
            {user.role === "ADMIN" && (
              <button
                onClick={() => {
                  setShowUserManagement((visible) => !visible);
                  if (!showUserManagement) {
                    setShowDocs(false);
                    setShowDiskMetrics(false);
                  }
                }}
                className={`rounded border px-3 py-1.5 text-xs font-mono transition ${
                  showUserManagement
                    ? "border-soc-neon bg-soc-neon/10 text-soc-neon"
                    : "border-soc-border text-slate-400 hover:border-soc-neon hover:text-soc-neon"
                }`}
                type="button"
              >
                User management
              </button>
            )}
            <span>{user.username} <span className="text-slate-500">({user.role})</span></span>
            <button onClick={logout} className="flex items-center gap-2 text-slate-400 hover:text-soc-neon" type="button">
              <LogOut size={16} aria-hidden="true" /> Sign out
            </button>
          </div>
        </div>
      </header>
      <section className="mx-auto max-w-7xl p-6">
        {dataError && <p className="mb-4 rounded border border-red-500/50 bg-red-950/30 p-3 text-sm text-red-300" role="alert">{dataError}</p>}
        {showDiskMetrics ? (
          <DiskMetricsModal onBack={() => setShowDiskMetrics(false)} />
        ) : showDocs ? (
          <DocumentationViewer onBack={() => setShowDocs(false)} />
        ) : showUserManagement && user.role === "ADMIN" ? (
          <UserManagement />
        ) : user.role === "VIEWER" ? (
          <ViewerDashboard stats={stats} onOpenDiskMetrics={() => setShowDiskMetrics(true)} />
        ) : (
          <>
            <MetricsRibbon stats={stats} loading={!stats} />
            <div className="mt-4 rounded-lg border border-soc-border bg-soc-card p-6">
              <div className="flex items-center gap-3">
                <Activity className="text-soc-neon" aria-hidden="true" />
                <h1 className="text-xl font-semibold">Operations overview</h1>
              </div>
              <p className="mt-3 text-slate-400">Upload evidence or start an authorized remote capture.</p>
            </div>
            <div className="mt-4"><CaptureControls profiles={profiles} onStarted={setSelectedJobId} /></div>
            <ThreatGrid profiles={profiles} />
            <PacketInspector initialJobId={selectedJobId} />
            <LiveActivity onResync={handleResync} onEvent={handleLiveEvent} />
          </>
        )}
      </section>
    </main>
  );
}
