import { useEffect, useRef, useState } from "react";
import { CloudUpload, Radio, Square } from "lucide-react";
import { apiFetch } from "../api/client.js";
import DetectionProfileSelector from "./DetectionProfileSelector.jsx";

const MAX_UPLOAD_BYTES = 512 * 1024 * 1024;

export default function CaptureControls({ profiles, onStarted }) {
  const fileInput = useRef(null);
  const [profile, setProfile] = useState(profiles[0]?.id || "");
  const [uploadState, setUploadState] = useState("");
  const [streamState, setStreamState] = useState("");
  const [streamJob, setStreamJob] = useState(null);
  const [workerKeys, setWorkerKeys] = useState([]);
  const [keysState, setKeysState] = useState("");
  const [form, setForm] = useState({
    target_host: "", ssh_port: "22", ssh_username: "", credential_ref: "", password: "",
    auth_method: "key",
    remote_interface: "eth0", duration_secs: "60", capture_filter: "",
  });
  useEffect(() => {
    if (!profile && profiles[0]) setProfile(profiles[0].id);
  }, [profile, profiles]);

  useEffect(() => {
    if (form.auth_method !== "key") return undefined;
    let active = true;
    setKeysState("Loading available keys...");
    apiFetch("/api/stream/keys")
      .then((result) => {
        if (!active) return;
        setWorkerKeys(result.keys || []);
        setKeysState(result.keys?.length ? "" : "No worker keys are mounted.");
      })
      .catch((error) => {
        if (active) {
          setWorkerKeys([]);
          setKeysState(error.message);
        }
      });
    return () => { active = false; };
  }, [form.auth_method]);

  function updateField(event) {
    setForm({ ...form, [event.target.name]: event.target.value });
  }

  function setAuthMethod(event) {
    const auth_method = event.target.value;
    setForm({ ...form, auth_method, credential_ref: auth_method === "key" ? form.credential_ref : "" });
  }

  async function upload(file) {
    if (!file) return;
    if (file.size > MAX_UPLOAD_BYTES) {
      setUploadState("File exceeds the 512 MiB upload limit.");
      return;
    }
    const body = new FormData();
    body.append("profile", profile);
    body.append("file", file);
    setUploadState("Uploading...");
    try {
      const result = await apiFetch("/api/upload", { method: "POST", body });
      setUploadState(`Uploaded ${result.size_bytes.toLocaleString()} bytes.`);
      onStarted?.(result.job_id);
    } catch (error) {
      setUploadState(error.message);
    } finally {
      if (fileInput.current) fileInput.current.value = "";
    }
  }

  async function startStream(event) {
    event.preventDefault();
    setStreamState("Starting...");
    try {
      const { auth_method: _authMethod, ...streamForm } = form;
      const result = await apiFetch("/api/stream", {
        method: "POST",
        body: JSON.stringify({
          ...streamForm,
          ssh_port: Number(form.ssh_port),
          duration_secs: Number(form.duration_secs),
          profile,
        }),
      });
      setStreamJob(result.job_id);
      setStreamState("Capture running.");
      onStarted?.(result.job_id);
    } catch (error) {
      setStreamState(error.message);
    }
  }

  async function stopStream() {
    if (!streamJob) return;
    setStreamState("Stopping...");
    try {
      await apiFetch(`/api/stream/${streamJob}/stop`, { method: "POST" });
      setStreamState("Stop requested.");
      setStreamJob(null);
    } catch (error) {
      setStreamState(error.message);
    }
  }

  return (
    <section className="grid gap-4 lg:grid-cols-2">
      <div className="rounded-lg border border-soc-border bg-soc-card p-5">
        <div className="flex items-center gap-2"><CloudUpload size={18} className="text-soc-neon" /><h2 className="font-semibold">Analyze PCAP</h2></div>
        <p className="mt-2 text-xs text-slate-500">PCAP and PCAPNG files are limited to 512 MiB.</p>
        <div className="mt-4"><DetectionProfileSelector profiles={profiles} value={profile} onChange={setProfile} /></div>
        <button type="button" onClick={() => fileInput.current?.click()} className="mt-4 w-full rounded border border-dashed border-soc-neon/50 px-4 py-8 text-sm text-slate-300 hover:bg-soc-deep/30">
          Choose capture file
        </button>
        <input ref={fileInput} className="hidden" type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap" onChange={(event) => upload(event.target.files?.[0])} />
        {uploadState && <p className="mt-3 text-sm text-slate-400" role="status">{uploadState}</p>}
      </div>

      <form onSubmit={startStream} className="rounded-lg border border-soc-border bg-soc-card p-5">
        <div className="flex items-center gap-2"><Radio size={18} className="text-soc-neon" /><h2 className="font-semibold">Remote capture</h2></div>
        <div className="mt-4"><DetectionProfileSelector profiles={profiles} value={profile} onChange={setProfile} /></div>
        <label className="mt-4 block text-sm">SSH authentication
          <select name="auth_method" value={form.auth_method} onChange={setAuthMethod} className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2">
            <option value="key">Private key reference</option>
            <option value="password">Password</option>
          </select>
        </label>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          {[
            ["target_host", "Target IP", "192.0.2.10"],
            ["ssh_username", "SSH username", "neto-capture"],
            ["remote_interface", "Interface", "eth0"],
            ["ssh_port", "SSH port", "22"],
            ["duration_secs", "Duration (seconds)", "60"],
          ].map(([name, label, placeholder]) => (
            <label className="text-sm" key={name}>{label}
              <input name={name} value={form[name]} onChange={updateField} placeholder={placeholder} className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2" required />
            </label>
          ))}
          {form.auth_method === "key" ? (
            <label className="text-sm">Credential reference
              <select name="credential_ref" value={form.credential_ref} onChange={updateField} className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2" required>
                <option value="">Choose a mounted worker key</option>
                {workerKeys.map((key) => <option key={key} value={key}>{key}</option>)}
              </select>
              {keysState && <span className="mt-1 block text-xs text-slate-500">{keysState}</span>}
            </label>
          ) : (
            <label className="text-sm">SSH password
              <input name="password" type="password" value={form.password} onChange={updateField} autoComplete="off" className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2" required />
            </label>
          )}
        </div>
        <label className="mt-3 block text-sm">BPF filter
          <input name="capture_filter" value={form.capture_filter} onChange={updateField} placeholder="optional, e.g. udp port 53" className="mt-2 w-full rounded border border-soc-border bg-soc-bg px-3 py-2" />
        </label>
        <div className="mt-4 flex items-center gap-3">
          <button disabled={Boolean(streamJob) || !profile} className="rounded bg-soc-neon px-4 py-2 font-semibold text-soc-bg disabled:opacity-50" type="submit">Start</button>
          <button disabled={!streamJob} onClick={stopStream} className="flex items-center gap-2 rounded border border-red-500/60 px-4 py-2 text-red-300 disabled:opacity-50" type="button"><Square size={14} /> Stop</button>
          {streamState && <span className="text-sm text-slate-400" role="status">{streamState}</span>}
        </div>
      </form>
    </section>
  );
}
