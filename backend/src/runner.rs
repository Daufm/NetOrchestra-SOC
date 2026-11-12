//! Background job execution: analysis of stored uploads and live remote-capture streaming.
//!
//! Live capture data path (all channels bounded, so backpressure reaches the worker):
//!
//! ```text
//! worker stdout (raw PCAP) -> reader task -+-> evidence file (create_new, sealed read-only after)
//!                                          +-> SHA-256 hasher
//!                                          +-> bounded mpsc -> feeder -> tshark stdin
//! tshark stdout (-T fields) -> pipeline -> PostgreSQL + detectors + WebSocket events
//! worker stderr (JSON lines) -> progress / diagnostics events
//! ```
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::{mpsc, oneshot, OwnedSemaphorePermit},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    analysis::{
        pipeline::{self, Ctx, Progress, Summary},
        tshark::{self, Input},
    },
    error::AppError,
    events::EventKind,
    evidence::{self, Actor},
    state::AppState,
};

#[derive(Clone)]
pub struct JobActor {
    pub id: Option<Uuid>,
    pub label: String,
}

impl JobActor {
    fn actor(&self) -> Actor<'_> {
        Actor {
            id: self.id,
            label: &self.label,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct StreamSpec {
    pub job_id: Uuid,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub credential_ref: String,
    pub password: Option<String>,
    pub interface: String,
    pub duration_secs: i64,
    pub filter: Option<String>,
    pub max_bytes: u64,
}

pub struct ProfileInfo {
    pub id: String,
    pub thresholds: Value,
}

fn short(msg: &str, max: usize) -> String {
    msg.chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(max)
        .collect()
}

pub fn workspace_for(state: &AppState, job_id: Uuid) -> PathBuf {
    Path::new(&state.config.workspace_dir).join(job_id.to_string())
}

async fn make_private_dir(path: &Path) -> std::io::Result<()> {
    tokio::fs::create_dir_all(path).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
    }
    Ok(())
}

async fn ensure_tshark(state: &AppState) -> Result<String, AppError> {
    let cfg = state.config.clone();
    state
        .tshark_info
        .get_or_init(
            || async move { tshark::validate(&cfg.tshark_path, &std::env::temp_dir()).await },
        )
        .await
        .clone()
        .map_err(|e| AppError::Internal(format!("tshark unavailable: {e}")))
}

async fn mark_running(state: &AppState, job_id: Uuid, mode: &str) {
    let _ = sqlx::query(
        "UPDATE capture_jobs SET status = 'running', started_at = COALESCE(started_at, now()) WHERE id = $1",
    )
    .bind(job_id)
    .execute(&state.pool)
    .await;
    state
        .events
        .publish(EventKind::JobStarted, job_id, json!({"mode": mode}));
}

async fn complete(state: &AppState, job_id: Uuid, summary: &Summary, warning: Option<String>) {
    let _ = sqlx::query(
        "UPDATE capture_jobs SET status = 'completed', progress_pct = 100, finished_at = now(), \
            packet_count = $2, error_message = $3 WHERE id = $1",
    )
    .bind(job_id)
    .bind(summary.packets as i64)
    .bind(warning.as_deref())
    .execute(&state.pool)
    .await;
    state.events.publish(
        EventKind::JobCompleted,
        job_id,
        json!({
            "packets": summary.packets, "findings": summary.findings,
            "malformed_lines": summary.malformed_lines,
            "findings_capped": summary.findings_capped, "detector_truncated": summary.detector_truncated,
            "warning": warning,
        }),
    );
}

async fn fail(state: &AppState, job_id: Uuid, message: &str) {
    let msg = short(message, 500);
    tracing::warn!(%job_id, error = %msg, "job failed");
    let _ = sqlx::query(
        "UPDATE capture_jobs SET status = 'failed', finished_at = now(), error_message = $2 WHERE id = $1",
    )
    .bind(job_id)
    .bind(&msg)
    .execute(&state.pool)
    .await;
    state
        .events
        .publish(EventKind::JobFailed, job_id, json!({"error": msg}));
}

async fn cleanup(state: &AppState, job_id: Uuid) {
    let dir = workspace_for(state, job_id);
    let removed = match tokio::fs::remove_dir_all(&dir).await {
        Ok(()) => true,
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    };
    state.jobs.unregister(job_id);
    state.events.publish(
        EventKind::CleanupCompleted,
        job_id,
        json!({"workspace_removed": removed}),
    );
}

/// Collect up to `max` bytes of a child's stderr (diagnostics only).
async fn read_stderr(mut e: tokio::process::ChildStderr, max: usize) -> String {
    let mut out = Vec::new();
    let _ = (&mut e).take(max as u64).read_to_end(&mut out).await;
    let _ = tokio::io::copy(&mut e, &mut tokio::io::sink()).await; // keep draining so the child never blocks
    String::from_utf8_lossy(&out).into_owned()
}

// --------------------------------------------------------------------------------------
// Uploads
// --------------------------------------------------------------------------------------

pub async fn run_upload_analysis(
    state: AppState,
    job_id: Uuid,
    artifact_id: Uuid,
    path: PathBuf,
    size: u64,
    actor: JobActor,
    profile: ProfileInfo,
    _permit: OwnedSemaphorePermit,
) {
    let _cancel = state.jobs.register(job_id);
    mark_running(&state, job_id, "upload").await;
    match analyze_file(&state, job_id, artifact_id, &path, size, &actor, &profile).await {
        Ok((summary, warning)) => complete(&state, job_id, &summary, warning).await,
        Err(e) => fail(&state, job_id, &e.to_string()).await,
    }
    cleanup(&state, job_id).await;
}

async fn analyze_file(
    state: &AppState,
    job_id: Uuid,
    artifact_id: Uuid,
    path: &Path,
    size: u64,
    actor: &JobActor,
    profile: &ProfileInfo,
) -> Result<(Summary, Option<String>), AppError> {
    let version = ensure_tshark(state).await?;
    let home = workspace_for(state, job_id);
    make_private_dir(&home).await.map_err(AppError::internal)?;

    // Integrity gate: never analyse evidence that no longer matches its recorded hash.
    let root = Path::new(&state.config.evidence_dir);
    let v = evidence::verify_artifact(&state.pool, root, artifact_id, &actor.actor(), None).await?;
    if !v.ok {
        return Err(AppError::Internal(
            "evidence integrity check failed; analysis aborted".into(),
        ));
    }
    evidence::record_custody(
        &state.pool,
        artifact_id,
        "analyzed",
        &actor.actor(),
        None,
        json!({"stage": "started", "profile": profile.id, "tshark": version}),
    )
    .await?;

    let mut child = tshark::fields_command(&state.config.tshark_path, &home, Input::File(path))
        .spawn()
        .map_err(|e| AppError::Internal(format!("cannot start tshark: {e}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::internal("tshark stdout"))?;
    let stderr_task = tokio::spawn(read_stderr(child.stderr.take().expect("piped"), 8192));

    let ctx = Ctx {
        pool: &state.pool,
        events: &state.events,
        job_id,
        profile_id: &profile.id,
        thresholds: &profile.thresholds,
    };
    let summary = pipeline::consume(&ctx, stdout, Progress::OfBytes(size)).await;
    let status = child.wait().await.map_err(AppError::internal)?;
    let stderr = stderr_task.await.unwrap_or_default();
    let summary = summary?;

    let mut warning = None;
    if !status.success() {
        if summary.packets == 0 {
            return Err(AppError::Internal(format!(
                "tshark could not read the capture: {}",
                short(&stderr, 300)
            )));
        }
        warning = Some(format!(
            "tshark reported a problem (capture may be truncated): {}",
            short(&stderr, 200)
        ));
    }
    evidence::record_custody(
        &state.pool,
        artifact_id,
        "analyzed",
        &actor.actor(),
        None,
        json!({"stage": "finished", "packets": summary.packets, "findings": summary.findings,
               "malformed_lines": summary.malformed_lines, "warning": warning}),
    )
    .await?;
    Ok((summary, warning))
}

// --------------------------------------------------------------------------------------
// Live remote capture
// --------------------------------------------------------------------------------------

struct CaptureOutcome {
    sha256: Vec<u8>,
    bytes: u64,
    io_error: Option<String>,
}

#[derive(Default)]
struct WorkerReport {
    last_error: Option<String>,
    host_key_fingerprint: Option<String>,
    backend: Option<String>,
    cleanup_done: bool,
}

pub async fn run_stream_job(
    state: AppState,
    spec: StreamSpec,
    actor: JobActor,
    profile: ProfileInfo,
    cancel: CancellationToken,
    _permit: OwnedSemaphorePermit,
) {
    let job_id = spec.job_id;
    mark_running(&state, job_id, "stream").await;
    if let Err(e) = stream_inner(&state, &spec, &actor, &profile, cancel).await {
        fail(&state, job_id, &e).await;
    }
    cleanup(&state, job_id).await;
}

async fn stream_inner(
    state: &AppState,
    spec: &StreamSpec,
    actor: &JobActor,
    profile: &ProfileInfo,
    cancel: CancellationToken,
) -> Result<(), String> {
    let job_id = spec.job_id;
    let cfg = &state.config;
    let worker_bin = cfg
        .worker_bin
        .clone()
        .ok_or("remote capture is not configured (NETO_WORKER_BIN)")?;
    ensure_tshark(state).await.map_err(|e| e.to_string())?;

    // Check disk storage before starting capture to prevent disk exhaustion
    if let Ok(disk) = crate::evidence::get_disk_metrics(Path::new(&cfg.evidence_dir)) {
        if disk.is_low_space {
            return Err(format!(
                "insufficient disk space on evidence volume: {:.1}% used, only {} available (minimum 10% or 1 GiB free required)",
                disk.used_percent,
                crate::evidence::format_bytes(disk.available_bytes)
            ));
        }
    }

    let home = workspace_for(state, job_id);
    make_private_dir(&home).await.map_err(|e| e.to_string())?;
    let evidence_dir = Path::new(&cfg.evidence_dir).join(job_id.to_string());
    make_private_dir(&evidence_dir)
        .await
        .map_err(|e| e.to_string())?;
    let evidence_path = evidence_dir.join("original.pcap");
    // create_new: an existing file is never overwritten.
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&evidence_path)
        .await
        .map_err(|e| format!("cannot create evidence file: {e}"))?;

    let session_id: Uuid = sqlx::query_scalar(
        "INSERT INTO worker_sessions (job_id, status, remote_host) VALUES ($1, 'connecting', $2::text::inet) RETURNING id",
    )
    .bind(job_id)
    .bind(&spec.host)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| e.to_string())?;

    // ---- worker process (spec on stdin; secrets are only *referenced*, never passed)
    let mut cmd = Command::new(&worker_bin);
    cmd.env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for key in ["PATH", "NETO_WORKER_KEYS_DIR", "NETO_WORKER_KNOWN_HOSTS"] {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }
    let mut worker = cmd
        .spawn()
        .map_err(|e| format!("cannot start worker: {e}"))?;
    let mut w_stdin = worker.stdin.take().ok_or("worker stdin")?;
    let mut w_stdout = worker.stdout.take().ok_or("worker stdout")?;
    let w_stderr = worker.stderr.take().ok_or("worker stderr")?;
    let spec_line = serde_json::to_string(spec).map_err(|e| e.to_string())? + "\n";
    w_stdin
        .write_all(spec_line.as_bytes())
        .await
        .map_err(|e| format!("worker stdin: {e}"))?;
    w_stdin.flush().await.map_err(|e| e.to_string())?;

    // ---- tshark fed from the capture stream
    let mut tshark_child = tshark::fields_command(&cfg.tshark_path, &home, Input::Stdin)
        .spawn()
        .map_err(|e| format!("cannot start tshark: {e}"))?;
    let mut t_stdin = tshark_child.stdin.take().ok_or("tshark stdin")?;
    let t_stdout = tshark_child.stdout.take().ok_or("tshark stdout")?;
    let t_stderr = tokio::spawn(read_stderr(
        tshark_child.stderr.take().expect("piped"),
        8192,
    ));

    // ---- tasks
    let limit_token = CancellationToken::new();
    let (chunk_tx, mut chunk_rx) = mpsc::channel::<Vec<u8>>(32);

    let max_bytes = spec.max_bytes;
    let limit_for_reader = limit_token.clone();
    let reader = tokio::spawn(async move {
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut io_error = None;
        let mut buf = vec![0u8; 64 * 1024];
        let mut analysis_alive = true;
        loop {
            let n = match w_stdout.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    io_error = Some(e.to_string());
                    break;
                }
            };
            if let Err(e) = file.write_all(&buf[..n]).await {
                io_error = Some(format!("evidence write failed: {e}"));
                limit_for_reader.cancel();
                break;
            }
            hasher.update(&buf[..n]);
            total += n as u64;
            if analysis_alive && chunk_tx.send(buf[..n].to_vec()).await.is_err() {
                analysis_alive = false; // keep recording evidence even if analysis died
            }
            if total >= max_bytes {
                limit_for_reader.cancel();
            }
        }
        let _ = file.flush().await;
        let _ = file.sync_all().await;
        drop(chunk_tx);
        CaptureOutcome {
            sha256: hasher.finalize().to_vec(),
            bytes: total,
            io_error,
        }
    });

    let feeder = tokio::spawn(async move {
        while let Some(chunk) = chunk_rx.recv().await {
            if t_stdin.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = t_stdin.shutdown().await; // EOF lets tshark finish
    });

    let (exit_tx, mut exit_rx) = oneshot::channel::<()>();
    let (kill_tx, kill_rx) = oneshot::channel::<()>();
    let waiter = tokio::spawn(async move {
        let status = tokio::select! {
            s = worker.wait() => s,
            _ = kill_rx => { let _ = worker.start_kill(); worker.wait().await }
        };
        let _ = exit_tx.send(());
        status
    });

    let deadline = Duration::from_secs(spec.duration_secs.max(1) as u64 + 45);
    let limit_for_control = limit_token.clone();
    let evidence_dir_for_check = Path::new(&cfg.evidence_dir).to_path_buf();
    let control = tokio::spawn(async move {
        let mut disk_check_interval = tokio::time::interval(Duration::from_secs(5));
        let reason = loop {
            tokio::select! {
                _ = &mut exit_rx => return "completed",
                _ = cancel.cancelled() => break "user",
                _ = limit_for_control.cancelled() => break "size_limit",
                _ = tokio::time::sleep(deadline) => break "timeout",
                _ = disk_check_interval.tick() => {
                    if let Ok(m) = crate::evidence::get_disk_metrics(&evidence_dir_for_check) {
                        if m.is_low_space {
                            tracing::warn!("Capture stopped: storage volume critically low on space");
                            limit_for_control.cancel();
                            break "disk_full";
                        }
                    }
                }
            }
        };
        let _ = w_stdin.write_all(b"{\"cmd\":\"stop\"}\n").await;
        let _ = w_stdin.flush().await;
        tokio::select! {
            _ = &mut exit_rx => {}
            _ = tokio::time::sleep(Duration::from_secs(10)) => { let _ = kill_tx.send(()); }
        }
        reason
    });

    let events = state.events.clone();
    let pool = state.pool.clone();
    let duration = spec.duration_secs.max(1) as f64;
    let started = std::time::Instant::now();
    let report_task = tokio::spawn(async move {
        let mut rep = WorkerReport::default();
        let mut lines = BufReader::new(w_stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(v) = serde_json::from_str::<Value>(&line) else {
                tracing::debug!(%job_id, worker = %short(&line, 200), "worker diagnostics");
                continue;
            };
            match v.get("event").and_then(Value::as_str) {
                Some("progress") => {
                    let pct =
                        ((started.elapsed().as_secs_f64() / duration) * 100.0).min(99.0) as i16;
                    let bytes = v.get("bytes").and_then(Value::as_i64).unwrap_or(0);
                    let _ = sqlx::query("UPDATE capture_jobs SET bytes_captured = $2, progress_pct = $3 WHERE id = $1")
                        .bind(job_id).bind(bytes).bind(pct).execute(&pool).await;
                    events.publish(
                        EventKind::JobProgress,
                        job_id,
                        json!({"phase": "capture", "bytes": bytes, "progress_pct": pct}),
                    );
                }
                Some("started") => {
                    rep.host_key_fingerprint = v
                        .get("host_key")
                        .and_then(Value::as_str)
                        .map(|s| short(s, 100));
                    rep.backend = v
                        .get("backend")
                        .and_then(Value::as_str)
                        .map(|s| s.to_string());
                    events.publish(
                        EventKind::JobProgress,
                        job_id,
                        json!({
                            "phase": "capturing",
                            "host_key": rep.host_key_fingerprint,
                            "backend": rep.backend.as_deref().unwrap_or("tcpdump")
                        }),
                    );
                }
                Some("error") => {
                    rep.last_error = v
                        .get("message")
                        .and_then(Value::as_str)
                        .map(|s| short(s, 300))
                }
                Some("cleanup") => rep.cleanup_done = true,
                _ => {}
            }
        }
        rep
    });

    let ctx = Ctx {
        pool: &state.pool,
        events: &state.events,
        job_id,
        profile_id: &profile.id,
        thresholds: &profile.thresholds,
    };
    let analysis = pipeline::consume(&ctx, t_stdout, Progress::External).await;

    // ---- join everything
    let outcome = reader.await.map_err(|e| e.to_string())?;
    let _ = feeder.await;
    let _ = tshark_child.wait().await;
    let tshark_err = t_stderr.await.unwrap_or_default();
    let exit = waiter.await.map_err(|e| e.to_string())?;
    let reason = control.await.unwrap_or("completed");
    let report = report_task.await.unwrap_or_default();

    let worker_ok = matches!(&exit, Ok(s) if s.success());
    let _ = sqlx::query(
        "UPDATE worker_sessions SET status = $2::text::worker_status, ended_at = now(), cleanup_done = $3, \
            host_key_fingerprint = $4, error_message = $5 WHERE id = $1",
    )
    .bind(session_id)
    .bind(if worker_ok || (reason != "completed" && outcome.bytes > 0) { "closed" } else { "failed" })
    .bind(report.cleanup_done)
    .bind(&report.host_key_fingerprint)
    .bind(report.last_error.as_deref())
    .execute(&state.pool)
    .await;

    if let Some(backend) = &report.backend {
        let _ = sqlx::query("UPDATE worker_sessions SET error_message = COALESCE(error_message, $2) WHERE id = $1 AND error_message IS NULL")
            .bind(session_id)
            .bind(format!("backend: {backend}"))
            .execute(&state.pool)
            .await;
    }

    state.events.publish(
        EventKind::CaptureStopped,
        job_id,
        json!({
            "reason": reason,
            "bytes": outcome.bytes,
            "worker_ok": worker_ok,
            "backend": report.backend.as_deref().unwrap_or("tcpdump")
        }),
    );

    if let Some(e) = &outcome.io_error {
        return Err(format!("capture stream error: {e}"));
    }
    if outcome.bytes == 0 {
        let _ = tokio::fs::remove_file(&evidence_path).await;
        let _ = tokio::fs::remove_dir(&evidence_dir).await;
        return Err(report
            .last_error
            .unwrap_or_else(|| "no data captured".to_string()));
    }

    // ---- seal and register the evidence (hash was computed while streaming)
    evidence::seal(&evidence_path)
        .await
        .map_err(|e| e.to_string())?;
    let mut tx = state.pool.begin().await.map_err(|e| e.to_string())?;
    let (artifact_id, ev_id): (Uuid, String) = sqlx::query_as(
        "INSERT INTO evidence_artifacts (evidence_id, job_id, kind, original_filename, storage_path, size_bytes, sha256, created_by) \
         VALUES ($1, $2, 'pcap', $3, $4, $5, $6, $7) RETURNING id, evidence_id",
    )
    .bind(evidence::new_evidence_id())
    .bind(job_id)
    .bind(format!("capture-{}-{}.pcap", spec.interface, job_id))
    .bind(evidence::relative_path(job_id, "pcap"))
    .bind(outcome.bytes as i64)
    .bind(&outcome.sha256)
    .bind(actor.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    sqlx::query("INSERT INTO evidence_hashes (artifact_id, digest, matches_original, computed_by) VALUES ($1, $2, TRUE, $3)")
        .bind(artifact_id).bind(&outcome.sha256).bind(actor.id)
        .execute(&mut *tx).await.map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    let detail = json!({"mode": "stream", "host": spec.host, "interface": spec.interface,
                        "stop_reason": reason, "evidence_id": ev_id, "sha256": evidence::hex(&outcome.sha256)});
    evidence::record_custody(
        &state.pool,
        artifact_id,
        "ingested",
        &actor.actor(),
        None,
        detail,
    )
    .await
    .map_err(|e| e.to_string())?;
    let _ = sqlx::query("UPDATE capture_jobs SET bytes_captured = $2 WHERE id = $1")
        .bind(job_id)
        .bind(outcome.bytes as i64)
        .execute(&state.pool)
        .await;

    let summary = analysis.map_err(|e| e.to_string())?;
    evidence::record_custody(
        &state.pool,
        artifact_id,
        "analyzed",
        &actor.actor(),
        None,
        json!({"stage": "finished", "packets": summary.packets, "findings": summary.findings}),
    )
    .await
    .map_err(|e| e.to_string())?;

    // A stop requested by the user (or a limit/timeout we enforced) is a normal end of capture.
    let expected_end = reason != "completed";
    if !worker_ok && !expected_end {
        return Err(report.last_error.unwrap_or_else(|| {
            format!(
                "worker exited abnormally; captured data was preserved as evidence ({})",
                short(&tshark_err, 100)
            )
        }));
    }
    let warning = (!worker_ok).then(|| format!("capture ended by {reason}"));
    complete(state, job_id, &summary, warning).await;
    Ok(())
}
