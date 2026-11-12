//! Forensics API: uploads, remote streaming, jobs, packets, evidence, findings, stats.
use std::{fs, path::Path};

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Path as UrlPath, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, QueryBuilder};
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::{
    analysis::tshark,
    auth::{
        audit::{self, AuditEvent},
        AuthUser, RequestMeta,
    },
    error::AppError,
    evidence::{self, Actor},
    runner::{self, JobActor, ProfileInfo, StreamSpec},
    state::AppState,
    validate,
};

pub fn router() -> Router<AppState> {
    Router::new()
        // The body is streamed to disk with our own byte counter, so axum's default 2 MiB limit is lifted here.
        .route("/upload", post(upload).layer(DefaultBodyLimit::disable()))
        .route("/stream", post(start_stream))
        .route("/stream/keys", get(list_worker_keys))
        .route("/stream/:job_id/stop", post(stop_stream))
        .route("/jobs", get(list_jobs))
        .route("/jobs/:job_id", get(get_job))
        .route("/jobs/:job_id/packets", get(list_packets))
        .route("/jobs/:job_id/packets/:frame", get(dissect_packet))
        .route("/jobs/:job_id/protocols", get(protocols))
        .route("/jobs/:job_id/evidence", get(job_evidence))
        .route(
            "/jobs/:job_id/evidence/:evidence_id/verify",
            post(verify_evidence),
        )
        .route(
            "/jobs/:job_id/evidence/:evidence_id/download",
            get(download_evidence),
        )
        .route("/findings", get(list_findings))
        .route("/findings/export", get(export_findings))
        .route(
            "/findings/:finding_id",
            get(get_finding).patch(triage_finding),
        )
        .route("/profiles", get(list_profiles))
        .route("/stats", get(stats))
        .route("/metrics/disk", get(get_disk_stats))
}

fn parse_uuid(s: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(s).map_err(|_| AppError::BadRequest("invalid id".into()))
}

async fn list_worker_keys(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, AppError> {
    auth.require("jobs:create")?;
    let dir = state
        .config
        .worker_keys_dir
        .as_deref()
        .ok_or(AppError::ServiceUnavailable(
            "worker key directory is not configured",
        ))?;
    let mut keys = Vec::new();
    for entry in fs::read_dir(dir)
        .map_err(|_| AppError::ServiceUnavailable("worker key directory is unavailable"))?
    {
        let entry = entry
            .map_err(|_| AppError::ServiceUnavailable("worker key directory cannot be read"))?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if name.is_empty()
            || name.starts_with('.')
            || name.contains('/')
            || name.contains('\\')
            || name.contains("..")
        {
            continue;
        }
        let metadata = entry
            .metadata()
            .map_err(|_| AppError::ServiceUnavailable("worker key metadata cannot be read"))?;
        if metadata.is_file() {
            keys.push(name.into_owned());
        }
    }
    keys.sort_unstable();
    Ok(Json(json!({ "keys": keys })))
}

fn page(limit: Option<i64>, offset: Option<i64>) -> (i64, i64) {
    (
        limit.unwrap_or(50).clamp(1, 200),
        offset.unwrap_or(0).max(0),
    )
}

fn actor_of(auth: &AuthUser) -> JobActor {
    JobActor {
        id: Some(auth.id),
        label: auth.username.clone(),
    }
}

async fn load_profile(state: &AppState, id: &str) -> Result<ProfileInfo, AppError> {
    let row: Option<(String, Value)> = sqlx::query_as(
        "SELECT id, thresholds FROM detection_profiles WHERE id = $1 AND is_enabled",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;
    row.map(|(id, thresholds)| ProfileInfo { id, thresholds })
        .ok_or_else(|| AppError::BadRequest("unknown or disabled detection profile".into()))
}

// ------------------------------------------------------------------ upload

async fn upload(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: AuthUser,
    mut mp: Multipart,
) -> Result<(StatusCode, Json<Value>), AppError> {
    auth.require("jobs:create")?;
    let permit = state.jobs.try_slot().ok_or(AppError::TooManyRequests {
        retry_after_secs: 5,
    })?;

    let mut profile: Option<ProfileInfo> = None;
    let max = state.config.max_upload_bytes;
    let job_id = Uuid::new_v4();
    let dir = Path::new(&state.config.evidence_dir).join(job_id.to_string());
    let path = dir.join("original.tmp");

    // Everything after the directory is created must clean up on failure.
    let result: Result<(String, String, u64, Vec<u8>, ProfileInfo), AppError> = async {
        while let Some(mut field) = mp
            .next_field()
            .await
            .map_err(|e| AppError::BadRequest(format!("malformed multipart body: {e}")))?
        {
            match field.name() {
                Some("profile") => {
                    let id = field
                        .text()
                        .await
                        .map_err(|_| AppError::BadRequest("bad profile field".into()))?;
                    profile = Some(load_profile(&state, id.trim()).await?);
                }
                Some("file") => {
                    let profile = profile.take().ok_or_else(|| {
                        AppError::BadRequest(
                            "send the 'profile' field before the 'file' field".into(),
                        )
                    })?;
                    let filename =
                        validate::display_filename(field.file_name().unwrap_or("capture"));
                    tokio::fs::create_dir_all(&dir)
                        .await
                        .map_err(AppError::internal)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = tokio::fs::set_permissions(
                            &dir,
                            std::fs::Permissions::from_mode(0o700),
                        )
                        .await;
                    }
                    let mut file = tokio::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .await
                        .map_err(AppError::internal)?;
                    let (mut hasher, mut total, mut head) = (Sha256::new(), 0u64, Vec::<u8>::new());
                    while let Some(chunk) = field
                        .chunk()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("upload interrupted: {e}")))?
                    {
                        total += chunk.len() as u64;
                        if total > max {
                            return Err(AppError::BadRequest(format!(
                                "file exceeds the {max} byte limit"
                            )));
                        }
                        if head.len() < 4 {
                            head.extend_from_slice(&chunk[..chunk.len().min(4 - head.len())]);
                            if head.len() >= 4 && evidence::detect_capture_kind(&head).is_none() {
                                return Err(AppError::BadRequest("not a PCAP/PCAPNG file".into()));
                            }
                        }
                        hasher.update(&chunk);
                        file.write_all(&chunk).await.map_err(AppError::internal)?;
                    }
                    file.flush().await.map_err(AppError::internal)?;
                    file.sync_all().await.map_err(AppError::internal)?;
                    if total == 0 || evidence::detect_capture_kind(&head).is_none() {
                        return Err(AppError::BadRequest("not a PCAP/PCAPNG file".into()));
                    }
                    return Ok((
                        filename,
                        evidence::detect_capture_kind(&head).unwrap().to_string(),
                        total,
                        hasher.finalize().to_vec(),
                        profile,
                    ));
                }
                _ => {}
            }
        }
        Err(AppError::BadRequest(
            "multipart body must contain 'profile' and 'file' fields".into(),
        ))
    }
    .await;

    let (filename, ext, size, digest, profile) = match result {
        Ok(v) => v,
        Err(e) => {
            let _ = tokio::fs::remove_dir_all(&dir).await;
            audit::record(
                &state.pool,
                &meta,
                AuditEvent::new("evidence.upload", "failure")
                    .actor(auth.id, &auth.username)
                    .detail(json!({"reason": e.to_string().chars().take(200).collect::<String>()})),
            )
            .await;
            return Err(e);
        }
    };

    // Final, immutable location: <evidence>/<job_id>/original.<ext>
    let final_path = dir.join(format!("original.{ext}"));
    let finalize = async {
        tokio::fs::rename(&path, &final_path).await?;
        evidence::seal(&final_path).await
    }
    .await;
    if let Err(e) = finalize {
        let _ = tokio::fs::remove_dir_all(&dir).await;
        return Err(AppError::internal(e));
    }

    let ev_id = evidence::new_evidence_id();
    let db: Result<Uuid, AppError> = async {
        let mut tx = state.pool.begin().await?;
        sqlx::query(
            "INSERT INTO capture_jobs (id, created_by, mode, status, profile_id, original_filename) \
             VALUES ($1, $2, 'upload', 'queued', $3, $4)",
        )
        .bind(job_id).bind(auth.id).bind(&profile.id).bind(&filename)
        .execute(&mut *tx).await?;
        let artifact: Uuid = sqlx::query_scalar(
            "INSERT INTO evidence_artifacts (evidence_id, job_id, kind, original_filename, storage_path, size_bytes, sha256, created_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
        )
        .bind(&ev_id).bind(job_id).bind(&ext).bind(&filename)
        .bind(evidence::relative_path(job_id, &ext)).bind(size as i64).bind(&digest).bind(auth.id)
        .fetch_one(&mut *tx).await?;
        sqlx::query("INSERT INTO evidence_hashes (artifact_id, digest, matches_original, computed_by) VALUES ($1, $2, TRUE, $3)")
            .bind(artifact).bind(&digest).bind(auth.id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(artifact)
    }
    .await;
    let artifact_id = match db {
        Ok(a) => a,
        Err(e) => {
            // Not registered: a sealed, orphaned file would be unaccounted-for evidence, so remove it.
            let _ = tokio::fs::set_permissions(
                &final_path,
                std::fs::Permissions::from(std::os::unix::fs::PermissionsExt::from_mode(0o600)),
            )
            .await;
            let _ = tokio::fs::remove_dir_all(&dir).await;
            return Err(e);
        }
    };
    evidence::record_custody(
        &state.pool, artifact_id, "ingested", &Actor { id: Some(auth.id), label: &auth.username }, Some(&meta),
        json!({"mode": "upload", "filename": filename, "size_bytes": size, "sha256": evidence::hex(&digest), "evidence_id": ev_id}),
    )
    .await?;
    audit::record(
        &state.pool,
        &meta,
        AuditEvent::new("evidence.upload", "success")
            .actor(auth.id, &auth.username)
            .resource("job", job_id),
    )
    .await;

    tokio::spawn(runner::run_upload_analysis(
        state.clone(),
        job_id,
        artifact_id,
        final_path,
        size,
        actor_of(&auth),
        profile,
        permit,
    ));
    Ok((
        StatusCode::ACCEPTED,
        Json(
            json!({"job_id": job_id, "status": "queued", "evidence_id": ev_id, "sha256": evidence::hex(&digest), "size_bytes": size}),
        ),
    ))
}

// ------------------------------------------------------------------ stream

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamReq {
    target_host: String,
    ssh_port: Option<u16>,
    ssh_username: String,
    credential_ref: Option<String>,
    password: Option<String>,
    remote_interface: String,
    duration_secs: i64,
    capture_filter: Option<String>,
    profile: String,
}

async fn start_stream(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: AuthUser,
    Json(req): Json<StreamReq>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    auth.require("jobs:create")?;
    if state.config.worker_bin.is_none() {
        return Err(AppError::ServiceUnavailable(
            "remote capture is not configured on this server",
        ));
    }
    let ip = validate::host(&req.target_host)?;
    validate::username(&req.ssh_username)?;
    let has_password = req.password.as_deref().is_some_and(|p| !p.is_empty());
    let has_key = req.credential_ref.as_deref().is_some_and(|r| !r.is_empty());
    if has_password == has_key {
        return Err(AppError::BadRequest(
            "provide exactly one of credential_ref or password".into(),
        ));
    }
    if has_key {
        validate::credential_ref(req.credential_ref.as_deref().unwrap_or_default())?;
    }
    validate::interface(&req.remote_interface)?;
    let filter = req
        .capture_filter
        .as_deref()
        .map(str::trim)
        .filter(|f| !f.is_empty());
    if let Some(f) = filter {
        validate::bpf_filter(f)?;
    }
    let port = req.ssh_port.unwrap_or(22);
    if port == 0 {
        return Err(AppError::BadRequest("ssh_port must be 1-65535".into()));
    }
    if req.duration_secs < 5 || req.duration_secs > state.config.max_capture_secs {
        return Err(AppError::BadRequest(format!(
            "duration_secs must be between 5 and {}",
            state.config.max_capture_secs
        )));
    }
    // Server-side request forgery guard: only operator-approved networks may be contacted.
    if !state.config.allowed_targets.iter().any(|c| c.contains(ip)) {
        audit::record(
            &state.pool,
            &meta,
            AuditEvent::new("capture.start", "denied")
                .actor(auth.id, &auth.username)
                .detail(
                    json!({"target": req.target_host, "reason": "not in NETO_ALLOWED_TARGETS"}),
                ),
        )
        .await;
        return Err(AppError::Forbidden(
            "target host is not in the allowed target list",
        ));
    }
    let profile = load_profile(&state, req.profile.trim()).await?;
    let permit = state.jobs.try_slot().ok_or(AppError::TooManyRequests {
        retry_after_secs: 5,
    })?;

    let job_id: Uuid = sqlx::query_scalar(
        "INSERT INTO capture_jobs (created_by, mode, status, profile_id, target_host, ssh_port, ssh_username, \
            credential_ref, remote_interface, capture_filter, duration_secs) \
         VALUES ($1, 'stream', 'queued', $2, $3::text::inet, $4, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind(auth.id).bind(&profile.id).bind(ip.to_string()).bind(port as i32).bind(&req.ssh_username)
    .bind(&req.credential_ref).bind(&req.remote_interface).bind(filter).bind(req.duration_secs as i32)
    .fetch_one(&state.pool)
    .await?;
    audit::record(&state.pool, &meta, AuditEvent::new("capture.start", "success").actor(auth.id, &auth.username).resource("job", job_id).detail(json!({"target": ip.to_string(), "interface": req.remote_interface, "duration_secs": req.duration_secs}))).await;

    let spec = StreamSpec {
        job_id,
        host: ip.to_string(),
        port,
        username: req.ssh_username,
        credential_ref: req.credential_ref.unwrap_or_default(),
        password: req.password,
        interface: req.remote_interface,
        duration_secs: req.duration_secs,
        filter: filter.map(str::to_string),
        max_bytes: state.config.max_stream_bytes,
    };
    let cancel = state.jobs.register(job_id);
    tokio::spawn(runner::run_stream_job(
        state.clone(),
        spec,
        actor_of(&auth),
        profile,
        cancel,
        permit,
    ));
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"job_id": job_id, "status": "queued"})),
    ))
}

async fn stop_stream(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: AuthUser,
    UrlPath(job_id): UrlPath<String>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    auth.require("jobs:stop")?;
    let job_id = parse_uuid(&job_id)?;
    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT created_by, mode::text, status::text FROM capture_jobs WHERE id = $1",
    )
    .bind(job_id)
    .fetch_optional(&state.pool)
    .await?;
    let (owner, mode, status) = row.ok_or(AppError::NotFound)?;
    // Analysts stop their own captures; admins may stop any.
    if owner != auth.id && !auth.has("users:manage") {
        return Err(AppError::NotFound);
    }
    if mode != "stream" {
        return Err(AppError::Conflict("only streaming jobs can be stopped"));
    }
    if !matches!(status.as_str(), "queued" | "running") || !state.jobs.stop(job_id) {
        return Err(AppError::Conflict("job is not running"));
    }
    sqlx::query("UPDATE capture_jobs SET status = 'stopping' WHERE id = $1 AND status IN ('queued','running')")
        .bind(job_id)
        .execute(&state.pool)
        .await?;
    audit::record(
        &state.pool,
        &meta,
        AuditEvent::new("capture.stop", "success")
            .actor(auth.id, &auth.username)
            .resource("job", job_id),
    )
    .await;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"job_id": job_id, "status": "stopping"})),
    ))
}

// -------------------------------------------------------------------- jobs

#[derive(sqlx::FromRow, Serialize)]
struct JobRow {
    id: Uuid,
    mode: String,
    status: String,
    profile_id: String,
    original_filename: Option<String>,
    target_host: Option<String>,
    remote_interface: Option<String>,
    duration_secs: Option<i32>,
    progress_pct: i16,
    packet_count: i64,
    bytes_captured: i64,
    error_message: Option<String>,
    findings_count: i64,
    created_by: Uuid,
    created_by_username: Option<String>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
}

const JOB_SELECT: &str = "SELECT j.id, j.mode::text AS mode, j.status::text AS status, j.profile_id, j.original_filename, \
    host(j.target_host) AS target_host, j.remote_interface, j.duration_secs, j.progress_pct, j.packet_count, \
    j.bytes_captured, j.error_message, (SELECT count(*) FROM threat_findings f WHERE f.job_id = j.id) AS findings_count, \
    j.created_by, u.username AS created_by_username, j.created_at, j.started_at, j.finished_at \
    FROM capture_jobs j LEFT JOIN users u ON u.id = j.created_by";

#[derive(Deserialize)]
struct JobsQuery {
    status: Option<String>,
    mode: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn list_jobs(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<JobsQuery>,
) -> Result<Json<Value>, AppError> {
    auth.require("jobs:read")?;
    let (limit, offset) = page(q.limit, q.offset);
    let mut count: QueryBuilder<Postgres> =
        QueryBuilder::new("SELECT count(*) FROM capture_jobs j WHERE 1=1");
    let mut list: QueryBuilder<Postgres> = QueryBuilder::new(format!("{JOB_SELECT} WHERE 1=1"));
    for qb in [&mut count, &mut list] {
        if let Some(s) = &q.status {
            qb.push(" AND j.status::text = ").push_bind(s.clone());
        }
        if let Some(m) = &q.mode {
            qb.push(" AND j.mode::text = ").push_bind(m.clone());
        }
    }
    list.push(" ORDER BY j.created_at DESC LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);
    let total: i64 = count.build_query_scalar().fetch_one(&state.pool).await?;
    let items: Vec<JobRow> = list.build_query_as().fetch_all(&state.pool).await?;
    Ok(Json(
        json!({"items": items, "total": total, "limit": limit, "offset": offset}),
    ))
}

async fn get_job(
    State(state): State<AppState>,
    auth: AuthUser,
    UrlPath(job_id): UrlPath<String>,
) -> Result<Json<Value>, AppError> {
    auth.require("jobs:read")?;
    let id = parse_uuid(&job_id)?;
    let job: JobRow = sqlx::query_as(&format!("{JOB_SELECT} WHERE j.id = $1"))
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;
    let sev: Vec<(String, i64)> = sqlx::query_as(
        "SELECT severity::text, count(*) FROM threat_findings WHERE job_id = $1 GROUP BY 1",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;

    // Check worker session for capture backend info
    let worker_backend: Option<String> = if job.mode == "stream" {
        let msg: Option<String> = sqlx::query_scalar(
            "SELECT error_message FROM worker_sessions WHERE job_id = $1 ORDER BY started_at DESC LIMIT 1"
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
        msg.and_then(|m| {
            if m.starts_with("backend: ") {
                Some(m.trim_start_matches("backend: ").to_string())
            } else {
                None
            }
        })
    } else {
        None
    };

    Ok(Json(
        json!({
            "job": job,
            "capture_backend": worker_backend.as_deref().unwrap_or(if job.mode == "stream" { "tcpdump" } else { "upload" }),
            "findings_by_severity": sev.into_iter().collect::<std::collections::HashMap<_, _>>()
        }),
    ))
}

// ----------------------------------------------------------------- packets

#[derive(Deserialize)]
struct PacketsQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    protocol: Option<String>,
    q: Option<String>,
    frame: Option<i64>,
    related_to: Option<i64>,
    filter: Option<String>,
}

#[derive(sqlx::FromRow, Serialize)]
struct PacketRow {
    frame_number: i64,
    captured_at: DateTime<Utc>,
    frame_length: i32,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    transport: Option<String>,
    src_port: Option<i32>,
    dst_port: Option<i32>,
    protocol_stack: Option<String>,
    top_protocol: Option<String>,
    dns_query: Option<String>,
    http_method: Option<String>,
    http_host: Option<String>,
    http_uri: Option<String>,
    tls_sni: Option<String>,
    fields: Value,
}

fn like(s: &str) -> String {
    format!(
        "%{}%",
        s.replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    )
}

fn check_ip(s: &str) -> Result<String, AppError> {
    s.trim()
        .parse::<std::net::IpAddr>()
        .map(|i| i.to_string())
        .map_err(|_| AppError::BadRequest("invalid IP address filter".into()))
}

async fn list_packets(
    State(state): State<AppState>,
    auth: AuthUser,
    UrlPath(job_id): UrlPath<String>,
    Query(q): Query<PacketsQuery>,
) -> Result<Json<Value>, AppError> {
    auth.require("jobs:read")?;
    let id = parse_uuid(&job_id)?;
    let (limit, offset) = page(q.limit, q.offset);
    let src = q.src_ip.as_deref().map(check_ip).transpose()?;
    let dst = q.dst_ip.as_deref().map(check_ip).transpose()?;
    if let Some(filter) = q.filter.as_deref() {
        const FILTERS: [&str; 14] = [
            "unexpected-protocols",
            "non-standard-ports",
            "top-talkers",
            "dns-tunneling",
            "dga",
            "c2-beaconing",
            "suspicious-user-agents",
            "anomalous-tls",
            "network-scans",
            "lateral-movement",
            "malicious-downloads",
            "web-attacks",
            "cleartext-credentials",
            "asymmetric-flows",
        ];
        if !FILTERS.contains(&filter) {
            return Err(AppError::BadRequest("unknown packet filter".into()));
        }
    }

    // "Related" = same endpoint pair and ports in either direction.
    let related: Option<(Option<String>, Option<String>, Option<i32>, Option<i32>)> = match q.related_to {
        Some(f) => Some(
            sqlx::query_as("SELECT host(src_ip), host(dst_ip), src_port, dst_port FROM packets WHERE job_id = $1 AND frame_number = $2")
                .bind(id).bind(f).fetch_optional(&state.pool).await?.ok_or(AppError::NotFound)?,
        ),
        None => None,
    };

    let build = |qb: &mut QueryBuilder<Postgres>| {
        qb.push(" WHERE p.job_id = ").push_bind(id);
        if let Some(filter) = q.filter.as_deref() {
            match filter {
                "unexpected-protocols" => {
                    qb.push(" AND lower(coalesce(p.protocol_stack, '')) ~ '(telnet|ftp|irc|tor)'");
                }
                "non-standard-ports" => {
                    qb.push(" AND ((lower(coalesce(p.top_protocol, '')) = 'http' AND coalesce(p.dst_port, 80) <> 80) OR (lower(coalesce(p.top_protocol, '')) = 'ssh' AND coalesce(p.dst_port, 22) <> 22) OR (lower(coalesce(p.top_protocol, '')) = 'ftp' AND coalesce(p.dst_port, 21) <> 21))");
                }
                "top-talkers" => {
                    qb.push(" AND p.frame_length >= 1048576 AND p.dst_ip IS NOT NULL AND NOT (p.dst_ip << inet '10.0.0.0/8' OR p.dst_ip << inet '172.16.0.0/12' OR p.dst_ip << inet '192.168.0.0/16' OR p.dst_ip << inet 'fc00::/7')");
                }
                "dns-tunneling" => {
                    qb.push(" AND lower(coalesce(p.top_protocol, '')) = 'dns' AND (length(coalesce(p.dns_query, '')) >= 50 OR p.dns_qtype IN (10, 255))");
                }
                "dga" => {
                    qb.push(" AND lower(coalesce(p.top_protocol, '')) = 'dns' AND p.fields->>'dns_response_code' = '3'");
                }
                "c2-beaconing" => {
                    qb.push(" AND p.dst_ip IS NOT NULL AND NOT (p.dst_ip << inet '10.0.0.0/8' OR p.dst_ip << inet '172.16.0.0/12' OR p.dst_ip << inet '192.168.0.0/16' OR p.dst_ip << inet 'fc00::/7')");
                }
                "suspicious-user-agents" => {
                    qb.push(" AND lower(coalesce(p.fields->>'http_user_agent', '')) ~ '(curl|python-requests|powershell)'");
                }
                "anomalous-tls" => {
                    qb.push(" AND lower(coalesce(p.protocol_stack, '')) ~ '(tls|ssl)' AND (p.fields->>'tls_certificate' = 'true' OR lower(coalesce(p.fields->>'tls_issuer', '')) ~ '(default|self|test)')");
                }
                "network-scans" => {
                    qb.push(" AND (p.fields->>'arp_opcode' IS NOT NULL OR (p.transport = 'tcp' AND p.fields->>'tcp_syn' = 'true' AND p.fields->>'tcp_ack' = 'false'))");
                }
                "lateral-movement" => {
                    qb.push(" AND p.dst_port IN (445, 3389, 5985, 5986) AND p.src_ip IS NOT NULL AND p.dst_ip IS NOT NULL AND (p.src_ip << inet '10.0.0.0/8' OR p.src_ip << inet '172.16.0.0/12' OR p.src_ip << inet '192.168.0.0/16') AND (p.dst_ip << inet '10.0.0.0/8' OR p.dst_ip << inet '172.16.0.0/12' OR p.dst_ip << inet '192.168.0.0/16')");
                }
                "malicious-downloads" => {
                    qb.push(" AND (lower(coalesce(p.http_uri, '')) ~ '\\.(exe|dll|elf|ps1|sh|zip|rar|7z)([?/#]|$)' OR lower(coalesce(p.fields->>'http_content_type', '')) ~ '(executable|x-dosexec|x-sh|zip|rar|7z)')");
                }
                "web-attacks" => {
                    qb.push(" AND lower(coalesce(p.http_uri, '')) ~ '(select(%20|\\+)|union(%20|\\+)|or(%20|\\+)1=1|\\.\\./|/etc/passwd|cmd=|powershell)'");
                }
                "cleartext-credentials" => {
                    qb.push(" AND lower(coalesce(p.protocol_stack, '')) ~ '(http|ftp|telnet|smtp|pop)' AND (p.http_method IS NOT NULL OR p.fields->>'http_auth_scheme' IS NOT NULL OR jsonb_array_length(coalesce(p.fields->'form_keys', '[]'::jsonb)) > 0)");
                }
                "asymmetric-flows" => {
                    qb.push(" AND p.frame_length >= 1048576 AND p.src_ip IS NOT NULL AND p.dst_ip IS NOT NULL AND (p.src_ip << inet '10.0.0.0/8' OR p.src_ip << inet '172.16.0.0/12' OR p.src_ip << inet '192.168.0.0/16') AND NOT (p.dst_ip << inet '10.0.0.0/8' OR p.dst_ip << inet '172.16.0.0/12' OR p.dst_ip << inet '192.168.0.0/16')");
                }
                "" | _ => {}
            }
        }
        if let Some(s) = &src {
            qb.push(" AND p.src_ip = ")
                .push_bind(s.clone())
                .push("::text::inet");
        }
        if let Some(d) = &dst {
            qb.push(" AND p.dst_ip = ")
                .push_bind(d.clone())
                .push("::text::inet");
        }
        if let Some(pr) = &q.protocol {
            qb.push(" AND p.top_protocol = ")
                .push_bind(pr.to_lowercase());
        }
        if let Some(f) = q.frame {
            qb.push(" AND p.frame_number = ").push_bind(f);
        }
        if let Some(t) = &q.q {
            let pat = like(t);
            qb.push(" AND (p.dns_query ILIKE ")
                .push_bind(pat.clone())
                .push(" OR p.http_host ILIKE ")
                .push_bind(pat.clone())
                .push(" OR p.http_uri ILIKE ")
                .push_bind(pat.clone())
                .push(" OR p.tls_sni ILIKE ")
                .push_bind(pat)
                .push(")");
        }
        if let Some((s, d, sp, dp)) = &related {
            qb.push(" AND ((host(p.src_ip) IS NOT DISTINCT FROM ")
                .push_bind(s.clone())
                .push(" AND host(p.dst_ip) IS NOT DISTINCT FROM ")
                .push_bind(d.clone())
                .push(" AND p.src_port IS NOT DISTINCT FROM ")
                .push_bind(*sp)
                .push(" AND p.dst_port IS NOT DISTINCT FROM ")
                .push_bind(*dp)
                .push(") OR (host(p.src_ip) IS NOT DISTINCT FROM ")
                .push_bind(d.clone())
                .push(" AND host(p.dst_ip) IS NOT DISTINCT FROM ")
                .push_bind(s.clone())
                .push(" AND p.src_port IS NOT DISTINCT FROM ")
                .push_bind(*dp)
                .push(" AND p.dst_port IS NOT DISTINCT FROM ")
                .push_bind(*sp)
                .push("))");
        }
    };
    let mut count: QueryBuilder<Postgres> = QueryBuilder::new("SELECT count(*) FROM packets p");
    build(&mut count);
    let mut list: QueryBuilder<Postgres> = QueryBuilder::new(
        "SELECT p.frame_number, p.captured_at, p.frame_length, host(p.src_ip) AS src_ip, host(p.dst_ip) AS dst_ip, \
         p.transport, p.src_port, p.dst_port, p.protocol_stack, p.top_protocol, p.dns_query, p.http_method, \
         p.http_host, p.http_uri, p.tls_sni, p.fields FROM packets p",
    );
    build(&mut list);
    list.push(" ORDER BY p.frame_number LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);
    let total: i64 = count.build_query_scalar().fetch_one(&state.pool).await?;
    let items: Vec<PacketRow> = list.build_query_as().fetch_all(&state.pool).await?;
    Ok(Json(
        json!({"items": items, "total": total, "limit": limit, "offset": offset}),
    ))
}

async fn protocols(
    State(state): State<AppState>,
    auth: AuthUser,
    UrlPath(job_id): UrlPath<String>,
) -> Result<Json<Value>, AppError> {
    auth.require("jobs:read")?;
    let id = parse_uuid(&job_id)?;
    let by_proto: Vec<(Option<String>, i64, i64)> = sqlx::query_as(
        "SELECT top_protocol, count(*), COALESCE(sum(frame_length), 0)::bigint FROM packets WHERE job_id = $1 \
         GROUP BY 1 ORDER BY 2 DESC LIMIT 25")
        .bind(id).fetch_all(&state.pool).await?;
    let by_stack: Vec<(Option<String>, i64)> = sqlx::query_as(
        "SELECT protocol_stack, count(*) FROM packets WHERE job_id = $1 GROUP BY 1 ORDER BY 2 DESC LIMIT 25")
        .bind(id).fetch_all(&state.pool).await?;
    Ok(Json(json!({
        "by_protocol": by_proto.into_iter().map(|(p, c, b)| json!({"protocol": p.unwrap_or_else(|| "unknown".into()), "packets": c, "bytes": b})).collect::<Vec<_>>(),
        "hierarchy": by_stack.into_iter().map(|(s, c)| json!({"stack": s.unwrap_or_default(), "packets": c})).collect::<Vec<_>>(),
    })))
}

/// Full TShark JSON dissection (with raw bytes) of one frame, produced on demand from the
/// original evidence. Records an `accessed` custody entry.
async fn dissect_packet(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: AuthUser,
    UrlPath((job_id, frame)): UrlPath<(String, u64)>,
) -> Result<Json<Value>, AppError> {
    auth.require("jobs:read")?;
    auth.require("evidence:read")?;
    let id = parse_uuid(&job_id)?;
    if frame == 0 {
        return Err(AppError::BadRequest("frame must be >= 1".into()));
    }
    let art: (Uuid, String) = sqlx::query_as(
        "SELECT id, storage_path FROM evidence_artifacts WHERE job_id = $1 AND kind IN ('pcap','pcapng') ORDER BY created_at LIMIT 1")
        .bind(id).fetch_optional(&state.pool).await?.ok_or(AppError::NotFound)?;
    let path = evidence::absolute_path(Path::new(&state.config.evidence_dir), &art.1)?;
    let home = std::env::temp_dir();
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        tshark::dissect_command(&state.config.tshark_path, &home, &path, frame).output(),
    )
    .await
    .map_err(|_| AppError::Internal("tshark dissection timed out".into()))?
    .map_err(|e| AppError::Internal(format!("tshark failed: {e}")))?;
    if !out.status.success() {
        return Err(AppError::Internal(
            "tshark could not dissect the frame".into(),
        ));
    }
    let arr: Value = serde_json::from_slice(&out.stdout)
        .map_err(|_| AppError::Internal("unparseable tshark output".into()))?;
    let packet = arr.get(0).cloned().ok_or(AppError::NotFound)?;
    evidence::record_custody(
        &state.pool,
        art.0,
        "accessed",
        &Actor {
            id: Some(auth.id),
            label: &auth.username,
        },
        Some(&meta),
        json!({"what": "packet_dissection", "frame": frame}),
    )
    .await?;
    Ok(Json(json!({"frame": frame, "dissection": packet})))
}

// ---------------------------------------------------------------- evidence

#[derive(sqlx::FromRow, Serialize)]
struct ArtifactRow {
    id: Uuid,
    evidence_id: String,
    kind: String,
    original_filename: Option<String>,
    size_bytes: i64,
    sha256: String,
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Serialize)]
struct CustodyRow {
    id: i64,
    action: String,
    actor_label: String,
    ip_address: Option<String>,
    detail: Value,
    occurred_at: DateTime<Utc>,
}

async fn job_evidence(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: AuthUser,
    UrlPath(job_id): UrlPath<String>,
) -> Result<Json<Value>, AppError> {
    auth.require("evidence:read")?;
    let id = parse_uuid(&job_id)?;
    let artifacts: Vec<ArtifactRow> = sqlx::query_as(
        "SELECT id, evidence_id, kind, original_filename, size_bytes, encode(sha256, 'hex') AS sha256, created_at \
         FROM evidence_artifacts WHERE job_id = $1 ORDER BY created_at")
        .bind(id).fetch_all(&state.pool).await?;
    let mut out = Vec::new();
    for a in artifacts {
        let custody: Vec<CustodyRow> = sqlx::query_as(
            "SELECT id, action::text AS action, actor_label, host(ip_address) AS ip_address, detail, occurred_at \
             FROM chain_of_custody WHERE artifact_id = $1 ORDER BY id")
            .bind(a.id).fetch_all(&state.pool).await?;
        let last_check: Option<(bool, DateTime<Utc>)> = sqlx::query_as(
            "SELECT matches_original, computed_at FROM evidence_hashes WHERE artifact_id = $1 ORDER BY id DESC LIMIT 1")
            .bind(a.id).fetch_optional(&state.pool).await?;
        evidence::record_custody(
            &state.pool,
            a.id,
            "accessed",
            &Actor {
                id: Some(auth.id),
                label: &auth.username,
            },
            Some(&meta),
            json!({"what": "metadata_view"}),
        )
        .await?;
        out.push(json!({"artifact": a, "custody": custody,
            "last_verification": last_check.map(|(ok, at)| json!({"matches_original": ok, "at": at}))}));
    }
    Ok(Json(json!({"items": out})))
}

async fn artifact_for(
    state: &AppState,
    job_id: &str,
    evidence_id: &str,
) -> Result<(Uuid, String, String), AppError> {
    let job = parse_uuid(job_id)?;
    sqlx::query_as("SELECT id, storage_path, COALESCE(original_filename, 'capture.pcap') FROM evidence_artifacts WHERE job_id = $1 AND evidence_id = $2")
        .bind(job).bind(evidence_id).fetch_optional(&state.pool).await?.ok_or(AppError::NotFound)
}

async fn verify_evidence(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: AuthUser,
    UrlPath((job_id, evidence_id)): UrlPath<(String, String)>,
) -> Result<Json<Value>, AppError> {
    auth.require("evidence:read")?;
    let (artifact, _, _) = artifact_for(&state, &job_id, &evidence_id).await?;
    let v = evidence::verify_artifact(
        &state.pool,
        Path::new(&state.config.evidence_dir),
        artifact,
        &Actor {
            id: Some(auth.id),
            label: &auth.username,
        },
        Some(&meta),
    )
    .await?;
    Ok(Json(json!({"evidence_id": evidence_id, "verified": v.ok,
        "expected_sha256": evidence::hex(&v.expected), "actual_sha256": evidence::hex(&v.actual)})))
}

async fn download_evidence(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: AuthUser,
    UrlPath((job_id, evidence_id)): UrlPath<(String, String)>,
) -> Result<Response, AppError> {
    auth.require("evidence:export")?;
    let (artifact, storage, filename) = artifact_for(&state, &job_id, &evidence_id).await?;
    let actor = Actor {
        id: Some(auth.id),
        label: &auth.username,
    };
    // Integrity is verified before anything leaves the system.
    let v = evidence::verify_artifact(
        &state.pool,
        Path::new(&state.config.evidence_dir),
        artifact,
        &actor,
        Some(&meta),
    )
    .await?;
    if !v.ok {
        audit::record(
            &state.pool,
            &meta,
            AuditEvent::new("evidence.export", "denied")
                .actor(auth.id, &auth.username)
                .resource("evidence", &evidence_id)
                .detail(json!({"reason": "integrity check failed"})),
        )
        .await;
        return Err(AppError::Conflict(
            "integrity verification failed; export refused",
        ));
    }
    let path = evidence::absolute_path(Path::new(&state.config.evidence_dir), &storage)?;
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(AppError::internal)?;
    evidence::record_custody(
        &state.pool,
        artifact,
        "exported",
        &actor,
        Some(&meta),
        json!({"sha256": evidence::hex(&v.actual), "filename": filename}),
    )
    .await?;
    audit::record(
        &state.pool,
        &meta,
        AuditEvent::new("evidence.export", "success")
            .actor(auth.id, &auth.username)
            .resource("evidence", &evidence_id),
    )
    .await;

    let safe: String = filename
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    let mut res = Response::new(Body::from_stream(ReaderStream::new(file)));
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "attachment; filename=\"{}\"",
            if safe.is_empty() {
                "capture.pcap"
            } else {
                &safe
            }
        ))
        .unwrap_or(HeaderValue::from_static("attachment")),
    );
    h.insert(
        "x-evidence-sha256",
        HeaderValue::from_str(&evidence::hex(&v.actual)).unwrap_or(HeaderValue::from_static("")),
    );
    Ok(res)
}

// ---------------------------------------------------------------- findings

#[derive(Deserialize, Default)]
struct FindingsQuery {
    job_id: Option<String>,
    profile: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(sqlx::FromRow, Serialize)]
struct FindingRow {
    id: Uuid,
    job_id: Uuid,
    profile_id: String,
    rule_id: String,
    severity: String,
    confidence: f64,
    status: String,
    title: String,
    explanation: String,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    src_port: Option<i32>,
    dst_port: Option<i32>,
    packet_frames: Vec<i64>,
    supporting_evidence: Value,
    detected_at: DateTime<Utc>,
}

const FINDING_SELECT: &str = "SELECT f.id, f.job_id, f.profile_id, f.rule_id, f.severity::text AS severity, \
    f.confidence::float8 AS confidence, f.status::text AS status, f.title, f.explanation, host(f.src_ip) AS src_ip, \
    host(f.dst_ip) AS dst_ip, f.src_port, f.dst_port, f.packet_frames, f.supporting_evidence, f.detected_at FROM threat_findings f";

fn finding_filters(qb: &mut QueryBuilder<Postgres>, q: &FindingsQuery) -> Result<(), AppError> {
    qb.push(" WHERE 1=1");
    if let Some(j) = &q.job_id {
        qb.push(" AND f.job_id = ").push_bind(parse_uuid(j)?);
    }
    if let Some(p) = &q.profile {
        qb.push(" AND f.profile_id = ").push_bind(p.clone());
    }
    if let Some(s) = &q.severity {
        let v: Vec<String> = s
            .split(',')
            .map(|x| x.trim().to_lowercase())
            .filter(|x| !x.is_empty())
            .collect();
        qb.push(" AND f.severity::text = ANY(")
            .push_bind(v)
            .push(")");
    }
    if let Some(s) = &q.status {
        let v: Vec<String> = s
            .split(',')
            .map(|x| x.trim().to_lowercase())
            .filter(|x| !x.is_empty())
            .collect();
        qb.push(" AND f.status::text = ANY(").push_bind(v).push(")");
    }
    if let Some(t) = q.q.as_deref().filter(|t| !t.trim().is_empty()) {
        let pat = like(t.trim());
        qb.push(" AND (f.title ILIKE ")
            .push_bind(pat.clone())
            .push(" OR f.explanation ILIKE ")
            .push_bind(pat.clone())
            .push(" OR f.rule_id ILIKE ")
            .push_bind(pat.clone())
            .push(" OR host(f.src_ip) ILIKE ")
            .push_bind(pat.clone())
            .push(" OR host(f.dst_ip) ILIKE ")
            .push_bind(pat)
            .push(")");
    }
    Ok(())
}

fn finding_order(q: &FindingsQuery) -> String {
    let col = match q.sort.as_deref() {
        Some("severity") => "f.severity",
        Some("confidence") => "f.confidence",
        Some("src_ip") => "f.src_ip",
        Some("dst_ip") => "f.dst_ip",
        Some("rule_id") => "f.rule_id",
        Some("status") => "f.status",
        _ => "f.detected_at",
    };
    let dir = if q.dir.as_deref() == Some("asc") {
        "ASC"
    } else {
        "DESC"
    };
    format!(" ORDER BY {col} {dir}, f.id")
}

async fn list_findings(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<FindingsQuery>,
) -> Result<Json<Value>, AppError> {
    auth.require("findings:read")?;
    let (limit, offset) = page(q.limit, q.offset);
    let mut count: QueryBuilder<Postgres> =
        QueryBuilder::new("SELECT count(*) FROM threat_findings f");
    finding_filters(&mut count, &q)?;
    let mut list: QueryBuilder<Postgres> = QueryBuilder::new(FINDING_SELECT);
    finding_filters(&mut list, &q)?;
    list.push(finding_order(&q))
        .push(" LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);
    let total: i64 = count.build_query_scalar().fetch_one(&state.pool).await?;
    let items: Vec<FindingRow> = list.build_query_as().fetch_all(&state.pool).await?;
    Ok(Json(
        json!({"items": items, "total": total, "limit": limit, "offset": offset}),
    ))
}

fn csv_cell(s: &str) -> String {
    // Neutralise spreadsheet formula injection, then quote.
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    format!("\"{}\"", s.replace('"', "\"\""))
}

#[derive(Deserialize)]
struct ExportQuery {
    format: Option<String>,
    #[serde(flatten)]
    filters: FindingsQuery,
}

async fn export_findings(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: AuthUser,
    Query(q): Query<ExportQuery>,
) -> Result<Response, AppError> {
    auth.require("findings:read")?;
    let mut list: QueryBuilder<Postgres> = QueryBuilder::new(FINDING_SELECT);
    finding_filters(&mut list, &q.filters)?;
    list.push(finding_order(&q.filters)).push(" LIMIT 10000");
    let rows: Vec<FindingRow> = list.build_query_as().fetch_all(&state.pool).await?;
    audit::record(
        &state.pool,
        &meta,
        AuditEvent::new("findings.export", "success")
            .actor(auth.id, &auth.username)
            .detail(json!({"rows": rows.len()})),
    )
    .await;
    let (body, ctype, name) = if q.format.as_deref() == Some("csv") {
        let mut s = String::from("id,job_id,detected_at,severity,confidence,status,profile,rule,title,src_ip,dst_ip,dst_port,packet_frames,explanation\n");
        for r in &rows {
            let cells = [
                r.id.to_string(),
                r.job_id.to_string(),
                r.detected_at.to_rfc3339(),
                r.severity.clone(),
                format!("{:.3}", r.confidence),
                r.status.clone(),
                r.profile_id.clone(),
                r.rule_id.clone(),
                r.title.clone(),
                r.src_ip.clone().unwrap_or_default(),
                r.dst_ip.clone().unwrap_or_default(),
                r.dst_port.map(|p| p.to_string()).unwrap_or_default(),
                r.packet_frames
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join(" "),
                r.explanation.clone(),
            ];
            s.push_str(
                &cells
                    .iter()
                    .map(|c| csv_cell(c))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            s.push('\n');
        }
        (s, "text/csv; charset=utf-8", "findings.csv")
    } else {
        (
            serde_json::to_string_pretty(&rows).map_err(AppError::internal)?,
            "application/json",
            "findings.json",
        )
    };
    let mut res = Response::new(Body::from(body));
    res.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    res.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")).unwrap(),
    );
    Ok(res)
}

async fn get_finding(
    State(state): State<AppState>,
    auth: AuthUser,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<FindingRow>, AppError> {
    auth.require("findings:read")?;
    let row: FindingRow = sqlx::query_as(&format!("{FINDING_SELECT} WHERE f.id = $1"))
        .bind(parse_uuid(&id)?)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(row))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TriageReq {
    status: String,
}

async fn triage_finding(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: AuthUser,
    UrlPath(id): UrlPath<String>,
    Json(req): Json<TriageReq>,
) -> Result<Json<Value>, AppError> {
    auth.require("findings:triage")?;
    if !["open", "triaged", "false_positive", "confirmed"].contains(&req.status.as_str()) {
        return Err(AppError::BadRequest(
            "status must be open, triaged, false_positive or confirmed".into(),
        ));
    }
    let id = parse_uuid(&id)?;
    let n =
        sqlx::query("UPDATE threat_findings SET status = $2::text::finding_status WHERE id = $1")
            .bind(id)
            .bind(&req.status)
            .execute(&state.pool)
            .await?
            .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }
    audit::record(
        &state.pool,
        &meta,
        AuditEvent::new("finding.triage", "success")
            .actor(auth.id, &auth.username)
            .resource("finding", id)
            .detail(json!({"status": req.status})),
    )
    .await;
    Ok(Json(json!({"id": id, "status": req.status})))
}

// ------------------------------------------------------- profiles & stats

async fn list_profiles(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, AppError> {
    auth.require("jobs:read")?;
    let rows: Vec<(String, String, String, Value)> = sqlx::query_as(
        "SELECT id, label, description, thresholds FROM detection_profiles WHERE is_enabled ORDER BY id")
        .fetch_all(&state.pool).await?;
    Ok(Json(
        json!({"items": rows.into_iter().map(|(id, label, description, thresholds)| json!({"id": id, "label": label, "description": description, "thresholds": thresholds})).collect::<Vec<_>>()}),
    ))
}

async fn stats(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Value>, AppError> {
    auth.require("jobs:read")?;
    let (jobs_total, jobs_active, packets_total, findings_total, evidence_total): (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM capture_jobs), \
                (SELECT count(*) FROM capture_jobs WHERE status IN ('queued','running','stopping')), \
                (SELECT COALESCE(sum(packet_count), 0)::bigint FROM capture_jobs), \
                (SELECT count(*) FROM threat_findings), \
                (SELECT count(*) FROM evidence_artifacts)")
        .fetch_one(&state.pool).await?;
    let sev: Vec<(String, i64)> =
        sqlx::query_as("SELECT severity::text, count(*) FROM threat_findings GROUP BY 1")
            .fetch_all(&state.pool)
            .await?;
    Ok(Json(json!({
        "jobs_total": jobs_total, "jobs_active": jobs_active, "packets_total": packets_total,
        "findings_total": findings_total, "evidence_total": evidence_total,
        "findings_by_severity": sev.into_iter().collect::<std::collections::HashMap<_, _>>(),
        "running_in_this_process": state.jobs.running_count(),
    })))
}


async fn get_disk_stats(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Value>, AppError> {
    // Accessible by all authenticated roles (ADMIN, ANALYST, VIEWER via jobs:read)
    auth.require("jobs:read")?;
    let path = std::path::Path::new(&state.config.evidence_dir);
    let metrics = evidence::get_disk_metrics(path).unwrap_or(evidence::DiskMetrics {
        total_bytes: 0,
        available_bytes: 0,
        used_bytes: 0,
        used_percent: 0.0,
        evidence_dir_bytes: 0,
        evidence_file_count: 0,
        is_low_space: false,
    });

    Ok(Json(json!({
        "evidence_dir": state.config.evidence_dir,
        "total_bytes": metrics.total_bytes,
        "available_bytes": metrics.available_bytes,
        "used_bytes": metrics.used_bytes,
        "used_percent": (metrics.used_percent * 10.0).round() / 10.0,
        "evidence_dir_bytes": metrics.evidence_dir_bytes,
        "evidence_file_count": metrics.evidence_file_count,
        "is_low_space": metrics.is_low_space,
    })))
}
