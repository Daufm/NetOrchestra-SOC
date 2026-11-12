//! Streaming analysis pipeline: TShark field output -> normalized packets (batched into
//! PostgreSQL) -> detector -> findings (persisted and published live). Memory is bounded:
//! packets are flushed in batches and detectors cap their group tables.
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use uuid::Uuid;

use super::{
    detect::{self, Detector, Finding},
    model::{parse_line, PacketRecord},
};
use crate::{
    error::AppError,
    events::{EventBus, EventKind},
};

const BATCH: usize = 1000;
const MAX_LINE_BYTES: usize = 1024 * 1024;
const MAX_FINDINGS_PER_JOB: usize = 1000;

pub struct Ctx<'a> {
    pub pool: &'a PgPool,
    pub events: &'a EventBus,
    pub job_id: Uuid,
    pub profile_id: &'a str,
    pub thresholds: &'a Value,
}

/// How progress percentage is derived.
#[derive(Clone, Copy)]
pub enum Progress {
    /// Estimate from bytes dissected vs. total capture size (uploads).
    OfBytes(u64),
    /// Caller reports progress itself (live captures).
    External,
}

#[derive(Debug, Default, Clone)]
pub struct Summary {
    pub packets: u64,
    pub bytes: u64,
    pub findings: u64,
    pub malformed_lines: u64,
    pub detector_truncated: bool,
    pub findings_capped: bool,
}

struct State {
    detector: Box<dyn Detector>,
    sensitive: Vec<String>,
    known: HashMap<String, Uuid>,
    summary: Summary,
}

pub async fn consume<R: AsyncRead + Unpin>(
    ctx: &Ctx<'_>,
    reader: R,
    progress: Progress,
) -> Result<Summary, AppError> {
    let detector = detect::for_profile(ctx.profile_id, ctx.thresholds).ok_or_else(|| {
        AppError::BadRequest(format!("unknown detection profile '{}'", ctx.profile_id))
    })?;
    let mut st = State {
        detector,
        sensitive: detect::http::sensitive_keys(ctx.thresholds),
        known: HashMap::new(),
        summary: Summary::default(),
    };

    let mut rd = BufReader::with_capacity(256 * 1024, reader);
    let mut buf: Vec<u8> = Vec::new();
    let mut batch: Vec<PacketRecord> = Vec::with_capacity(BATCH);
    let mut last_flush = Instant::now();
    let mut last_progress = Instant::now();

    loop {
        // `buf` persists across timeouts, so a partially read line is never lost.
        let read =
            tokio::time::timeout(Duration::from_millis(500), rd.read_until(b'\n', &mut buf)).await;
        match read {
            Err(_) => {} // idle: fall through to the time-based flush below
            Ok(Err(e)) => return Err(AppError::internal(format!("reading tshark output: {e}"))),
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                if buf.last() == Some(&b'\n') {
                    if buf.len() > MAX_LINE_BYTES {
                        st.summary.malformed_lines += 1;
                    } else {
                        let line = String::from_utf8_lossy(&buf);
                        let line = line.trim_end_matches(['\n', '\r']);
                        if !line.is_empty() {
                            match parse_line(line) {
                                Ok(p) => {
                                    st.detector.observe(&p);
                                    st.summary.bytes += (p.len.max(0) as u64) + 16;
                                    batch.push(p);
                                }
                                Err(_) => st.summary.malformed_lines += 1,
                            }
                        }
                    }
                    buf.clear();
                }
            }
        }
        if batch.len() >= BATCH
            || (!batch.is_empty() && last_flush.elapsed() >= Duration::from_secs(1))
        {
            flush(ctx, &mut st, &mut batch, false).await?;
            last_flush = Instant::now();
        }
        if last_progress.elapsed() >= Duration::from_millis(750) {
            report(ctx, &st, progress).await;
            last_progress = Instant::now();
        }
    }
    if !buf.is_empty() {
        st.summary.malformed_lines += 1; // trailing partial line (e.g. truncated capture)
    }
    flush(ctx, &mut st, &mut batch, true).await?;
    st.summary.detector_truncated = st.detector.truncated();
    report(ctx, &st, progress).await;
    Ok(st.summary)
}

async fn report(ctx: &Ctx<'_>, st: &State, progress: Progress) {
    let pct = match progress {
        Progress::OfBytes(total) if total > 0 => {
            Some(((st.summary.bytes * 100) / total).min(99) as i16)
        }
        _ => None,
    };
    let _ = sqlx::query(
        "UPDATE capture_jobs SET packet_count = $2, progress_pct = COALESCE($3, progress_pct) WHERE id = $1",
    )
    .bind(ctx.job_id)
    .bind(st.summary.packets as i64)
    .bind(pct)
    .execute(ctx.pool)
    .await;
    ctx.events.publish(
        EventKind::JobProgress,
        ctx.job_id,
        json!({"phase": "analysis", "packets": st.summary.packets, "findings": st.summary.findings, "progress_pct": pct}),
    );
}

async fn flush(
    ctx: &Ctx<'_>,
    st: &mut State,
    batch: &mut Vec<PacketRecord>,
    final_: bool,
) -> Result<(), AppError> {
    if !batch.is_empty() {
        insert_packets(ctx.pool, ctx.job_id, batch, &st.sensitive).await?;
        st.summary.packets += batch.len() as u64;
        batch.clear();
    }
    sync_findings(ctx, st, final_).await
}

fn fields_json(p: &PacketRecord) -> Value {
    json!({
        "tcp_syn": p.tcp_syn,
        "tcp_ack": p.tcp_ack,
        // Only the scheme of an Authorization header is kept, never the credential.
        "http_auth_scheme": p.http_auth.as_deref().and_then(|a| a.split_whitespace().next()).map(str::to_lowercase),
        "form_keys": p.form_keys,
        "dns_queries": p.dns_queries.iter().map(|(n, _)| n).collect::<Vec<_>>(),
        "dns_response": p.dns_is_response,
        "dns_response_code": p.dns_response_code,
        "arp_opcode": p.arp_opcode,
        "http_user_agent": p.http_user_agent,
        "http_content_type": p.http_content_type,
        "tls_certificate": p.tls_certificate.is_some(),
        "tls_not_before": p.tls_not_before,
        "tls_not_after": p.tls_not_after,
        "tls_issuer": p.tls_issuer,
    })
}

async fn insert_packets(
    pool: &PgPool,
    job_id: Uuid,
    rows: &[PacketRecord],
    sensitive: &[String],
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO packets (job_id, frame_number, captured_at, frame_length, src_ip, dst_ip, ip_version, \
            transport, src_port, dst_port, protocol_stack, top_protocol, dns_query, dns_qtype, \
            http_method, http_host, http_uri, tls_sni, fields) \
         SELECT $1, f, t, l, s::inet, d::inet, v, tr, sp, dp, ps, tp, dq, dt, hm, hh, hu, sni, fl \
         FROM UNNEST($2::bigint[], $3::timestamptz[], $4::int[], $5::text[], $6::text[], $7::smallint[], \
            $8::text[], $9::int[], $10::int[], $11::text[], $12::text[], $13::text[], $14::int[], \
            $15::text[], $16::text[], $17::text[], $18::text[], $19::jsonb[]) \
            AS u(f, t, l, s, d, v, tr, sp, dp, ps, tp, dq, dt, hm, hh, hu, sni, fl) \
         ON CONFLICT (job_id, frame_number) DO NOTHING",
    )
    .bind(job_id)
    .bind(rows.iter().map(|p| p.frame).collect::<Vec<_>>())
    .bind(rows.iter().map(|p| p.ts).collect::<Vec<_>>())
    .bind(rows.iter().map(|p| p.len).collect::<Vec<_>>())
    .bind(rows.iter().map(|p| p.src_ip.clone()).collect::<Vec<_>>())
    .bind(rows.iter().map(|p| p.dst_ip.clone()).collect::<Vec<_>>())
    .bind(rows.iter().map(|p| p.ip_version).collect::<Vec<_>>())
    .bind(rows.iter().map(|p| p.transport.map(str::to_string)).collect::<Vec<_>>())
    .bind(rows.iter().map(|p| p.src_port).collect::<Vec<_>>())
    .bind(rows.iter().map(|p| p.dst_port).collect::<Vec<_>>())
    .bind(rows.iter().map(|p| Some(p.protocols.clone())).collect::<Vec<_>>())
    .bind(rows.iter().map(|p| p.top_protocol.clone()).collect::<Vec<_>>())
    .bind(rows.iter().map(|p| p.dns_queries.first().map(|q| q.0.clone())).collect::<Vec<_>>())
    .bind(rows.iter().map(|p| p.dns_queries.first().and_then(|q| q.1)).collect::<Vec<_>>())
    .bind(rows.iter().map(|p| p.http_method.clone()).collect::<Vec<_>>())
    .bind(rows.iter().map(|p| p.http_host.clone()).collect::<Vec<_>>())
    .bind(
        rows.iter()
            .map(|p| p.http_uri.as_deref().map(|u| detect::http::redact_uri(u, sensitive)))
            .collect::<Vec<_>>(),
    )
    .bind(rows.iter().map(|p| p.tls_sni.clone()).collect::<Vec<_>>())
    .bind(rows.iter().map(fields_json).collect::<Vec<_>>())
    .execute(pool)
    .await?;
    Ok(())
}

async fn sync_findings(ctx: &Ctx<'_>, st: &mut State, final_: bool) -> Result<(), AppError> {
    let mut current = st.detector.findings();
    current.sort_by(|a, b| a.key.cmp(&b.key)); // deterministic insertion order
    for f in current {
        match st.known.get(&f.key).copied() {
            None => {
                if st.known.len() >= MAX_FINDINGS_PER_JOB {
                    st.summary.findings_capped = true;
                    continue;
                }
                let id = insert_finding(ctx, &f).await?;
                st.known.insert(f.key.clone(), id);
                st.summary.findings += 1;
                if let Some(frame) = f.frames.first() {
                    ctx.events.publish(
                        EventKind::PacketDetected,
                        ctx.job_id,
                        json!({"finding_id": id, "frame": frame, "rule_id": f.rule_id}),
                    );
                }
                ctx.events.publish(
                    EventKind::ThreatDetected,
                    ctx.job_id,
                    json!({
                        "finding_id": id, "rule_id": f.rule_id, "severity": f.severity,
                        "confidence": f.confidence, "title": f.title,
                        "src_ip": f.src_ip, "dst_ip": f.dst_ip,
                        "frames": f.frames.iter().take(5).collect::<Vec<_>>(),
                    }),
                );
            }
            Some(id) if final_ => update_finding(ctx.pool, id, &f).await?,
            Some(_) => {}
        }
    }
    Ok(())
}

async fn insert_finding(ctx: &Ctx<'_>, f: &Finding) -> Result<Uuid, AppError> {
    Ok(sqlx::query_scalar(
        "INSERT INTO threat_findings (job_id, profile_id, rule_id, severity, confidence, title, explanation, \
            src_ip, dst_ip, src_port, dst_port, packet_frames, supporting_evidence, detected_at) \
         VALUES ($1, $2, $3, $4::text::severity, $5::float8::numeric(4,3), $6, $7, $8::text::inet, \
            $9::text::inet, $10, $11, $12, $13, $14) RETURNING id",
    )
    .bind(ctx.job_id)
    .bind(ctx.profile_id)
    .bind(f.rule_id)
    .bind(f.severity)
    .bind(f.confidence)
    .bind(&f.title)
    .bind(&f.explanation)
    .bind(&f.src_ip)
    .bind(&f.dst_ip)
    .bind(f.src_port)
    .bind(f.dst_port)
    .bind(&f.frames)
    .bind(&f.evidence)
    .bind(f.detected_at)
    .fetch_one(ctx.pool)
    .await?)
}

async fn update_finding(pool: &PgPool, id: Uuid, f: &Finding) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE threat_findings SET severity = $2::text::severity, confidence = $3::float8::numeric(4,3), \
            explanation = $4, packet_frames = $5, supporting_evidence = $6 WHERE id = $1",
    )
    .bind(id)
    .bind(f.severity)
    .bind(f.confidence)
    .bind(&f.explanation)
    .bind(&f.frames)
    .bind(&f.evidence)
    .execute(pool)
    .await?;
    Ok(())
}
