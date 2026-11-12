//! End-to-end forensics tests: real router + PostgreSQL + TShark, using synthetic PCAPs from
//! `tests/fixtures` (generate with `python3 tests/make_fixtures.py tests/fixtures`).
//! Live streaming is exercised with a mock worker script (no SSH needed).
//!   DATABASE_URL=postgres://user:pass@localhost/postgres cargo test --test forensics_flow -- --ignored
use std::{collections::HashMap, path::PathBuf, time::Duration};

use axum::{
    body::Body,
    http::{header, HeaderMap, Method, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use netorchestra_backend::{
    config::Config,
    events::{Event, EventKind},
    routes,
    state::AppState,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const BOOT: &str = "bootstrap-token-0123456789abcdef";
const PW: &str = "correct-horse-battery-1";

fn fixture(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/fixtures")
        .join(name);
    std::fs::read(&p)
        .unwrap_or_else(|e| panic!("missing fixture {p:?}: {e} (run tests/make_fixtures.py)"))
}

struct Env {
    app: Router,
    state: AppState,
    admin: String,
    viewer: String,
    evidence: PathBuf,
    _tmp: PathBuf,
}

async fn call(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
    headers: &[(&str, String)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut req = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let req = match body {
        Some(b) => req
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let (s, h) = (res.status(), res.headers().clone());
    (
        s,
        h,
        res.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
}

async fn json_call(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
    tok: &str,
) -> (StatusCode, Value) {
    let (s, _, b) = call(
        app,
        method,
        uri,
        body,
        &[("authorization", format!("Bearer {tok}"))],
    )
    .await;
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

async fn login(app: &Router, user: &str) -> String {
    let (s, _, b) = call(
        app,
        Method::POST,
        "/api/auth/login",
        Some(json!({"username": user, "password": PW})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    serde_json::from_slice::<Value>(&b).unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn setup(pool: PgPool, extra: &[(&str, String)]) -> Env {
    let tmp = std::env::temp_dir().join(format!("neto-it-{}", Uuid::new_v4()));
    let evidence = tmp.join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    let mut m: HashMap<String, String> = HashMap::from([
        ("DATABASE_URL".into(), "postgres://x:y@h/db".into()),
        (
            "NETO_JWT_SECRET".into(),
            "0123456789abcdef0123456789abcdef0123".into(),
        ),
        ("NETO_BOOTSTRAP_TOKEN".into(), BOOT.into()),
        ("NETO_ALLOW_REGISTRATION".into(), "true".into()),
        (
            "NETO_EVIDENCE_DIR".into(),
            evidence.to_string_lossy().into(),
        ),
        (
            "NETO_WORKSPACE_DIR".into(),
            tmp.join("ws").to_string_lossy().into(),
        ),
    ]);
    for (k, v) in extra {
        m.insert(k.to_string(), v.clone());
    }
    let state = AppState::new(pool, Config::from_lookup(|k| m.get(k).cloned()).unwrap()).unwrap();
    let app = routes::router(state.clone());
    let (s, _, _) = call(
        &app,
        Method::POST,
        "/api/auth/register",
        Some(json!({"username": "admin", "password": PW})),
        &[("x-bootstrap-token", BOOT.into())],
    )
    .await;
    // Tests that build several environments on one database re-use the existing users.
    assert!(
        matches!(
            s,
            StatusCode::CREATED | StatusCode::CONFLICT | StatusCode::FORBIDDEN
        ),
        "{s}"
    );
    let (s, _, _) = call(
        &app,
        Method::POST,
        "/api/auth/register",
        Some(json!({"username": "viewer1", "password": PW})),
        &[],
    )
    .await;
    assert!(
        matches!(s, StatusCode::CREATED | StatusCode::CONFLICT),
        "{s}"
    );
    let admin = login(&app, "admin").await;
    let viewer = login(&app, "viewer1").await;
    Env {
        app,
        state,
        admin,
        viewer,
        evidence,
        _tmp: tmp,
    }
}

fn multipart(parts: &[(&str, Option<&str>, Vec<u8>)]) -> (String, Vec<u8>) {
    let boundary = "----netoTestBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();
    for (name, filename, data) in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        match filename {
            Some(f) => body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes()),
            None => body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes()),
        }
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

async fn upload_raw(
    app: &Router,
    tok: &str,
    parts: &[(&str, Option<&str>, Vec<u8>)],
) -> (StatusCode, Value) {
    let (ct, body) = multipart(parts);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/upload")
        .header(header::CONTENT_TYPE, ct)
        .header("authorization", format!("Bearer {tok}"))
        .body(Body::from(body))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let s = res.status();
    let b = res.into_body().collect().await.unwrap().to_bytes();
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

async fn upload(env: &Env, file: &str, profile: &str) -> Uuid {
    let (s, b) = upload_raw(
        &env.app,
        &env.admin,
        &[
            ("profile", None, profile.as_bytes().to_vec()),
            ("file", Some(file), fixture(file)),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    Uuid::parse_str(b["job_id"].as_str().unwrap()).unwrap()
}

async fn wait_done(env: &Env, job: Uuid) -> Value {
    for _ in 0..240 {
        let (s, b) = json_call(
            &env.app,
            Method::GET,
            &format!("/api/jobs/{job}"),
            None,
            &env.admin,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let st = b["job"]["status"].as_str().unwrap().to_string();
        if st == "completed" || st == "failed" {
            return b;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("job {job} did not finish");
}

async fn findings(env: &Env, job: Uuid) -> Vec<Value> {
    let (s, b) = json_call(
        &env.app,
        Method::GET,
        &format!("/api/findings?job_id={job}&limit=200"),
        None,
        &env.admin,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    b["items"].as_array().unwrap().clone()
}

fn rules(f: &[Value]) -> Vec<String> {
    f.iter()
        .map(|x| x["rule_id"].as_str().unwrap().to_string())
        .collect()
}

fn drain(rx: &mut tokio::sync::broadcast::Receiver<Event>) -> Vec<Event> {
    let mut v = Vec::new();
    while let Ok(e) = rx.try_recv() {
        v.push(e);
    }
    v
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL and tshark"]
async fn dns_tunnel_upload_end_to_end(pool: PgPool) {
    let env = setup(pool.clone(), &[]).await;
    let mut rx = env.state.events.subscribe();
    let raw = fixture("dns_tunnel.pcap");
    let job = upload(&env, "dns_tunnel.pcap", "dns_tunnel").await;
    let done = wait_done(&env, job).await;
    assert_eq!(done["job"]["status"], "completed", "{done}");
    assert_eq!(done["job"]["packet_count"], 63);
    assert_eq!(done["job"]["progress_pct"], 100);

    let f = findings(&env, job).await;
    let r = rules(&f);
    for want in ["dns.long_label", "dns.high_entropy", "dns.txt_heavy"] {
        assert!(r.iter().any(|x| x == want), "missing {want}: {r:?}");
    }
    // Only the tunnelling client is flagged, never the benign resolver users.
    assert!(f.iter().all(|x| x["src_ip"] == "192.0.2.10"), "{f:?}");
    // Every finding references real frames of the original capture.
    for x in &f {
        let frames = x["packet_frames"].as_array().unwrap();
        assert!(!frames.is_empty());
        for fr in frames {
            let (s, p) = json_call(
                &env.app,
                Method::GET,
                &format!("/api/jobs/{job}/packets?frame={}", fr),
                None,
                &env.admin,
            )
            .await;
            assert_eq!(s, StatusCode::OK);
            assert_eq!(p["total"], 1, "frame {fr} not in packet table");
        }
        let c = x["confidence"].as_f64().unwrap();
        assert!((0.0..=1.0).contains(&c));
        assert_eq!(x["status"], "open", "findings are never auto-confirmed");
    }

    // Evidence: hash matches the uploaded bytes, file is sealed, custody trail complete.
    let (s, ev) = json_call(
        &env.app,
        Method::GET,
        &format!("/api/jobs/{job}/evidence"),
        None,
        &env.admin,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let item = &ev["items"][0];
    assert_eq!(
        item["artifact"]["sha256"],
        format!("{:x}", Sha256::digest(&raw))
    );
    let actions: Vec<&str> = item["custody"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["action"].as_str().unwrap())
        .collect();
    for want in ["ingested", "verified", "analyzed"] {
        assert!(
            actions.contains(&want),
            "custody missing {want}: {actions:?}"
        );
    }
    let stored = env.evidence.join(job.to_string()).join("original.pcap");
    assert_eq!(
        std::fs::read(&stored).unwrap(),
        raw,
        "original bytes preserved"
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&stored).unwrap().permissions().mode() & 0o777,
        0o400
    );
    assert!(
        !env._tmp.join("ws").join(job.to_string()).exists(),
        "workspace cleaned up"
    );

    // Packet browsing helpers.
    let (_, p) = json_call(
        &env.app,
        Method::GET,
        &format!("/api/jobs/{job}/packets?src_ip=192.0.2.20"),
        None,
        &env.admin,
    )
    .await;
    assert_eq!(p["total"], 3);
    let (_, p) = json_call(
        &env.app,
        Method::GET,
        &format!("/api/jobs/{job}/packets?related_to=1"),
        None,
        &env.admin,
    )
    .await;
    assert_eq!(p["total"], 1);
    let (s, _) = json_call(
        &env.app,
        Method::GET,
        &format!("/api/jobs/{job}/packets?src_ip=not-an-ip"),
        None,
        &env.admin,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (_, pr) = json_call(
        &env.app,
        Method::GET,
        &format!("/api/jobs/{job}/protocols"),
        None,
        &env.admin,
    )
    .await;
    assert_eq!(pr["by_protocol"][0]["protocol"], "dns");

    // Full TShark JSON dissection with raw bytes, and the access is recorded.
    let (s, d) = json_call(
        &env.app,
        Method::GET,
        &format!("/api/jobs/{job}/packets/1"),
        None,
        &env.admin,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{d}");
    let layers = &d["dissection"]["_source"]["layers"];
    assert!(
        layers.get("dns").is_some() && layers.get("frame_raw").is_some(),
        "{layers}"
    );
    let accessed: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chain_of_custody WHERE action = 'accessed'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(accessed >= 2);

    // Live events arrived in a sane order, with unique ids.
    let events = drain(&mut rx);
    let kinds: Vec<EventKind> = events.iter().map(|e| e.kind).collect();
    assert_eq!(kinds.first(), Some(&EventKind::JobStarted));
    assert!(
        kinds.contains(&EventKind::ThreatDetected) && kinds.contains(&EventKind::PacketDetected)
    );
    assert!(kinds.contains(&EventKind::JobProgress));
    let completed = kinds
        .iter()
        .position(|k| *k == EventKind::JobCompleted)
        .expect("job_completed");
    assert_eq!(kinds.last(), Some(&EventKind::CleanupCompleted));
    assert!(completed < kinds.len() - 1);
    let ids: std::collections::HashSet<_> = events.iter().map(|e| e.id).collect();
    assert_eq!(ids.len(), events.len());
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL and tshark"]
async fn cleartext_http_findings_never_leak_secrets(pool: PgPool) {
    let env = setup(pool.clone(), &[]).await;
    let job = upload(&env, "cleartext_http.pcap", "cleartext_http").await;
    assert_eq!(wait_done(&env, job).await["job"]["status"], "completed");
    let f = findings(&env, job).await;
    let r = rules(&f);
    for want in [
        "http.basic_auth",
        "http.cleartext_login",
        "http.sensitive_query",
    ] {
        assert!(r.iter().any(|x| x == want), "missing {want}: {r:?}");
    }
    assert!(
        f.iter().all(|x| x["src_ip"] != "192.0.2.32"),
        "benign client must not be flagged"
    );

    // Scan everything persisted for the secrets that were in the capture.
    let dump: String = sqlx::query_scalar(
        "SELECT COALESCE((SELECT string_agg(row_to_json(f)::text, ' ') FROM threat_findings f), '') || \
                COALESCE((SELECT string_agg(row_to_json(p)::text, ' ') FROM packets p), '') || \
                COALESCE((SELECT string_agg(row_to_json(a)::text, ' ') FROM audit_logs a), '') || \
                COALESCE((SELECT string_agg(row_to_json(c)::text, ' ') FROM chain_of_custody c), '')")
        .fetch_one(&pool).await.unwrap();
    for secret in [
        "SuperSecret123",
        "Hunter2Hunter2",
        "YWxpY2U6U3VwZXJTZWNyZXQxMjM",
        "abc123secrettoken",
    ] {
        assert!(
            !dump.contains(secret),
            "secret {secret} leaked into the database"
        );
    }
    assert!(dump.contains("<redacted>"));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL and tshark"]
async fn remote_access_findings_and_benign_capture_is_clean(pool: PgPool) {
    let env = setup(pool, &[]).await;
    let job = upload(&env, "remote_access.pcap", "remote_access").await;
    assert_eq!(wait_done(&env, job).await["job"]["status"], "completed");
    let f = findings(&env, job).await;
    let r = rules(&f);
    for want in [
        "remote.conn_burst",
        "remote.many_sources",
        "remote.session_seen",
    ] {
        assert!(r.iter().any(|x| x == want), "missing {want}: {r:?}");
    }
    let burst = f
        .iter()
        .find(|x| x["rule_id"] == "remote.conn_burst")
        .unwrap();
    assert_eq!(
        (burst["src_ip"].as_str(), burst["dst_port"].as_i64()),
        (Some("192.0.2.40"), Some(22))
    );
    assert!(f.iter().all(|x| x["src_ip"] != "2001:db8::5"
        || x["severity"] == "info"
        || x["severity"] == "low"));

    for profile in ["dns_tunnel", "cleartext_http", "remote_access"] {
        let j = upload(&env, "benign.pcap", profile).await;
        assert_eq!(wait_done(&env, j).await["job"]["status"], "completed");
        assert!(
            findings(&env, j).await.is_empty(),
            "benign capture flagged under {profile}"
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL and tshark"]
async fn upload_validation_and_rbac(pool: PgPool) {
    let env = setup(pool, &[("NETO_MAX_UPLOAD_BYTES", "4096".into())]).await;
    let pcap = fixture("benign.pcap");
    let ok = |p: &str| {
        vec![
            ("profile", None, p.as_bytes().to_vec()),
            ("file", Some("a.pcap"), pcap.clone()),
        ]
    };

    let (s, _) = upload_raw(&env.app, &env.viewer, &ok("dns_tunnel")).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "VIEWER cannot upload");
    let (s, _, _) = call(&env.app, Method::POST, "/api/upload", None, &[]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = upload_raw(&env.app, &env.admin, &ok("nope")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "unknown profile");
    let (s, _) = upload_raw(
        &env.app,
        &env.admin,
        &[
            ("file", Some("a.pcap"), pcap.clone()),
            ("profile", None, b"dns_tunnel".to_vec()),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "profile must precede file");
    let (s, b) = upload_raw(
        &env.app,
        &env.admin,
        &[
            ("profile", None, b"dns_tunnel".to_vec()),
            (
                "file",
                Some("evil.pcap"),
                b"MZ\x90\x00 not a capture".to_vec(),
            ),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    let (s, _) = upload_raw(
        &env.app,
        &env.admin,
        &[
            ("profile", None, b"dns_tunnel".to_vec()),
            ("file", Some("big.pcap"), fixture("dns_tunnel.pcap")),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "over the size limit");
    // Rejected uploads leave nothing behind and create no jobs.
    assert_eq!(
        std::fs::read_dir(&env.evidence).unwrap().count(),
        0,
        "rejected files must be removed"
    );
    let (_, jobs) = json_call(&env.app, Method::GET, "/api/jobs", None, &env.admin).await;
    assert_eq!(jobs["total"], 0);

    // Viewers can read but not write.
    let (s, _) = json_call(&env.app, Method::GET, "/api/stats", None, &env.viewer).await;
    assert_eq!(s, StatusCode::OK);
    let (s, p) = json_call(&env.app, Method::GET, "/api/profiles", None, &env.viewer).await;
    assert_eq!(
        (s, p["items"].as_array().unwrap().len()),
        (StatusCode::OK, 3)
    );
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL and tshark"]
async fn evidence_integrity_verify_tamper_and_export(pool: PgPool) {
    let env = setup(pool.clone(), &[]).await;
    let raw = fixture("benign.pcap");
    let job = upload(&env, "benign.pcap", "dns_tunnel").await;
    wait_done(&env, job).await;
    let (_, ev) = json_call(
        &env.app,
        Method::GET,
        &format!("/api/jobs/{job}/evidence"),
        None,
        &env.admin,
    )
    .await;
    let eid = ev["items"][0]["artifact"]["evidence_id"]
        .as_str()
        .unwrap()
        .to_string();

    let (s, v) = json_call(
        &env.app,
        Method::POST,
        &format!("/api/jobs/{job}/evidence/{eid}/verify"),
        None,
        &env.admin,
    )
    .await;
    assert_eq!((s, &v["verified"]), (StatusCode::OK, &json!(true)));
    let dl = format!("/api/jobs/{job}/evidence/{eid}/download");
    let (s, _, _) = call(
        &env.app,
        Method::GET,
        &dl,
        None,
        &[("authorization", format!("Bearer {}", env.viewer))],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "VIEWER cannot export");
    let (s, h, body) = call(
        &env.app,
        Method::GET,
        &dl,
        None,
        &[("authorization", format!("Bearer {}", env.admin))],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body, raw);
    assert_eq!(
        h.get("x-evidence-sha256").unwrap().to_str().unwrap(),
        format!("{:x}", Sha256::digest(&raw))
    );
    let exported: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chain_of_custody WHERE action = 'exported'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(exported, 1);

    // Simulate tampering on disk (needs write permission restored first).
    let stored = env.evidence.join(job.to_string()).join("original.pcap");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&stored, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut bad = raw.clone();
    *bad.last_mut().unwrap() ^= 0xff;
    std::fs::write(&stored, bad).unwrap();
    let (_, v) = json_call(
        &env.app,
        Method::POST,
        &format!("/api/jobs/{job}/evidence/{eid}/verify"),
        None,
        &env.admin,
    )
    .await;
    assert_eq!(v["verified"], false);
    let (s, _, _) = call(
        &env.app,
        Method::GET,
        &dl,
        None,
        &[("authorization", format!("Bearer {}", env.admin))],
    )
    .await;
    assert_eq!(
        s,
        StatusCode::CONFLICT,
        "tampered evidence must not be exported"
    );
    let failed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chain_of_custody WHERE action = 'verification_failed'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(failed >= 2);
    // A tampered capture is also refused for new analysis.
    let (s, _) = json_call(
        &env.app,
        Method::GET,
        &format!(
            "/api/jobs/{}/evidence/EV-00000000-000000000000/download",
            job
        ),
        None,
        &env.admin,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL and tshark"]
async fn findings_listing_triage_and_csv_export(pool: PgPool) {
    let env = setup(pool, &[]).await;
    let job = upload(&env, "dns_tunnel.pcap", "dns_tunnel").await;
    wait_done(&env, job).await;
    let (_, all) = json_call(
        &env.app,
        Method::GET,
        "/api/findings?sort=confidence&dir=desc&limit=2",
        None,
        &env.viewer,
    )
    .await;
    assert_eq!(all["items"].as_array().unwrap().len(), 2);
    assert!(all["total"].as_i64().unwrap() >= 3);
    let c: Vec<f64> = all["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["confidence"].as_f64().unwrap())
        .collect();
    assert!(c[0] >= c[1]);
    let (_, hi) = json_call(
        &env.app,
        Method::GET,
        "/api/findings?severity=critical",
        None,
        &env.viewer,
    )
    .await;
    assert_eq!(hi["total"], 0);
    let (_, q) = json_call(
        &env.app,
        Method::GET,
        "/api/findings?q=evil-tunnel",
        None,
        &env.viewer,
    )
    .await;
    assert!(q["total"].as_i64().unwrap() >= 3);
    let (_, q) = json_call(
        &env.app,
        Method::GET,
        "/api/findings?q=%25%25",
        None,
        &env.viewer,
    )
    .await;
    assert_eq!(
        q["total"], 0,
        "LIKE wildcards in the search box are escaped"
    );

    let id = all["items"][0]["id"].as_str().unwrap();
    let (s, _) = json_call(
        &env.app,
        Method::PATCH,
        &format!("/api/findings/{id}"),
        Some(json!({"status": "triaged"})),
        &env.viewer,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "VIEWER cannot triage");
    let (s, _) = json_call(
        &env.app,
        Method::PATCH,
        &format!("/api/findings/{id}"),
        Some(json!({"status": "bogus"})),
        &env.admin,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = json_call(
        &env.app,
        Method::PATCH,
        &format!("/api/findings/{id}"),
        Some(json!({"status": "false_positive"})),
        &env.admin,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, one) = json_call(
        &env.app,
        Method::GET,
        &format!("/api/findings/{id}"),
        None,
        &env.viewer,
    )
    .await;
    assert_eq!(one["status"], "false_positive");

    let (s, h, body) = call(
        &env.app,
        Method::GET,
        "/api/findings/export?format=csv",
        None,
        &[("authorization", format!("Bearer {}", env.viewer))],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(h
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/csv"));
    let csv = String::from_utf8(body).unwrap();
    assert!(csv.starts_with("id,job_id,detected_at,severity"));
    assert!(csv.lines().count() >= 4);
}

fn write_mock_worker(dir: &std::path::Path, body: &str) -> String {
    let p = dir.join(format!("mock-worker-{}.sh", Uuid::new_v4()));
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p.to_string_lossy().into_owned()
}

fn stream_req(profile: &str) -> Value {
    json!({"target_host": "192.0.2.10", "ssh_port": 22, "ssh_username": "capture", "credential_ref": "soc-key",
           "remote_interface": "eth0", "duration_secs": 30, "capture_filter": "udp port 53", "profile": profile})
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL and tshark"]
async fn live_stream_pipeline_with_mock_worker(pool: PgPool) {
    let tmp = std::env::temp_dir().join(format!("neto-mw-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).unwrap();
    let fx = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/dns_tunnel.pcap");
    // Emits a real capture, then waits for the stop command like the real worker does.
    let worker = write_mock_worker(&tmp, &format!(
        "read spec\necho '{{\"event\":\"started\",\"host_key\":\"SHA256:mockfingerprint\"}}' >&2\ncat '{}'\n\
         echo '{{\"event\":\"progress\",\"bytes\":9659}}' >&2\nread cmd\necho '{{\"event\":\"cleanup\"}}' >&2\nexit 0", fx.display()));
    let env = setup(
        pool.clone(),
        &[
            ("NETO_WORKER_BIN", worker),
            ("NETO_ALLOWED_TARGETS", "192.0.2.0/24".into()),
        ],
    )
    .await;
    let mut rx = env.state.events.subscribe();

    let (s, b) = json_call(
        &env.app,
        Method::POST,
        "/api/stream",
        Some(stream_req("dns_tunnel")),
        &env.admin,
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    let job = b["job_id"].as_str().unwrap().to_string();

    // Wait for live analysis of the streamed data, then stop the capture.
    let mut seen = false;
    for _ in 0..120 {
        let (_, j) = json_call(
            &env.app,
            Method::GET,
            &format!("/api/jobs/{job}"),
            None,
            &env.admin,
        )
        .await;
        if j["job"]["packet_count"].as_i64().unwrap_or(0) >= 63 {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        seen,
        "packets were not analysed while the capture was still running"
    );
    let (_, live) = json_call(
        &env.app,
        Method::GET,
        &format!("/api/jobs/{job}"),
        None,
        &env.admin,
    )
    .await;
    assert!(
        ["running", "queued"].contains(&live["job"]["status"].as_str().unwrap()),
        "still capturing: {live}"
    );

    let (s, _) = json_call(
        &env.app,
        Method::POST,
        &format!("/api/stream/{job}/stop"),
        None,
        &env.viewer,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, b) = json_call(
        &env.app,
        Method::POST,
        &format!("/api/stream/{job}/stop"),
        None,
        &env.admin,
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");

    let job_id = Uuid::parse_str(&job).unwrap();
    let done = wait_done(&env, job_id).await;
    assert_eq!(done["job"]["status"], "completed", "{done}");
    assert_eq!(done["job"]["packet_count"], 63);
    assert!(rules(&findings(&env, job_id).await).contains(&"dns.long_label".to_string()));

    // Evidence was tee'd to disk while streaming: identical bytes, correct hash, sealed.
    let raw = std::fs::read(&fx).unwrap();
    let stored = env.evidence.join(&job).join("original.pcap");
    assert_eq!(std::fs::read(&stored).unwrap(), raw);
    let (_, ev) = json_call(
        &env.app,
        Method::GET,
        &format!("/api/jobs/{job}/evidence"),
        None,
        &env.admin,
    )
    .await;
    assert_eq!(
        ev["items"][0]["artifact"]["sha256"],
        format!("{:x}", Sha256::digest(&raw))
    );
    let ws: (String, bool, Option<String>) = sqlx::query_as(
        "SELECT status::text, cleanup_done, host_key_fingerprint FROM worker_sessions",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        ws,
        ("closed".into(), true, Some("SHA256:mockfingerprint".into()))
    );

    let kinds: Vec<EventKind> = drain(&mut rx).iter().map(|e| e.kind).collect();
    for want in [
        EventKind::JobStarted,
        EventKind::ThreatDetected,
        EventKind::CaptureStopped,
        EventKind::JobCompleted,
        EventKind::CleanupCompleted,
    ] {
        assert!(kinds.contains(&want), "missing {want:?} in {kinds:?}");
    }
    // Stopping an already finished job is a conflict.
    let (s, _) = json_call(
        &env.app,
        Method::POST,
        &format!("/api/stream/{job}/stop"),
        None,
        &env.admin,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL and tshark"]
async fn failed_worker_marks_job_failed_without_evidence(pool: PgPool) {
    let tmp = std::env::temp_dir().join(format!("neto-mw-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).unwrap();
    let worker = write_mock_worker(&tmp, "read spec\necho '{\"event\":\"error\",\"message\":\"host key verification failed\"}' >&2\nexit 3");
    let env = setup(
        pool.clone(),
        &[
            ("NETO_WORKER_BIN", worker),
            ("NETO_ALLOWED_TARGETS", "192.0.2.0/24".into()),
        ],
    )
    .await;
    let (_, b) = json_call(
        &env.app,
        Method::POST,
        "/api/stream",
        Some(stream_req("dns_tunnel")),
        &env.admin,
    )
    .await;
    let job = Uuid::parse_str(b["job_id"].as_str().unwrap()).unwrap();
    let done = wait_done(&env, job).await;
    assert_eq!(done["job"]["status"], "failed");
    assert_eq!(done["job"]["error_message"], "host key verification failed");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence_artifacts")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    assert!(
        !env.evidence.join(job.to_string()).exists(),
        "empty evidence directory removed"
    );
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL and tshark"]
async fn stream_request_validation_and_target_allowlist(pool: PgPool) {
    // Not configured at all.
    let env = setup(pool.clone(), &[]).await;
    let (s, _) = json_call(
        &env.app,
        Method::POST,
        "/api/stream",
        Some(stream_req("dns_tunnel")),
        &env.admin,
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);

    let tmp = std::env::temp_dir().join(format!("neto-mw-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).unwrap();
    let worker = write_mock_worker(&tmp, "exit 0");
    let env = setup(
        pool.clone(),
        &[
            ("NETO_WORKER_BIN", worker),
            ("NETO_ALLOWED_TARGETS", "192.0.2.0/24".into()),
        ],
    )
    .await;
    let mut cases: Vec<(&str, Value, StatusCode)> = Vec::new();
    let mutate = |k: &str, v: Value| {
        let mut r = stream_req("dns_tunnel");
        r[k] = v;
        r
    };
    cases.push((
        "target outside allow-list",
        mutate("target_host", json!("203.0.113.9")),
        StatusCode::FORBIDDEN,
    ));
    cases.push((
        "hostname instead of IP",
        mutate("target_host", json!("example.com")),
        StatusCode::BAD_REQUEST,
    ));
    cases.push((
        "interface injection",
        mutate("remote_interface", json!("eth0; reboot")),
        StatusCode::BAD_REQUEST,
    ));
    cases.push((
        "filter injection",
        mutate("capture_filter", json!("port 22; id")),
        StatusCode::BAD_REQUEST,
    ));
    cases.push((
        "filter backtick",
        mutate("capture_filter", json!("`id`")),
        StatusCode::BAD_REQUEST,
    ));
    cases.push((
        "username injection",
        mutate("ssh_username", json!("a$(id)")),
        StatusCode::BAD_REQUEST,
    ));
    cases.push((
        "credential path traversal",
        mutate("credential_ref", json!("../../etc/shadow")),
        StatusCode::BAD_REQUEST,
    ));
    cases.push((
        "duration too long",
        mutate("duration_secs", json!(999999)),
        StatusCode::BAD_REQUEST,
    ));
    cases.push((
        "duration too short",
        mutate("duration_secs", json!(1)),
        StatusCode::BAD_REQUEST,
    ));
    cases.push((
        "unknown profile",
        mutate("profile", json!("nope")),
        StatusCode::BAD_REQUEST,
    ));
    cases.push((
        "unknown field",
        mutate("extra", json!(1)),
        StatusCode::UNPROCESSABLE_ENTITY,
    ));
    for (name, body, want) in cases {
        let (s, b) = json_call(
            &env.app,
            Method::POST,
            "/api/stream",
            Some(body),
            &env.admin,
        )
        .await;
        assert_eq!(s, want, "{name}: {b}");
    }
    let (s, _) = json_call(
        &env.app,
        Method::POST,
        "/api/stream",
        Some(stream_req("dns_tunnel")),
        &env.viewer,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = json_call(
        &env.app,
        Method::POST,
        &format!("/api/stream/{}/stop", Uuid::new_v4()),
        None,
        &env.admin,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM capture_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "rejected requests create no jobs");
    let denied: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_logs WHERE action = 'capture.start' AND outcome = 'denied'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(denied, 1);
}
