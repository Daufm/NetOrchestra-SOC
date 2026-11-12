//! Schema integration tests. They need a live PostgreSQL and are `#[ignore]`d so that
//! `cargo test` works without one. Run with:
//!
//!   DATABASE_URL=postgres://user:pass@localhost/postgres cargo test --test db_schema -- --ignored
//!
//! `#[sqlx::test]` creates a throwaway database per test and applies ./migrations to it,
//! so the role in DATABASE_URL needs CREATEDB.
use sqlx::{types::Uuid, PgPool};

async fn user(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, role_id) \
         VALUES ($1, '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA', 3) RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("insert user")
}

async fn upload_job(pool: &PgPool, user_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO capture_jobs (created_by, mode, profile_id, original_filename) \
         VALUES ($1, 'upload', 'dns_tunnel', 'a.pcap') RETURNING id",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("insert job")
}

async fn artifact(pool: &PgPool, job_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO evidence_artifacts (evidence_id, job_id, kind, storage_path, size_bytes, sha256) \
         VALUES ('EV-20260101-ABCDEF012345', $1, 'pcap', 'jobs/x/a.pcap', 10, $2) RETURNING id",
    )
    .bind(job_id)
    .bind(vec![7u8; 32])
    .fetch_one(pool)
    .await
    .expect("insert artifact")
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn seed_data_is_present(pool: PgPool) {
    let roles: i64 = sqlx::query_scalar("SELECT count(*) FROM roles")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(roles, 3);
    let profiles: Vec<String> = sqlx::query_scalar("SELECT id FROM detection_profiles ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(profiles, ["cleartext_http", "dns_tunnel", "remote_access"]);
    let viewer_perms: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id = rp.role_id WHERE r.name = 'VIEWER'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(viewer_perms, 3);
    let viewer_can_export: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id = rp.role_id \
         JOIN permissions p ON p.id = rp.permission_id \
         WHERE r.name = 'VIEWER' AND p.code IN ('evidence:export', 'jobs:create')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(viewer_can_export, 0, "VIEWER must be read-only");
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn usernames_are_case_insensitively_unique(pool: PgPool) {
    user(&pool, "Alice").await;
    let dup = sqlx::query(
        "INSERT INTO users (username, password_hash, role_id) VALUES ('alice', '$argon2id$x', 3)",
    )
    .execute(&pool)
    .await;
    assert!(dup.is_err());
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn non_argon2_password_hashes_are_rejected(pool: PgPool) {
    let r = sqlx::query(
        "INSERT INTO users (username, password_hash, role_id) VALUES ('bob', 'plaintext', 3)",
    )
    .execute(&pool)
    .await;
    assert!(r.is_err());
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn refresh_token_hash_must_be_sha256_length(pool: PgPool) {
    let uid = user(&pool, "carol").await;
    let bad = sqlx::query(
        "INSERT INTO refresh_sessions (user_id, family_id, token_hash, expires_at) \
         VALUES ($1, gen_random_uuid(), $2, now() + interval '7 days')",
    )
    .bind(uid)
    .bind(vec![1u8; 16])
    .execute(&pool)
    .await;
    assert!(bad.is_err());
    let good = sqlx::query(
        "INSERT INTO refresh_sessions (user_id, family_id, token_hash, expires_at) \
         VALUES ($1, gen_random_uuid(), $2, now() + interval '7 days')",
    )
    .bind(uid)
    .bind(vec![1u8; 32])
    .execute(&pool)
    .await;
    assert!(good.is_ok());
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn stream_jobs_require_target_parameters(pool: PgPool) {
    let uid = user(&pool, "dave").await;
    let r = sqlx::query(
        "INSERT INTO capture_jobs (created_by, mode, profile_id) VALUES ($1, 'stream', 'dns_tunnel')",
    )
    .bind(uid)
    .execute(&pool)
    .await;
    assert!(r.is_err());
    let ok = sqlx::query(
        "INSERT INTO capture_jobs (created_by, mode, profile_id, target_host, ssh_port, ssh_username, \
         remote_interface, duration_secs) \
         VALUES ($1, 'stream', 'dns_tunnel', '192.0.2.10', 22, 'cap', 'eth0', 60)",
    )
    .bind(uid)
    .execute(&pool)
    .await;
    assert!(ok.is_ok(), "{ok:?}");
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn remote_interface_rejects_shell_metacharacters(pool: PgPool) {
    let uid = user(&pool, "erin").await;
    let r = sqlx::query(
        "INSERT INTO capture_jobs (created_by, mode, profile_id, target_host, ssh_port, ssh_username, \
         remote_interface, duration_secs) \
         VALUES ($1, 'stream', 'dns_tunnel', '192.0.2.10', 22, 'cap', 'eth0; rm -rf /', 60)",
    )
    .bind(uid)
    .execute(&pool)
    .await;
    assert!(r.is_err());
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn packets_are_unique_per_job_and_frame(pool: PgPool) {
    let uid = user(&pool, "frank").await;
    let job = upload_job(&pool, uid).await;
    let ins = "INSERT INTO packets (job_id, frame_number, captured_at, frame_length, src_ip, dst_ip, ip_version, transport) \
               VALUES ($1, 1, now(), 60, '10.0.0.1', '2001:db8::1', 4, 'udp')";
    sqlx::query(ins).bind(job).execute(&pool).await.unwrap();
    assert!(sqlx::query(ins).bind(job).execute(&pool).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn findings_need_packet_refs_and_valid_confidence(pool: PgPool) {
    let uid = user(&pool, "gina").await;
    let job = upload_job(&pool, uid).await;
    let base = "INSERT INTO threat_findings (job_id, profile_id, rule_id, severity, confidence, title, explanation, packet_frames, detected_at) \
                VALUES ($1, 'dns_tunnel', 'r1', 'high', $2, 't', 'e', $3, now())";
    let no_refs = sqlx::query(base)
        .bind(job)
        .bind(0.8f64)
        .bind(Vec::<i64>::new())
        .execute(&pool)
        .await;
    assert!(no_refs.is_err(), "finding without packet refs must fail");
    let bad_conf = sqlx::query(base)
        .bind(job)
        .bind(1.5f64)
        .bind(vec![1i64])
        .execute(&pool)
        .await;
    assert!(bad_conf.is_err(), "confidence > 1 must fail");
    let ok = sqlx::query(base)
        .bind(job)
        .bind(0.8f64)
        .bind(vec![1i64, 2])
        .execute(&pool)
        .await;
    assert!(ok.is_ok(), "{ok:?}");
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn evidence_is_immutable_and_custody_is_append_only(pool: PgPool) {
    let uid = user(&pool, "hana").await;
    let job = upload_job(&pool, uid).await;
    let art = artifact(&pool, job).await;

    let upd = sqlx::query("UPDATE evidence_artifacts SET size_bytes = 11 WHERE id = $1")
        .bind(art)
        .execute(&pool)
        .await;
    assert!(upd.unwrap_err().to_string().contains("immutable"));
    let del = sqlx::query("DELETE FROM evidence_artifacts WHERE id = $1")
        .bind(art)
        .execute(&pool)
        .await;
    assert!(del.is_err());

    sqlx::query(
        "INSERT INTO chain_of_custody (artifact_id, action, actor_id, actor_label) VALUES ($1, 'ingested', $2, 'hana')",
    )
    .bind(art)
    .bind(uid)
    .execute(&pool)
    .await
    .unwrap();
    let upd = sqlx::query("UPDATE chain_of_custody SET actor_label = 'x'")
        .execute(&pool)
        .await;
    assert!(upd.unwrap_err().to_string().contains("append-only"));
    assert!(sqlx::query("DELETE FROM chain_of_custody")
        .execute(&pool)
        .await
        .is_err());

    sqlx::query(
        "INSERT INTO evidence_hashes (artifact_id, digest, matches_original) VALUES ($1, $2, true)",
    )
    .bind(art)
    .bind(vec![7u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    assert!(sqlx::query("DELETE FROM evidence_hashes")
        .execute(&pool)
        .await
        .is_err());
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn audit_log_is_append_only(pool: PgPool) {
    sqlx::query("INSERT INTO audit_logs (action, outcome) VALUES ('auth.login', 'success')")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query("UPDATE audit_logs SET outcome = 'failure'")
        .execute(&pool)
        .await
        .is_err());
    assert!(sqlx::query("DELETE FROM audit_logs")
        .execute(&pool)
        .await
        .is_err());
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn evidence_cannot_be_orphaned_by_job_deletion(pool: PgPool) {
    let uid = user(&pool, "ivan").await;
    let job = upload_job(&pool, uid).await;
    artifact(&pool, job).await;
    let del = sqlx::query("DELETE FROM capture_jobs WHERE id = $1")
        .bind(job)
        .execute(&pool)
        .await;
    assert!(del.is_err(), "jobs with evidence must not be deletable");
}
