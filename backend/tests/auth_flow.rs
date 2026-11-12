//! End-to-end authentication tests against a real PostgreSQL (driving the real router).
//! `#[ignore]`d so plain `cargo test` needs no database. Run with:
//!   DATABASE_URL=postgres://user:pass@localhost/postgres cargo test --test auth_flow -- --ignored
use std::collections::HashMap;

use axum::{
    body::Body,
    http::{header, HeaderMap, Method, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use netorchestra_backend::{
    auth::{jwt::JwtKeys, tokens::sha256},
    config::Config,
    routes,
    state::AppState,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const SECRET: &str = "0123456789abcdef0123456789abcdef0123";
const BOOT: &str = "bootstrap-token-0123456789abcdef";
const ORIGIN: &str = "http://localhost:5173";
const PW: &str = "correct-horse-battery-1";

fn app(pool: PgPool, extra: &[(&str, &str)]) -> Router {
    let mut m: HashMap<String, String> = HashMap::from([
        ("DATABASE_URL".into(), "postgres://x:y@h/db".into()),
        ("NETO_JWT_SECRET".into(), SECRET.into()),
        ("NETO_BOOTSTRAP_TOKEN".into(), BOOT.into()),
        ("NETO_CORS_ORIGINS".into(), ORIGIN.into()),
    ]);
    for (k, v) in extra {
        m.insert(k.to_string(), v.to_string());
    }
    let cfg = Config::from_lookup(|k| m.get(k).cloned()).unwrap();
    routes::router(AppState::new(pool, cfg).unwrap())
}

async fn call(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
    headers: &[(&str, String)],
) -> (StatusCode, HeaderMap, Value) {
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
    let (status, headers) = (res.status(), res.headers().clone());
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, json)
}

fn bearer(t: &str) -> (&'static str, String) {
    ("authorization", format!("Bearer {t}"))
}

fn set_cookie(h: &HeaderMap, name: &str) -> Option<String> {
    h.get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{name}=")))
        .map(str::to_string)
}

fn cookie_value(h: &HeaderMap, name: &str) -> String {
    let c = set_cookie(h, name).unwrap_or_else(|| panic!("no {name} cookie"));
    c[name.len() + 1..].split(';').next().unwrap().to_string()
}

struct Session {
    access: String,
    refresh: String,
    csrf: String,
}

async fn register_admin(app: &Router, name: &str) {
    let (s, _, _) = call(
        app,
        Method::POST,
        "/api/auth/register",
        Some(json!({"username": name, "password": PW})),
        &[("x-bootstrap-token", BOOT.to_string())],
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
}

async fn login(app: &Router, name: &str, pw: &str) -> Session {
    let (s, h, b) = call(
        app,
        Method::POST,
        "/api/auth/login",
        Some(json!({"username": name, "password": pw})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "login failed: {b}");
    Session {
        access: b["access_token"].as_str().unwrap().to_string(),
        refresh: cookie_value(&h, "neto_refresh"),
        csrf: cookie_value(&h, "neto_csrf"),
    }
}

fn refresh_headers(refresh: &str, csrf: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            "cookie",
            format!("neto_refresh={refresh}; neto_csrf={csrf}"),
        ),
        ("x-csrf-token", csrf.to_string()),
        ("origin", ORIGIN.to_string()),
    ]
}

async fn do_refresh(app: &Router, refresh: &str, csrf: &str) -> (StatusCode, HeaderMap, Value) {
    call(
        app,
        Method::POST,
        "/api/auth/refresh",
        None,
        &refresh_headers(refresh, csrf),
    )
    .await
}

async fn me_status(app: &Router, access: &str) -> StatusCode {
    call(app, Method::GET, "/api/auth/me", None, &[bearer(access)])
        .await
        .0
}

/// Admin + a viewer created through public registration (enabled for these tests).
async fn admin_and_viewer(pool: PgPool) -> (Router, Session, Session) {
    let app = app(pool, &[("NETO_ALLOW_REGISTRATION", "true")]);
    register_admin(&app, "admin").await;
    let (s, _, b) = call(
        &app,
        Method::POST,
        "/api/auth/register",
        Some(json!({"username": "viewer1", "password": PW, "email": "v@example.com"})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(
        b["role"], "VIEWER",
        "public registration must only create VIEWER"
    );
    let a = login(&app, "admin", PW).await;
    let v = login(&app, "viewer1", PW).await;
    (app, a, v)
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn bootstrap_and_registration_policy(pool: PgPool) {
    let app = app(pool, &[]);
    let body = json!({"username": "admin", "password": PW});

    // Before any user is registered, auth status reports bootstrap mode.
    let (s, _, b) = call(&app, Method::GET, "/api/auth/status", None, &[]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["has_users"], false);
    assert_eq!(b["bootstrap_mode"], true);
    assert_eq!(b["allow_registration"], true);

    // First user: bootstrap token required.
    let (s, _, _) = call(
        &app,
        Method::POST,
        "/api/auth/register",
        Some(body.clone()),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = call(
        &app,
        Method::POST,
        "/api/auth/register",
        Some(body.clone()),
        &[(
            "x-bootstrap-token",
            "wrong-token-wrong-token-wrong".to_string(),
        )],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, b) = call(
        &app,
        Method::POST,
        "/api/auth/register",
        Some(body),
        &[("x-bootstrap-token", BOOT.to_string())],
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(b["role"], "ADMIN");

    // Once an admin is created, auth status reports has_users=true and bootstrap_mode=false.
    let (s, _, b) = call(&app, Method::GET, "/api/auth/status", None, &[]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["has_users"], true);
    assert_eq!(b["bootstrap_mode"], false);
    assert_eq!(b["allow_registration"], false);

    // Registration is disabled by default once an admin exists, bootstrap token or not.
    let (s, _, _) = call(
        &app,
        Method::POST,
        "/api/auth/register",
        Some(json!({"username": "second", "password": PW})),
        &[("x-bootstrap-token", BOOT.to_string())],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Weak password / bad username are rejected up front.
    let app2 = self::app(
        sqlx::PgPool::connect_lazy("postgres://x:y@127.0.0.1:1/z").unwrap(),
        &[],
    );
    let (s, _, _) = call(
        &app2,
        Method::POST,
        "/api/auth/register",
        Some(json!({"username": "ab", "password": PW})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn login_me_cookies_and_token_validation(pool: PgPool) {
    let app = app(pool, &[]);
    register_admin(&app, "admin").await;

    // Unknown user and wrong password are indistinguishable.
    let (s1, _, b1) = call(
        &app,
        Method::POST,
        "/api/auth/login",
        Some(json!({"username": "nobody", "password": "whatever-whatever"})),
        &[],
    )
    .await;
    let (s2, _, b2) = call(
        &app,
        Method::POST,
        "/api/auth/login",
        Some(json!({"username": "admin", "password": "wrong-password-123"})),
        &[],
    )
    .await;
    assert_eq!(
        (s1, s2),
        (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED)
    );
    assert_eq!(b1, b2);

    let (s, h, b) = call(
        &app,
        Method::POST,
        "/api/auth/login",
        Some(json!({"username": "ADMIN", "password": PW})),
        &[],
    )
    .await; // case-insensitive username
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["token_type"], "Bearer");
    assert_eq!(b["expires_in"], 900);
    assert!(b["user"].get("password_hash").is_none());

    let rc = set_cookie(&h, "neto_refresh").unwrap();
    for attr in ["HttpOnly", "SameSite=Strict", "Path=/api/auth", "Secure"] {
        assert!(rc.contains(attr), "refresh cookie missing {attr}: {rc}");
    }
    assert_eq!(h.get("cache-control").unwrap(), "no-store");
    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");

    let access = b["access_token"].as_str().unwrap();
    let (s, _, me) = call(&app, Method::GET, "/api/auth/me", None, &[bearer(access)]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me["role"], "ADMIN");
    assert!(me["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p == "users:manage"));

    // No / malformed / foreign tokens.
    assert_eq!(
        call(&app, Method::GET, "/api/auth/me", None, &[]).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(me_status(&app, "not.a.jwt").await, StatusCode::UNAUTHORIZED);
    let forged = JwtKeys::new(
        b"ffffffffffffffffffffffffffffffffffff",
        "netorchestra",
        "netorchestra-api",
    )
    .issue(Uuid::new_v4(), "ADMIN", Uuid::new_v4(), 900)
    .unwrap()
    .0;
    assert_eq!(me_status(&app, &forged).await, StatusCode::UNAUTHORIZED);

    // Correctly signed but for a session/user that does not exist.
    let ghost = JwtKeys::new(SECRET.as_bytes(), "netorchestra", "netorchestra-api")
        .issue(Uuid::new_v4(), "ADMIN", Uuid::new_v4(), 900)
        .unwrap()
        .0;
    assert_eq!(me_status(&app, &ghost).await, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn refresh_rotation_and_reuse_detection(pool: PgPool) {
    let app = app(pool.clone(), &[]);
    register_admin(&app, "admin").await;
    let s1 = login(&app, "admin", PW).await;

    // Rotation issues a new refresh token and a working access token.
    let (st, h, b) = do_refresh(&app, &s1.refresh, &s1.csrf).await;
    assert_eq!(st, StatusCode::OK);
    let r2 = cookie_value(&h, "neto_refresh");
    let c2 = cookie_value(&h, "neto_csrf");
    assert_ne!(r2, s1.refresh);
    let access2 = b["access_token"].as_str().unwrap().to_string();
    assert_eq!(me_status(&app, &access2).await, StatusCode::OK);

    // Only the SHA-256 digest is stored, never the token.
    let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT token_hash FROM refresh_sessions")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(stored.contains(&sha256(&r2)));
    assert!(stored.iter().all(|h| h.len() == 32 && h != r2.as_bytes()));

    // Replaying the rotated-out token is reuse: rejected AND the whole family is revoked.
    let (st, h, _) = do_refresh(&app, &s1.refresh, &s1.csrf).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert!(
        set_cookie(&h, "neto_refresh")
            .unwrap()
            .contains("Max-Age=0"),
        "failed refresh clears cookie"
    );
    let (st, _, _) = do_refresh(&app, &r2, &c2).await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "legit descendant token must die with the family"
    );
    assert_eq!(
        me_status(&app, &access2).await,
        StatusCode::UNAUTHORIZED,
        "access token of revoked family is rejected immediately"
    );

    let reuse_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_logs WHERE action = 'auth.refresh_reuse_detected'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(reuse_audits, 1);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn refresh_requires_csrf_and_allowed_origin(pool: PgPool) {
    let app = app(pool, &[]);
    register_admin(&app, "admin").await;
    let s = login(&app, "admin", PW).await;
    let uri = "/api/auth/refresh";

    // Cookie only, no CSRF header.
    let (st, _, _) = call(
        &app,
        Method::POST,
        uri,
        None,
        &[(
            "cookie",
            format!("neto_refresh={}; neto_csrf={}", s.refresh, s.csrf),
        )],
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    // Mismatched CSRF header.
    let mut h = refresh_headers(&s.refresh, &s.csrf);
    h[1] = ("x-csrf-token", "x".repeat(43));
    assert_eq!(
        call(&app, Method::POST, uri, None, &h).await.0,
        StatusCode::FORBIDDEN
    );
    // Disallowed Origin.
    let mut h = refresh_headers(&s.refresh, &s.csrf);
    h[2] = ("origin", "https://evil.example".to_string());
    assert_eq!(
        call(&app, Method::POST, uri, None, &h).await.0,
        StatusCode::FORBIDDEN
    );
    // No cookie at all.
    assert_eq!(
        call(&app, Method::POST, uri, None, &[]).await.0,
        StatusCode::UNAUTHORIZED
    );
    // The legitimate request still works (CSRF failures must not have burned the token).
    assert_eq!(
        do_refresh(&app, &s.refresh, &s.csrf).await.0,
        StatusCode::OK
    );

    // Logout is CSRF-protected too.
    let s = login(&app, "admin", PW).await;
    let (st, _, _) = call(
        &app,
        Method::POST,
        "/api/auth/logout",
        None,
        &[("cookie", format!("neto_refresh={}", s.refresh))],
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn account_lockout_after_repeated_failures(pool: PgPool) {
    let app = app(pool, &[]);
    register_admin(&app, "admin").await;
    for _ in 0..5 {
        let (s, _, _) = call(
            &app,
            Method::POST,
            "/api/auth/login",
            Some(json!({"username": "admin", "password": "wrong-password-123"})),
            &[],
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    // Locked: even the correct password is refused, with Retry-After.
    let (s, h, _) = call(
        &app,
        Method::POST,
        "/api/auth/login",
        Some(json!({"username": "admin", "password": PW})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = h
        .get("retry-after")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry > 0 && retry <= 900);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn rbac_and_admin_password_reset(pool: PgPool) {
    let (app, admin, viewer) = admin_and_viewer(pool.clone()).await;
    let viewer_id: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = 'viewer1'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let new_pw = "brand-new-viewer-password-9";
    let body = json!({"user_id": viewer_id, "new_password": new_pw});

    // VIEWER lacks users:manage.
    let (s, _, _) = call(
        &app,
        Method::POST,
        "/api/auth/admin/reset-password",
        Some(body.clone()),
        &[bearer(&viewer.access)],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Unauthenticated.
    let (s, _, _) = call(
        &app,
        Method::POST,
        "/api/auth/admin/reset-password",
        Some(body.clone()),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Unknown target.
    let (s, _, _) = call(
        &app,
        Method::POST,
        "/api/auth/admin/reset-password",
        Some(json!({"user_id": Uuid::new_v4(), "new_password": new_pw})),
        &[bearer(&admin.access)],
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // ADMIN succeeds; the viewer's existing sessions die immediately.
    let (s, _, _) = call(
        &app,
        Method::POST,
        "/api/auth/admin/reset-password",
        Some(body),
        &[bearer(&admin.access)],
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        me_status(&app, &viewer.access).await,
        StatusCode::UNAUTHORIZED
    );
    let (s, _, _) = call(
        &app,
        Method::POST,
        "/api/auth/login",
        Some(json!({"username": "viewer1", "password": PW})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "old password no longer works");

    // New password works but the account is flagged: only /api/auth/* is usable until changed.
    let v2 = login(&app, "viewer1", new_pw).await;
    assert_eq!(me_status(&app, &v2.access).await, StatusCode::OK);
    let (s, _, b) = call(
        &app,
        Method::GET,
        "/api/health",
        None,
        &[bearer(&v2.access)],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}"); // public route unaffected

    // Audit trail captured the denial and the success.
    let actions: Vec<(String, String)> = sqlx::query_as(
        "SELECT action, outcome FROM audit_logs WHERE action = 'auth.admin_reset_password' ORDER BY id")
        .fetch_all(&pool).await.unwrap();
    assert!(actions.contains(&("auth.admin_reset_password".into(), "denied".into())));
    assert!(actions.contains(&("auth.admin_reset_password".into(), "success".into())));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn change_password_revokes_all_sessions(pool: PgPool) {
    let app = app(pool, &[]);
    register_admin(&app, "admin").await;
    let s1 = login(&app, "admin", PW).await;
    let s2 = login(&app, "admin", PW).await;
    let uri = "/api/auth/change-password";
    let new_pw = "another-strong-password-7";

    // Wrong current password.
    let (s, _, _) = call(
        &app,
        Method::POST,
        uri,
        Some(json!({"current_password": "nope-nope-nope-1", "new_password": new_pw})),
        &[bearer(&s1.access)],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Weak new password.
    let (s, _, _) = call(
        &app,
        Method::POST,
        uri,
        Some(json!({"current_password": PW, "new_password": "short"})),
        &[bearer(&s1.access)],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // Success.
    let (s, _, _) = call(
        &app,
        Method::POST,
        uri,
        Some(json!({"current_password": PW, "new_password": new_pw})),
        &[bearer(&s1.access)],
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    assert_eq!(me_status(&app, &s1.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(me_status(&app, &s2.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        do_refresh(&app, &s2.refresh, &s2.csrf).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (s, _, _) = call(
        &app,
        Method::POST,
        "/api/auth/login",
        Some(json!({"username": "admin", "password": PW})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let s3 = login(&app, "admin", new_pw).await;
    assert_eq!(me_status(&app, &s3.access).await, StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn logout_logout_all_and_session_management(pool: PgPool) {
    let (app, admin, viewer) = admin_and_viewer(pool).await;

    // Session listing: current flag, and visibility limited to own sessions.
    let admin2 = login(&app, "admin", PW).await;
    let (s, _, list) = call(
        &app,
        Method::GET,
        "/api/auth/sessions",
        None,
        &[bearer(&admin.access)],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list.iter().filter(|x| x["current"] == true).count(), 1);
    let other = list.iter().find(|x| x["current"] == false).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    // A viewer cannot revoke an admin session (indistinguishable from nonexistent).
    let (s, _, _) = call(
        &app,
        Method::DELETE,
        &format!("/api/auth/sessions/{other}"),
        None,
        &[bearer(&viewer.access)],
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(
        call(
            &app,
            Method::DELETE,
            "/api/auth/sessions/not-a-uuid",
            None,
            &[bearer(&viewer.access)]
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );

    // The owner can; the targeted session dies, the other survives.
    let (s, _, _) = call(
        &app,
        Method::DELETE,
        &format!("/api/auth/sessions/{other}"),
        None,
        &[bearer(&admin.access)],
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        me_status(&app, &admin2.access).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(me_status(&app, &admin.access).await, StatusCode::OK);

    // An ADMIN (sessions:manage_all) can revoke another user's session.
    let (_, _, vlist) = call(
        &app,
        Method::GET,
        "/api/auth/sessions",
        None,
        &[bearer(&viewer.access)],
    )
    .await;
    let vsid = vlist[0]["session_id"].as_str().unwrap().to_string();
    let (s, _, _) = call(
        &app,
        Method::DELETE,
        &format!("/api/auth/sessions/{vsid}"),
        None,
        &[bearer(&admin.access)],
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        me_status(&app, &viewer.access).await,
        StatusCode::UNAUTHORIZED
    );

    // Logout (cookie + CSRF) ends only this session family.
    let a3 = login(&app, "admin", PW).await;
    let a4 = login(&app, "admin", PW).await;
    let (s, h, _) = call(
        &app,
        Method::POST,
        "/api/auth/logout",
        None,
        &refresh_headers(&a3.refresh, &a3.csrf),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(set_cookie(&h, "neto_refresh")
        .unwrap()
        .contains("Max-Age=0"));
    assert_eq!(me_status(&app, &a3.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(me_status(&app, &a4.access).await, StatusCode::OK);
    // Logout without a cookie is a harmless no-op.
    assert_eq!(
        call(&app, Method::POST, "/api/auth/logout", None, &[])
            .await
            .0,
        StatusCode::NO_CONTENT
    );

    // logout-all kills everything for the user.
    let (s, _, _) = call(
        &app,
        Method::POST,
        "/api/auth/logout-all",
        None,
        &[bearer(&a4.access)],
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(me_status(&app, &a4.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        me_status(&app, &admin.access).await,
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn deactivated_user_is_locked_out_immediately(pool: PgPool) {
    let app = app(pool.clone(), &[]);
    register_admin(&app, "admin").await;
    let s = login(&app, "admin", PW).await;
    assert_eq!(me_status(&app, &s.access).await, StatusCode::OK);
    sqlx::query("UPDATE users SET is_active = FALSE")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(me_status(&app, &s.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        do_refresh(&app, &s.refresh, &s.csrf).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (st, _, _) = call(
        &app,
        Method::POST,
        "/api/auth/login",
        Some(json!({"username": "admin", "password": PW})),
        &[],
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn cors_allows_only_configured_origins(pool: PgPool) {
    let app = app(pool, &[]);
    let preflight = |origin: &str| {
        Request::builder()
            .method(Method::OPTIONS)
            .uri("/api/auth/refresh")
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "x-csrf-token")
            .body(Body::empty())
            .unwrap()
    };
    let ok = app.clone().oneshot(preflight(ORIGIN)).await.unwrap();
    assert_eq!(
        ok.headers().get("access-control-allow-origin").unwrap(),
        ORIGIN
    );
    assert_eq!(
        ok.headers()
            .get("access-control-allow-credentials")
            .unwrap(),
        "true"
    );
    let bad = app
        .clone()
        .oneshot(preflight("https://evil.example"))
        .await
        .unwrap();
    assert!(bad.headers().get("access-control-allow-origin").is_none());
}
