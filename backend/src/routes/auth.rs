//! `/api/auth/*` — first-party JWT authentication.
//!
//! * Access token: short-lived JWT, returned in the response body and kept in frontend memory.
//! * Refresh token: opaque random value in a Secure/HttpOnly/SameSite=Strict cookie scoped to
//!   `/api/auth`; only its SHA-256 digest is stored. Every refresh rotates it, and presenting an
//!   already-rotated token revokes the whole session family (reuse detection).
//! * CSRF: cookie-authenticated endpoints (refresh, logout) require an allow-listed `Origin`
//!   (when sent) plus a double-submit token (`neto_csrf` cookie == `X-CSRF-Token` header).
//!   Bearer-authenticated endpoints are not CSRF-able because the token is never a cookie.
use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    auth::{
        audit::{self, AuditEvent},
        password::{self, validate_new_password},
        tokens::{ct_eq, random_token, sha256},
        AuthUser, RequestMeta,
    },
    error::AppError,
    state::AppState,
};

const REFRESH_COOKIE: &str = "neto_refresh";
const CSRF_COOKIE: &str = "neto_csrf";
const CSRF_HEADER: &str = "x-csrf-token";
const BOOTSTRAP_HEADER: &str = "x-bootstrap-token";

// Fixed key for the advisory lock that serialises first-admin bootstrap.
const BOOTSTRAP_LOCK_KEY: i64 = 7_340_301;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/status", get(auth_status))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .route("/logout-all", post(logout_all))
        .route("/me", get(me))
        .route("/change-password", post(change_password))
        .route("/admin/reset-password", post(admin_reset_password))
        .route(
            "/admin/users",
            get(admin_list_users).post(admin_create_user),
        )
        .route("/admin/users/:user_id", patch(admin_update_user))
        .route("/sessions", get(list_sessions))
        .route("/sessions/:session_id", delete(delete_session))
        .layer(DefaultBodyLimit::max(64 * 1024))
}

// ---------------------------------------------------------------- DTOs

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterReq {
    username: String,
    password: String,
    email: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginReq {
    username: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangePasswordReq {
    current_password: String,
    new_password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminResetReq {
    user_id: Uuid,
    new_password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminCreateUserReq {
    username: String,
    email: Option<String>,
    password: String,
    role: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminUpdateUserReq {
    role: Option<String>,
    is_active: Option<bool>,
}

#[derive(sqlx::FromRow, Serialize)]
struct AdminUserView {
    id: Uuid,
    username: String,
    email: Option<String>,
    role: String,
    is_active: bool,
    must_change_password: bool,
    last_login_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(Serialize, Clone)]
struct UserView {
    id: Uuid,
    username: String,
    email: Option<String>,
    role: String,
    must_change_password: bool,
}

#[derive(Serialize)]
struct AuthResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    /// Echo of the CSRF cookie value, for cross-origin SPAs that cannot read the cookie.
    csrf_token: String,
    user: UserView,
}

#[derive(Serialize)]
struct SessionView {
    session_id: Uuid,
    started_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    user_agent: Option<String>,
    ip_address: Option<String>,
    expires_at: DateTime<Utc>,
    current: bool,
}

// ------------------------------------------------------------- helpers

fn validate_username(u: &str) -> Result<(), AppError> {
    let ok = (3..=64).contains(&u.len())
        && u.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "username must be 3-64 characters: letters, digits, '.', '_' or '-'".into(),
        ))
    }
}

fn validate_email(e: Option<&str>) -> Result<(), AppError> {
    match e {
        None => Ok(()),
        Some(e) => {
            let ok = e.len() <= 254
                && e.matches('@').count() == 1
                && !e.starts_with('@')
                && !e.ends_with('@')
                && !e.chars().any(|c| c.is_whitespace() || c.is_control());
            if ok {
                Ok(())
            } else {
                Err(AppError::BadRequest("invalid email address".into()))
            }
        }
    }
}

fn throttle(state: &AppState, key: String, max: usize, window: Duration) -> Result<(), AppError> {
    state
        .limiter
        .hit(&key, max, window)
        .map_err(|retry_after_secs| AppError::TooManyRequests { retry_after_secs })
}

fn refresh_cookie(state: &AppState, value: String) -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE, value))
        .path("/api/auth")
        .http_only(true)
        .secure(state.config.cookie_secure)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::seconds(state.config.refresh_ttl_secs))
        .build()
}

fn csrf_cookie(state: &AppState, value: String) -> Cookie<'static> {
    // Deliberately NOT HttpOnly: double-submit needs script access (same-origin deployments).
    Cookie::build((CSRF_COOKIE, value))
        .path("/")
        .http_only(false)
        .secure(state.config.cookie_secure)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::seconds(state.config.refresh_ttl_secs))
        .build()
}

fn clear_cookies(state: &AppState, jar: CookieJar) -> CookieJar {
    jar.remove(
        Cookie::build((REFRESH_COOKIE, ""))
            .path("/api/auth")
            .http_only(true)
            .secure(state.config.cookie_secure)
            .same_site(SameSite::Strict),
    )
    .remove(
        Cookie::build((CSRF_COOKIE, ""))
            .path("/")
            .http_only(false)
            .secure(state.config.cookie_secure)
            .same_site(SameSite::Strict),
    )
}

/// CSRF defence for cookie-authenticated endpoints.
fn check_csrf(state: &AppState, headers: &HeaderMap, jar: &CookieJar) -> Result<(), AppError> {
    if let Some(origin) = headers.get(header::ORIGIN) {
        let origin = origin.to_str().unwrap_or("");
        if !state.config.cors_origins.iter().any(|o| o == origin) {
            return Err(AppError::Forbidden("origin not allowed"));
        }
    }
    let cookie = jar.get(CSRF_COOKIE).map(|c| c.value().to_string());
    let header_val = headers
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    match (cookie, header_val) {
        (Some(c), Some(h)) if !c.is_empty() && ct_eq(&c, &h) => Ok(()),
        _ => Err(AppError::Forbidden("CSRF validation failed")),
    }
}

/// Create a refresh-session row. Returns `(raw_token, family_id)`; only the digest is stored.
async fn insert_session(
    conn: &mut PgConnection,
    state: &AppState,
    user_id: Uuid,
    family: Option<Uuid>,
    meta: &RequestMeta,
) -> Result<(String, Uuid, Uuid), AppError> {
    let raw = random_token();
    let family = family.unwrap_or_else(Uuid::new_v4);
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO refresh_sessions \
         (user_id, family_id, token_hash, user_agent, ip_address, last_used_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5::text::inet, now(), now() + ($6::float8 * interval '1 second')) \
         RETURNING id",
    )
    .bind(user_id)
    .bind(family)
    .bind(sha256(&raw))
    .bind(meta.user_agent.as_deref())
    .bind(meta.ip.as_deref())
    .bind(state.config.refresh_ttl_secs as f64)
    .fetch_one(conn)
    .await?;
    Ok((raw, id, family))
}

fn auth_response(
    state: &AppState,
    user: UserView,
    family: Uuid,
    refresh_raw: String,
    jar: CookieJar,
) -> Result<(CookieJar, Json<AuthResponse>), AppError> {
    let (access_token, expires_in) =
        state
            .jwt
            .issue(user.id, &user.role, family, state.config.access_ttl_secs)?;
    let csrf = random_token();
    let jar = jar
        .add(refresh_cookie(state, refresh_raw))
        .add(csrf_cookie(state, csrf.clone()));
    Ok((
        jar,
        Json(AuthResponse {
            access_token,
            token_type: "Bearer",
            expires_in,
            csrf_token: csrf,
            user,
        }),
    ))
}

async fn revoke_user_sessions(
    conn: &mut PgConnection,
    user_id: Uuid,
    reason: &str,
) -> Result<u64, AppError> {
    let r = sqlx::query(
        "UPDATE refresh_sessions SET revoked_at = now(), revoked_reason = $2 \
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(reason)
    .execute(conn)
    .await?;
    Ok(r.rows_affected())
}

// ------------------------------------------------------------ status

#[derive(Serialize)]
struct AuthStatusView {
    has_users: bool,
    allow_registration: bool,
    bootstrap_mode: bool,
}

async fn auth_status(
    State(state): State<AppState>,
) -> Result<Json<AuthStatusView>, AppError> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&state.pool)
        .await?;
    let has_users = count > 0;
    let bootstrap_mode = !has_users;
    let allow_registration = bootstrap_mode || state.config.allow_registration;
    Ok(Json(AuthStatusView {
        has_users,
        allow_registration,
        bootstrap_mode,
    }))
}

// ------------------------------------------------------------ register

async fn register(
    State(state): State<AppState>,
    meta: RequestMeta,
    headers: HeaderMap,
    Json(req): Json<RegisterReq>,
) -> Result<(StatusCode, Json<UserView>), AppError> {
    throttle(
        &state,
        format!("register:{}", meta.ip_key()),
        10,
        Duration::from_secs(3600),
    )?;
    validate_username(&req.username)?;
    validate_email(req.email.as_deref())?;
    validate_new_password(&req.password, &req.username)?;
    let hash = password::hash_async(req.password).await?;

    let mut tx = state.pool.begin().await?;
    // Serialise registrations so two concurrent requests cannot both become "first admin".
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(BOOTSTRAP_LOCK_KEY)
        .execute(&mut *tx)
        .await?;
    let existing: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&mut *tx)
        .await?;

    let (role_id, role_name): (i16, &str) = if existing == 0 {
        // First-admin bootstrap: requires a deployment-provided secret.
        let provided = headers
            .get(BOOTSTRAP_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        match &state.config.bootstrap_token {
            None => {
                audit::record(
                    &state.pool,
                    &meta,
                    AuditEvent::new("auth.bootstrap", "denied")
                        .label(&req.username)
                        .detail(json!({"reason": "bootstrap token not configured"})),
                )
                .await;
                return Err(AppError::Forbidden(
                    "first-admin bootstrap is not configured",
                ));
            }
            Some(expected) if !ct_eq(expected, provided) => {
                audit::record(
                    &state.pool,
                    &meta,
                    AuditEvent::new("auth.bootstrap", "denied")
                        .label(&req.username)
                        .detail(json!({"reason": "invalid bootstrap token"})),
                )
                .await;
                return Err(AppError::Forbidden("invalid bootstrap token"));
            }
            Some(_) => (1, "ADMIN"),
        }
    } else if state.config.allow_registration {
        // Public registration can only ever create the least-privileged role.
        (3, "VIEWER")
    } else {
        audit::record(
            &state.pool,
            &meta,
            AuditEvent::new("auth.register", "denied")
                .label(&req.username)
                .detail(json!({"reason": "registration disabled"})),
        )
        .await;
        return Err(AppError::Forbidden("registration is disabled"));
    };

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, role_id) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(&req.username)
    .bind(&req.email)
    .bind(&hash)
    .bind(role_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match AppError::from(e) {
        AppError::Conflict(_) => AppError::Conflict("username or email already in use"),
        other => other,
    })?;
    tx.commit().await?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent::new(
            if existing == 0 {
                "auth.bootstrap"
            } else {
                "auth.register"
            },
            "success",
        )
        .actor(id, &req.username)
        .resource("user", id)
        .detail(json!({"role": role_name})),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(UserView {
            id,
            username: req.username,
            email: req.email,
            role: role_name.to_string(),
            must_change_password: false,
        }),
    ))
}

// --------------------------------------------------------------- login

#[derive(sqlx::FromRow)]
struct LoginRow {
    id: Uuid,
    username: String,
    email: Option<String>,
    password_hash: String,
    role: String,
    is_active: bool,
    must_change_password: bool,
    locked_until: Option<DateTime<Utc>>,
}

async fn login(
    State(state): State<AppState>,
    meta: RequestMeta,
    jar: CookieJar,
    Json(req): Json<LoginReq>,
) -> Result<(CookieJar, Json<AuthResponse>), AppError> {
    if req.username.is_empty()
        || req.username.len() > 64
        || req.password.is_empty()
        || req.password.len() > 512
    {
        return Err(AppError::BadRequest(
            "invalid username or password format".into(),
        ));
    }
    throttle(
        &state,
        format!("login:{}", meta.ip_key()),
        30,
        Duration::from_secs(60),
    )?;

    let user: Option<LoginRow> = sqlx::query_as(
        "SELECT u.id, u.username, u.email, u.password_hash, r.name AS role, u.is_active, \
                u.must_change_password, u.locked_until \
         FROM users u JOIN roles r ON r.id = u.role_id \
         WHERE lower(u.username) = lower($1)",
    )
    .bind(&req.username)
    .fetch_optional(&state.pool)
    .await?;

    let Some(user) = user else {
        // Equalise timing with the "wrong password" path.
        let _ = password::verify_async(req.password, state.dummy_hash.to_string()).await;
        audit::record(
            &state.pool,
            &meta,
            AuditEvent::new("auth.login", "failure")
                .label(&req.username)
                .detail(json!({"reason": "unknown user"})),
        )
        .await;
        return Err(AppError::Unauthorized("invalid credentials"));
    };

    if let Some(until) = user.locked_until {
        let remaining = (until - Utc::now()).num_seconds();
        if remaining > 0 {
            audit::record(
                &state.pool,
                &meta,
                AuditEvent::new("auth.login", "denied")
                    .actor(user.id, &user.username)
                    .detail(json!({"reason": "account locked"})),
            )
            .await;
            return Err(AppError::TooManyRequests {
                retry_after_secs: remaining as u64,
            });
        }
    }

    let ok = password::verify_async(req.password, user.password_hash.clone()).await;
    if !ok {
        sqlx::query(
            "UPDATE users SET failed_login_count = failed_login_count + 1, \
               locked_until = CASE WHEN failed_login_count + 1 >= $2 \
                 THEN now() + ($3::float8 * interval '1 second') ELSE locked_until END \
             WHERE id = $1",
        )
        .bind(user.id)
        .bind(state.config.login_max_failures)
        .bind(state.config.login_lock_secs as f64)
        .execute(&state.pool)
        .await?;
        audit::record(
            &state.pool,
            &meta,
            AuditEvent::new("auth.login", "failure")
                .actor(user.id, &user.username)
                .detail(json!({"reason": "bad password"})),
        )
        .await;
        return Err(AppError::Unauthorized("invalid credentials"));
    }
    if !user.is_active {
        audit::record(
            &state.pool,
            &meta,
            AuditEvent::new("auth.login", "denied")
                .actor(user.id, &user.username)
                .detail(json!({"reason": "account disabled"})),
        )
        .await;
        return Err(AppError::Unauthorized("invalid credentials"));
    }

    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = now() WHERE id = $1",
    )
    .bind(user.id)
    .execute(&mut *tx)
    .await?;
    let (raw, _session_id, family) = insert_session(&mut tx, &state, user.id, None, &meta).await?;
    tx.commit().await?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent::new("auth.login", "success")
            .actor(user.id, &user.username)
            .resource("session", family),
    )
    .await;

    auth_response(
        &state,
        UserView {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            must_change_password: user.must_change_password,
        },
        family,
        raw,
        jar,
    )
}

// ------------------------------------------------------------- refresh

#[derive(sqlx::FromRow)]
struct RefreshRow {
    id: Uuid,
    user_id: Uuid,
    family_id: Uuid,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    revoked_reason: Option<String>,
}

#[derive(sqlx::FromRow)]
struct UserLite {
    username: String,
    email: Option<String>,
    role: String,
    is_active: bool,
    must_change_password: bool,
}

async fn refresh(
    State(state): State<AppState>,
    meta: RequestMeta,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    match refresh_inner(&state, &meta, &headers, jar.clone()).await {
        Ok(ok) => ok.into_response(),
        // Any failed refresh also clears the client's cookies.
        Err(e) => (clear_cookies(&state, jar), e).into_response(),
    }
}

async fn refresh_inner(
    state: &AppState,
    meta: &RequestMeta,
    headers: &HeaderMap,
    jar: CookieJar,
) -> Result<(CookieJar, Json<AuthResponse>), AppError> {
    let raw = jar
        .get(REFRESH_COOKIE)
        .map(|c| c.value().to_string())
        .filter(|v| !v.is_empty())
        .ok_or(AppError::Unauthorized("no session"))?;
    check_csrf(state, headers, &jar)?;
    throttle(
        state,
        format!("refresh:{}", meta.ip_key()),
        60,
        Duration::from_secs(60),
    )?;

    let mut tx = state.pool.begin().await?;
    // Row lock serialises concurrent use of the same token.
    let row: Option<RefreshRow> = sqlx::query_as(
        "SELECT id, user_id, family_id, expires_at, revoked_at, revoked_reason \
         FROM refresh_sessions WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(sha256(&raw))
    .fetch_optional(&mut *tx)
    .await?;
    let row = row.ok_or(AppError::Unauthorized("invalid session"))?;

    if row.revoked_at.is_some() {
        if row.revoked_reason.as_deref() == Some("rotated") {
            // A token that was already rotated is being replayed: assume theft and kill the family.
            sqlx::query(
                "UPDATE refresh_sessions SET revoked_at = now(), revoked_reason = 'reuse_detected' \
                 WHERE family_id = $1 AND revoked_at IS NULL",
            )
            .bind(row.family_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            audit::record(
                &state.pool,
                meta,
                AuditEvent::new("auth.refresh_reuse_detected", "denied")
                    .resource("session", row.family_id)
                    .detail(json!({"user_id": row.user_id})),
            )
            .await;
        }
        return Err(AppError::Unauthorized("invalid session"));
    }

    if row.expires_at <= Utc::now() {
        sqlx::query("UPDATE refresh_sessions SET revoked_at = now(), revoked_reason = 'expired' WHERE id = $1")
            .bind(row.id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Err(AppError::Unauthorized("session expired"));
    }

    let user: UserLite = sqlx::query_as(
        "SELECT u.username, u.email, r.name AS role, u.is_active, u.must_change_password \
         FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1",
    )
    .bind(row.user_id)
    .fetch_one(&mut *tx)
    .await?;
    if !user.is_active {
        revoke_user_sessions(&mut tx, row.user_id, "logout_all").await?;
        tx.commit().await?;
        return Err(AppError::Unauthorized("invalid session"));
    }

    let (new_raw, new_id, family) =
        insert_session(&mut tx, state, row.user_id, Some(row.family_id), meta).await?;
    sqlx::query(
        "UPDATE refresh_sessions SET revoked_at = now(), revoked_reason = 'rotated', \
         replaced_by = $2, last_used_at = now() WHERE id = $1",
    )
    .bind(row.id)
    .bind(new_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    auth_response(
        state,
        UserView {
            id: row.user_id,
            username: user.username,
            email: user.email,
            role: user.role,
            must_change_password: user.must_change_password,
        },
        family,
        new_raw,
        jar,
    )
}

// -------------------------------------------------------------- logout

async fn logout(
    State(state): State<AppState>,
    meta: RequestMeta,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), AppError> {
    let Some(raw) = jar.get(REFRESH_COOKIE).map(|c| c.value().to_string()) else {
        return Ok((clear_cookies(&state, jar), StatusCode::NO_CONTENT));
    };
    // Without CSRF protection a third party could force-logout a user.
    check_csrf(&state, &headers, &jar)?;

    let family: Option<(Uuid, Uuid)> = sqlx::query_as(
        "UPDATE refresh_sessions SET revoked_at = now(), revoked_reason = 'logout' \
         WHERE family_id = (SELECT family_id FROM refresh_sessions WHERE token_hash = $1) \
           AND revoked_at IS NULL \
         RETURNING user_id, family_id",
    )
    .bind(sha256(&raw))
    .fetch_optional(&state.pool)
    .await?;
    if let Some((user_id, family_id)) = family {
        audit::record(
            &state.pool,
            &meta,
            AuditEvent::new("auth.logout", "success")
                .resource("session", family_id)
                .detail(json!({"user_id": user_id})),
        )
        .await;
    }
    Ok((clear_cookies(&state, jar), StatusCode::NO_CONTENT))
}

async fn logout_all(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: AuthUser,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), AppError> {
    let mut conn = state.pool.acquire().await?;
    let n = revoke_user_sessions(&mut conn, auth.id, "logout_all").await?;
    audit::record(
        &state.pool,
        &meta,
        AuditEvent::new("auth.logout_all", "success")
            .actor(auth.id, &auth.username)
            .detail(json!({"sessions_revoked": n})),
    )
    .await;
    Ok((clear_cookies(&state, jar), StatusCode::NO_CONTENT))
}

// ------------------------------------------------------------------ me

async fn me(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let u: (Option<String>, bool) =
        sqlx::query_as("SELECT email, must_change_password FROM users WHERE id = $1")
            .bind(auth.id)
            .fetch_one(&state.pool)
            .await?;
    Ok(Json(json!({
        "id": auth.id,
        "username": auth.username,
        "email": u.0,
        "role": auth.role,
        "permissions": auth.permissions,
        "must_change_password": u.1,
        "session_id": auth.session_family,
    })))
}

// ----------------------------------------------------- password change

async fn change_password(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: AuthUser,
    jar: CookieJar,
    Json(req): Json<ChangePasswordReq>,
) -> Result<(CookieJar, StatusCode), AppError> {
    // Bound guessing of the current password through a stolen access token.
    throttle(
        &state,
        format!("pwchange:{}", auth.id),
        10,
        Duration::from_secs(900),
    )?;
    validate_new_password(&req.new_password, &auth.username)?;

    let current_hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(auth.id)
        .fetch_one(&state.pool)
        .await?;
    if !password::verify_async(req.current_password, current_hash).await {
        audit::record(
            &state.pool,
            &meta,
            AuditEvent::new("auth.change_password", "failure")
                .actor(auth.id, &auth.username)
                .detail(json!({"reason": "current password incorrect"})),
        )
        .await;
        return Err(AppError::Unauthorized("current password is incorrect"));
    }

    let new_hash = password::hash_async(req.new_password).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE users SET password_hash = $2, password_changed_at = now(), \
         must_change_password = FALSE, failed_login_count = 0, locked_until = NULL WHERE id = $1",
    )
    .bind(auth.id)
    .bind(&new_hash)
    .execute(&mut *tx)
    .await?;
    revoke_user_sessions(&mut tx, auth.id, "password_change").await?;
    tx.commit().await?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent::new("auth.change_password", "success").actor(auth.id, &auth.username),
    )
    .await;
    // All sessions (including this one) are revoked: the client must log in again.
    Ok((clear_cookies(&state, jar), StatusCode::NO_CONTENT))
}

async fn admin_reset_password(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: AuthUser,
    Json(req): Json<AdminResetReq>,
) -> Result<StatusCode, AppError> {
    if let Err(e) = auth.require("users:manage") {
        audit::record(
            &state.pool,
            &meta,
            AuditEvent::new("auth.admin_reset_password", "denied")
                .actor(auth.id, &auth.username)
                .resource("user", req.user_id),
        )
        .await;
        return Err(e);
    }

    #[allow(dead_code)]
    async fn admin_list_users(
        State(state): State<AppState>,
        auth: AuthUser,
    ) -> Result<Json<Vec<AdminUserView>>, AppError> {
        auth.require("users:manage")?;
        let users = sqlx::query_as(
            "SELECT u.id, u.username, u.email, r.name AS role, u.is_active, \
             u.must_change_password, u.last_login_at, u.created_at \
             FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.created_at, u.username",
        )
        .fetch_all(&state.pool)
        .await?;
        Ok(Json(users))
    }

    #[allow(dead_code)]
    async fn admin_create_user(
        State(state): State<AppState>,
        meta: RequestMeta,
        auth: AuthUser,
        Json(req): Json<AdminCreateUserReq>,
    ) -> Result<(StatusCode, Json<AdminUserView>), AppError> {
        auth.require("users:manage")?;
        validate_username(&req.username)?;
        validate_email(req.email.as_deref())?;
        let role = req.role.trim().to_uppercase();
        if !matches!(role.as_str(), "ANALYST" | "VIEWER") {
            return Err(AppError::BadRequest(
                "admin-created users may only be ANALYST or VIEWER".into(),
            ));
        }
        validate_new_password(&req.password, &req.username)?;
        let hash = password::hash_async(req.password).await?;
        let mut tx = state.pool.begin().await?;
        let row = sqlx::query_as(
            "INSERT INTO users (username, email, password_hash, role_id, must_change_password) \
             SELECT $1, $2, $3, id, TRUE FROM roles WHERE name = $4 \
             RETURNING id, username, email, role_id, is_active, must_change_password, last_login_at, created_at",
        )
        .bind(req.username.trim())
        .bind(req.email.as_deref().map(str::trim).filter(|v| !v.is_empty()))
        .bind(hash)
        .bind(&role)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if e.to_string().contains("users_username_lower_key") {
                AppError::Conflict("username already exists")
            } else {
                AppError::Internal(format!("could not create user: {e}"))
            }
        })?;
        let (
            id,
            username,
            email,
            _role_id,
            is_active,
            must_change_password,
            last_login_at,
            created_at,
        ): (
            Uuid,
            String,
            Option<String>,
            i16,
            bool,
            bool,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
        ) = row;
        tx.commit().await?;
        audit::record(
            &state.pool,
            &meta,
            AuditEvent::new("auth.admin_create_user", "success")
                .actor(auth.id, &auth.username)
                .resource("user", id)
                .detail(json!({"role": role})),
        )
        .await;
        Ok((
            StatusCode::CREATED,
            Json(AdminUserView {
                id,
                username,
                email,
                role,
                is_active,
                must_change_password,
                last_login_at,
                created_at,
            }),
        ))
    }

    #[allow(dead_code)]
    async fn admin_update_user(
        State(state): State<AppState>,
        meta: RequestMeta,
        auth: AuthUser,
        Path(user_id): Path<Uuid>,
        Json(req): Json<AdminUpdateUserReq>,
    ) -> Result<Json<AdminUserView>, AppError> {
        auth.require("users:manage")?;
        if user_id == auth.id && req.is_active == Some(false) {
            return Err(AppError::BadRequest(
                "cannot disable the current admin account".into(),
            ));
        }
        let role = req.role.map(|r| r.trim().to_uppercase());
        if let Some(role) = &role {
            if !matches!(role.as_str(), "ADMIN" | "ANALYST" | "VIEWER") {
                return Err(AppError::BadRequest(
                    "role must be ADMIN, ANALYST, or VIEWER".into(),
                ));
            }
        }
        let row = sqlx::query_as(
            "UPDATE users u SET role_id = COALESCE((SELECT id FROM roles WHERE name = $2), u.role_id), \
             is_active = COALESCE($3, u.is_active) WHERE u.id = $1 \
             RETURNING u.id, u.username, u.email, u.is_active, u.must_change_password, u.last_login_at, u.created_at",
        )
        .bind(user_id).bind(role.as_deref()).bind(req.is_active)
        .fetch_optional(&state.pool).await?.ok_or(AppError::NotFound)?;
        let (id, username, email, is_active, must_change_password, last_login_at, created_at): (
            Uuid,
            String,
            Option<String>,
            bool,
            bool,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
        ) = row;
        let actual_role: String = sqlx::query_scalar(
            "SELECT r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1",
        )
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
        if req.is_active == Some(false) {
            let mut conn = state.pool.acquire().await?;
            revoke_user_sessions(&mut conn, id, "admin_disabled").await?;
        }
        audit::record(
            &state.pool,
            &meta,
            AuditEvent::new("auth.admin_update_user", "success")
                .actor(auth.id, &auth.username)
                .resource("user", id)
                .detail(json!({"role": actual_role, "is_active": is_active})),
        )
        .await;
        Ok(Json(AdminUserView {
            id,
            username,
            email,
            role: actual_role,
            is_active,
            must_change_password,
            last_login_at,
            created_at,
        }))
    }
    let target: Option<String> = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
        .bind(req.user_id)
        .fetch_optional(&state.pool)
        .await?;
    let target = target.ok_or(AppError::NotFound)?;
    validate_new_password(&req.new_password, &target)?;

    let hash = password::hash_async(req.new_password).await?;
    let mut tx = state.pool.begin().await?;
    // The admin knows the new password, so the user must choose their own at next login.
    sqlx::query(
        "UPDATE users SET password_hash = $2, password_changed_at = now(), \
         must_change_password = TRUE, failed_login_count = 0, locked_until = NULL WHERE id = $1",
    )
    .bind(req.user_id)
    .bind(&hash)
    .execute(&mut *tx)
    .await?;
    let n = revoke_user_sessions(&mut tx, req.user_id, "admin_reset").await?;
    tx.commit().await?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent::new("auth.admin_reset_password", "success")
            .actor(auth.id, &auth.username)
            .resource("user", req.user_id)
            .detail(json!({"sessions_revoked": n})),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_list_users(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<AdminUserView>>, AppError> {
    auth.require("users:manage")?;
    Ok(Json(sqlx::query_as(
        "SELECT u.id, u.username, u.email, r.name AS role, u.is_active, u.must_change_password, u.last_login_at, u.created_at FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.created_at, u.username",
    ).fetch_all(&state.pool).await?))
}

async fn admin_create_user(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: AuthUser,
    Json(req): Json<AdminCreateUserReq>,
) -> Result<(StatusCode, Json<AdminUserView>), AppError> {
    auth.require("users:manage")?;
    validate_username(&req.username)?;
    validate_email(req.email.as_deref())?;
    let role = req.role.trim().to_uppercase();
    if !matches!(role.as_str(), "ANALYST" | "VIEWER") {
        return Err(AppError::BadRequest(
            "new users may only be ANALYST or VIEWER".into(),
        ));
    }
    validate_new_password(&req.password, &req.username)?;
    let hash = password::hash_async(req.password).await?;
    let row: AdminUserView = sqlx::query_as(
        "WITH inserted AS (INSERT INTO users (username, email, password_hash, role_id, must_change_password) SELECT $1, $2, $3, id, TRUE FROM roles WHERE name = $4 RETURNING *) SELECT i.id, i.username, i.email, $4::text AS role, i.is_active, i.must_change_password, i.last_login_at, i.created_at FROM inserted i",
    ).bind(req.username.trim()).bind(req.email.as_deref()).bind(hash).bind(&role)
    .fetch_one(&state.pool).await.map_err(|e| if e.to_string().contains("users_username_lower_key") { AppError::Conflict("username already exists") } else { AppError::Internal(format!("could not create user: {e}")) })?;
    audit::record(
        &state.pool,
        &meta,
        AuditEvent::new("auth.admin_create_user", "success")
            .actor(auth.id, &auth.username)
            .resource("user", row.id),
    )
    .await;
    Ok((StatusCode::CREATED, Json(row)))
}

async fn admin_update_user(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: AuthUser,
    Path(user_id): Path<Uuid>,
    Json(req): Json<AdminUpdateUserReq>,
) -> Result<Json<AdminUserView>, AppError> {
    auth.require("users:manage")?;
    if user_id == auth.id && req.is_active == Some(false) {
        return Err(AppError::BadRequest(
            "cannot disable the current admin account".into(),
        ));
    }
    let role = req.role.map(|v| v.trim().to_uppercase());
    if let Some(value) = &role {
        if !matches!(value.as_str(), "ADMIN" | "ANALYST" | "VIEWER") {
            return Err(AppError::BadRequest(
                "role must be ADMIN, ANALYST, or VIEWER".into(),
            ));
        }
    }
    let row: AdminUserView = sqlx::query_as(
        "UPDATE users u SET role_id = COALESCE((SELECT id FROM roles WHERE name = $2), u.role_id), is_active = COALESCE($3, u.is_active) WHERE u.id = $1 RETURNING u.id, u.username, u.email, (SELECT name FROM roles WHERE id = u.role_id) AS role, u.is_active, u.must_change_password, u.last_login_at, u.created_at",
    ).bind(user_id).bind(role.as_deref()).bind(req.is_active).fetch_optional(&state.pool).await?.ok_or(AppError::NotFound)?;
    if req.is_active == Some(false) {
        let mut conn = state.pool.acquire().await?;
        revoke_user_sessions(&mut conn, user_id, "admin_disabled").await?;
    }
    audit::record(
        &state.pool,
        &meta,
        AuditEvent::new("auth.admin_update_user", "success")
            .actor(auth.id, &auth.username)
            .resource("user", row.id),
    )
    .await;
    Ok(Json(row))
}

// ------------------------------------------------------------ sessions

#[derive(sqlx::FromRow)]
struct SessionRow {
    family_id: Uuid,
    started_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    user_agent: Option<String>,
    ip_address: Option<String>,
    expires_at: DateTime<Utc>,
}

/// Lists the caller's active sessions. `session_id` is the stable session-family id,
/// which does not change when the refresh token rotates.
async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<SessionView>>, AppError> {
    let rows: Vec<SessionRow> = sqlx::query_as(
        "SELECT s.family_id, \
                (SELECT min(f.created_at) FROM refresh_sessions f WHERE f.family_id = s.family_id) AS started_at, \
                s.last_used_at, s.user_agent, host(s.ip_address) AS ip_address, s.expires_at \
         FROM refresh_sessions s \
         WHERE s.user_id = $1 AND s.revoked_at IS NULL AND s.expires_at > now() \
         ORDER BY started_at DESC",
    )
    .bind(auth.id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| SessionView {
                current: r.family_id == auth.session_family,
                session_id: r.family_id,
                started_at: r.started_at,
                last_used_at: r.last_used_at,
                user_agent: r.user_agent,
                ip_address: r.ip_address,
                expires_at: r.expires_at,
            })
            .collect(),
    ))
}

async fn delete_session(
    State(state): State<AppState>,
    meta: RequestMeta,
    auth: AuthUser,
    jar: CookieJar,
    Path(session_id): Path<String>,
) -> Result<(CookieJar, StatusCode), AppError> {
    let family = Uuid::parse_str(&session_id)
        .map_err(|_| AppError::BadRequest("session_id must be a UUID".into()))?;
    let any_user = auth.has("sessions:manage_all");
    // Sessions of other users are indistinguishable from nonexistent ones (404) for non-admins.
    let r = sqlx::query(
        "UPDATE refresh_sessions SET revoked_at = now(), revoked_reason = 'logout' \
         WHERE family_id = $1 AND revoked_at IS NULL AND ($3 OR user_id = $2)",
    )
    .bind(family)
    .bind(auth.id)
    .bind(any_user)
    .execute(&state.pool)
    .await?;
    if r.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    audit::record(
        &state.pool,
        &meta,
        AuditEvent::new("auth.session_revoked", "success")
            .actor(auth.id, &auth.username)
            .resource("session", family),
    )
    .await;
    let jar = if family == auth.session_family {
        clear_cookies(&state, jar)
    } else {
        jar
    };
    Ok((jar, StatusCode::NO_CONTENT))
}
