//! Request extractors: `RequestMeta` (client IP, user agent, request id) and `AuthUser`
//! (verified bearer token + live database check for RBAC).
use std::net::SocketAddr;

use axum::{
    async_trait,
    extract::{ConnectInfo, FromRequestParts, OriginalUri},
    http::{header, request::Parts},
};
use uuid::Uuid;

use crate::{error::AppError, state::AppState};

#[derive(Debug, Clone, Default)]
pub struct RequestMeta {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
}

impl RequestMeta {
    /// Key used for per-client throttling.
    pub fn ip_key(&self) -> &str {
        self.ip.as_deref().unwrap_or("unknown")
    }
}

#[async_trait]
impl FromRequestParts<AppState> for RequestMeta {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip().to_string());
        // X-Forwarded-For is client-controlled unless a trusted proxy sets it, so it is only
        // honoured when NETO_TRUST_PROXY=true. The last entry is the one our proxy appended.
        let ip = if state.config.trust_proxy {
            parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .map(|s| s.trim().to_string())
                .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
                .or(peer)
        } else {
            peer
        };
        let user_agent = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(256).collect());
        let request_id = parts
            .headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(64).collect());
        Ok(Self {
            ip,
            user_agent,
            request_id,
        })
    }
}

/// An authenticated caller. Role and permissions come from the database on every request,
/// so role changes, deactivation and session revocation take effect immediately.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub permissions: Vec<String>,
    /// Session family the presented access token belongs to.
    pub session_family: Uuid,
}

impl AuthUser {
    pub fn has(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }

    /// Backend RBAC check: `Forbidden` unless the caller's role grants `permission`.
    pub fn require(&self, permission: &str) -> Result<(), AppError> {
        if self.has(permission) {
            Ok(())
        } else {
            Err(AppError::Forbidden("insufficient permissions"))
        }
    }
}

#[derive(sqlx::FromRow)]
struct AuthRow {
    id: Uuid,
    username: String,
    role: String,
    is_active: bool,
    must_change_password: bool,
    permissions: Vec<String>,
    session_live: bool,
}

const AUTH_QUERY: &str = "\
SELECT u.id, u.username, r.name AS role, u.is_active, u.must_change_password, \
       COALESCE(array_agg(p.code) FILTER (WHERE p.code IS NOT NULL), ARRAY[]::text[]) AS permissions, \
       EXISTS (SELECT 1 FROM refresh_sessions s \
               WHERE s.family_id = $2 AND s.user_id = u.id \
                 AND s.revoked_at IS NULL AND s.expires_at > now()) AS session_live \
FROM users u \
JOIN roles r ON r.id = u.role_id \
LEFT JOIN role_permissions rp ON rp.role_id = r.id \
LEFT JOIN permissions p ON p.id = rp.permission_id \
WHERE u.id = $1 \
GROUP BY u.id, r.name";

/// Verify a bearer token and load the live user/permissions. `path` is the request path
/// (used to enforce `must_change_password`).
pub async fn authenticate_token(
    state: &AppState,
    token: &str,
    path: &str,
) -> Result<(AuthUser, i64), AppError> {
    let claims = state
        .jwt
        .verify(token)
        .map_err(|_| AppError::Unauthorized("invalid or expired token"))?;
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("invalid or expired token"))?;
    let family = Uuid::parse_str(&claims.sid)
        .map_err(|_| AppError::Unauthorized("invalid or expired token"))?;

    let row: Option<AuthRow> = sqlx::query_as(AUTH_QUERY)
        .bind(user_id)
        .bind(family)
        .fetch_optional(&state.pool)
        .await?;
    let row = row
        .filter(|r| r.is_active && r.session_live)
        .ok_or(AppError::Unauthorized("invalid or expired token"))?;

    // After an admin reset the user may only use /api/auth/* until they change the password.
    if row.must_change_password && !path.starts_with("/api/auth/") {
        return Err(AppError::PasswordChangeRequired);
    }
    Ok((
        AuthUser {
            id: row.id,
            username: row.username,
            role: row.role,
            permissions: row.permissions,
            session_family: family,
        },
        claims.exp,
    ))
}

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized("missing credentials"))?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or(AppError::Unauthorized("missing credentials"))?;
        let path = parts
            .extensions
            .get::<OriginalUri>()
            .map(|o| o.0.path().to_string())
            .unwrap_or_else(|| parts.uri.path().to_string());
        authenticate_token(state, token, &path)
            .await
            .map(|(u, _)| u)
    }
}
