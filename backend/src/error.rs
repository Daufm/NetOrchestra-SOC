//! Application error type with a stable JSON error envelope:
//! `{"error": {"code": "...", "message": "..."}}`.
//! Internal details are logged, never returned to the client.
use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Unauthorized(&'static str),
    Forbidden(&'static str),
    PasswordChangeRequired,
    NotFound,
    Conflict(&'static str),
    TooManyRequests { retry_after_secs: u64 },
    ServiceUnavailable(&'static str),
    Internal(String),
}

impl AppError {
    pub fn internal(e: impl std::fmt::Display) -> Self {
        Self::Internal(e.to_string())
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        if let Some(db) = e.as_database_error() {
            // 23505 = unique_violation
            if db.code().as_deref() == Some("23505") {
                return Self::Conflict("resource already exists");
            }
        }
        Self::Internal(e.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message): (StatusCode, &str, String) = match &self {
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m.clone()),
            Self::Unauthorized(m) => (StatusCode::UNAUTHORIZED, "unauthorized", (*m).to_string()),
            Self::Forbidden(m) => (StatusCode::FORBIDDEN, "forbidden", (*m).to_string()),
            Self::PasswordChangeRequired => (
                StatusCode::FORBIDDEN,
                "password_change_required",
                "password change required before continuing".to_string(),
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found".to_string()),
            Self::Conflict(m) => (StatusCode::CONFLICT, "conflict", (*m).to_string()),
            Self::TooManyRequests { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_requests",
                "too many attempts, try again later".to_string(),
            ),
            Self::ServiceUnavailable(m) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                (*m).to_string(),
            ),
            Self::Internal(detail) => {
                tracing::error!(error = %detail, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "internal server error".to_string(),
                )
            }
        };
        let mut res = (
            status,
            Json(json!({ "error": { "code": code, "message": message } })),
        )
            .into_response();
        if let Self::TooManyRequests { retry_after_secs } = self {
            if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                res.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        res
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AppError {}
