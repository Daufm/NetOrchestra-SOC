//! `/api/health` is liveness (process is up). `/api/ready` is readiness
//! (the database answers), suitable for container and orchestrator probes.
use std::time::Duration;

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use serde::Serialize;

use crate::{db, state::AppState};

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}

#[derive(Serialize)]
pub struct ReadyResponse {
    pub status: &'static str,
    pub database: &'static str,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "netorchestra-backend",
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub async fn ready(State(state): State<AppState>) -> (StatusCode, Json<ReadyResponse>) {
    let probe = tokio::time::timeout(Duration::from_secs(3), db::ping(&state.pool)).await;
    match probe {
        Ok(Ok(())) => (
            StatusCode::OK,
            Json(ReadyResponse {
                status: "ready",
                database: "up",
            }),
        ),
        failure => {
            // Do not leak driver error text to unauthenticated callers; log it instead.
            match failure {
                Ok(Err(e)) => tracing::warn!(error = %e, "readiness probe failed"),
                _ => tracing::warn!("readiness probe timed out"),
            }
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadyResponse {
                    status: "not_ready",
                    database: "down",
                }),
            )
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
}

#[cfg(test)]
mod tests {
    use crate::{routes, state::AppState};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app() -> axum::Router {
        routes::router(AppState::unreachable_for_tests())
    }

    #[tokio::test]
    async fn health_returns_ok_json() {
        let res = app()
            .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "ok");
    }

    #[tokio::test]
    async fn ready_is_503_when_database_is_down() {
        let res = app()
            .oneshot(Request::get("/api/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["database"], "down");
    }

    #[tokio::test]
    async fn unknown_route_is_404() {
        let res = app()
            .oneshot(Request::get("/api/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
