pub mod auth;
pub mod docs;
pub mod forensics;
pub mod health;
pub mod ws;

use axum::{
    http::{header, HeaderName, HeaderValue, Method},
    Router,
};
use std::time::Duration;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};

use crate::{config::Config, state::AppState};

fn cors_layer(cfg: &Config) -> CorsLayer {
    if cfg.cors_origins.is_empty() {
        // No origins configured: no CORS headers are emitted, so browsers enforce same-origin.
        return CorsLayer::new();
    }
    let origins: Vec<HeaderValue> = cfg
        .cors_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("x-csrf-token"),
        ])
        .max_age(Duration::from_secs(600))
}

/// Application router. Later phases add forensics and WebSocket routes.
pub fn router(state: AppState) -> Router {
    let cors = cors_layer(&state.config);
    Router::new()
        .nest(
            "/api",
            health::router()
                .nest("/auth", auth::router())
                .merge(docs::router())
                .merge(forensics::router())
                .merge(ws::router()),
        )
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(cors)
}
