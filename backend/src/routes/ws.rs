//! `GET /api/ws` — live job events.
//!
//! Browsers cannot set an `Authorization` header on a WebSocket, and putting a token in the
//! URL leaks it into logs. Instead the first message must be `{"type":"auth","token":"<jwt>"}`
//! within 5 seconds. The session ends when the access token expires so the client reconnects
//! with a fresh one. A slow consumer receives a `resync` message instead of unbounded buffering.
use std::time::Duration;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde_json::json;
use tokio::sync::broadcast::error::RecvError;

use crate::{auth::authenticate_token, error::AppError, state::AppState};

pub fn router() -> Router<AppState> {
    Router::new().route("/ws", get(ws_handler))
}

async fn ws_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    // Defence in depth against cross-site WebSocket hijacking.
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if !state.config.cors_origins.iter().any(|o| o == origin) {
            return AppError::Forbidden("origin not allowed").into_response();
        }
    }
    ws.max_message_size(16 * 1024)
        .on_upgrade(move |socket| session(state, socket))
}

async fn send_json(socket: &mut WebSocket, v: serde_json::Value) -> bool {
    socket.send(Message::Text(v.to_string())).await.is_ok()
}

async fn session(state: AppState, mut socket: WebSocket) {
    // ---- authenticate
    let first = tokio::time::timeout(Duration::from_secs(5), socket.recv()).await;
    let token = match first {
        Ok(Some(Ok(Message::Text(t)))) => serde_json::from_str::<serde_json::Value>(&t)
            .ok()
            .filter(|v| v["type"] == "auth")
            .and_then(|v| v["token"].as_str().map(str::to_string)),
        _ => None,
    };
    let Some(token) = token else {
        let _ = send_json(
            &mut socket,
            json!({"type": "error", "code": "auth_required"}),
        )
        .await;
        return;
    };
    let (user, exp) = match authenticate_token(&state, &token, "/api/ws").await {
        Ok(ok) if ok.0.has("jobs:read") => ok,
        _ => {
            let _ = send_json(
                &mut socket,
                json!({"type": "error", "code": "unauthorized"}),
            )
            .await;
            return;
        }
    };
    let mut rx = state.events.subscribe();
    if !send_json(
        &mut socket,
        json!({"type": "auth_ok", "user": user.username, "role": user.role}),
    )
    .await
    {
        return;
    }

    let secs_left = (exp - chrono::Utc::now().timestamp()).max(1) as u64;
    let expiry = tokio::time::sleep(Duration::from_secs(secs_left));
    tokio::pin!(expiry);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
    heartbeat.tick().await;

    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(e) => {
                    let Ok(text) = serde_json::to_string(&e) else { continue };
                    if socket.send(Message::Text(text)).await.is_err() { break; }
                }
                Err(RecvError::Lagged(n)) => {
                    if !send_json(&mut socket, json!({"type": "resync", "missed": n})).await { break; }
                }
                Err(RecvError::Closed) => break,
            },
            msg = socket.recv() => match msg {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(Message::Text(t))) if t.trim() == "ping" => {
                    if !send_json(&mut socket, json!({"type": "pong"})).await { break; }
                }
                Some(Ok(_)) => {} // ignore everything else
            },
            _ = heartbeat.tick() => {
                if socket.send(Message::Ping(Vec::new())).await.is_err() { break; }
            }
            _ = &mut expiry => {
                let _ = send_json(&mut socket, json!({"type": "error", "code": "token_expired"})).await;
                break;
            }
        }
    }
    let _ = socket.close().await;
}
