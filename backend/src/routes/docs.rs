//! `/api/docs` documentation endpoints.
//! Returns metadata and markdown contents of system docs.
use axum::{extract::Path, routing::get, Json, Router};
use serde::Serialize;

use crate::{error::AppError, state::AppState};

#[derive(Serialize, Clone)]
pub struct DocItem {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub filename: &'static str,
}

#[derive(Serialize)]
pub struct DocDetail {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub content: &'static str,
}

const DOCS_CATALOG: &[DocItem] = &[
    DocItem {
        id: "architecture",
        title: "System Architecture",
        category: "Design",
        description: "Components, data pipelines, network topology and design decisions.",
        filename: "ARCHITECTURE.md",
    },
    DocItem {
        id: "api",
        title: "API Reference",
        category: "Reference",
        description: "Comprehensive REST endpoints, parameters, RBAC permissions, and WebSocket schemas.",
        filename: "API.md",
    },
    DocItem {
        id: "detection",
        title: "Threat Detection Engine",
        category: "Detection",
        description: "Detection rules, profiles, thresholds, and credential redaction mechanisms.",
        filename: "DETECTION.md",
    },
    DocItem {
        id: "security",
        title: "Security & Hardening",
        category: "Security",
        description: "Security controls, threat modeling, operational hardening checklist, and isolation.",
        filename: "SECURITY.md",
    },
    DocItem {
        id: "auth",
        title: "Authentication & RBAC",
        category: "Security",
        description: "JWT access tokens, rotating refresh cookies, CSRF protection, and role permissions.",
        filename: "AUTH.md",
    },
    DocItem {
        id: "database",
        title: "Database Schema & Persistence",
        category: "Data",
        description: "PostgreSQL 16+ schemas, integrity constraints, SQLx offline mode, backup and restore.",
        filename: "DATABASE.md",
    },
    DocItem {
        id: "worker",
        title: "Go Remote Capture Worker",
        category: "Worker",
        description: "SSH execution worker protocol, allowlisting, remote capabilities, and capture lifecycle.",
        filename: "WORKER.md",
    },
    DocItem {
        id: "ssh-remote-setup",
        title: "SSH & Remote Host Setup",
        category: "Operations",
        description: "Step-by-step guide to generating SSH keys, remote capture account setup, CAP_NET_RAW, and known_hosts.",
        filename: "SSH_REMOTE_SETUP.md",
    },
];

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/docs", get(list_docs))
        .route("/docs/:id", get(get_doc))
}

async fn list_docs() -> Json<Vec<DocItem>> {
    Json(DOCS_CATALOG.to_vec())
}

async fn get_doc(Path(id): Path<String>) -> Result<Json<DocDetail>, AppError> {
    let doc = match id.as_str() {
        "architecture" => DocDetail {
            id: "architecture",
            title: "System Architecture",
            category: "Design",
            description: "Components, data pipelines, network topology and design decisions.",
            content: include_str!("../../../docs/ARCHITECTURE.md"),
        },
        "api" => DocDetail {
            id: "api",
            title: "API Reference",
            category: "Reference",
            description: "Comprehensive REST endpoints, parameters, RBAC permissions, and WebSocket schemas.",
            content: include_str!("../../../docs/API.md"),
        },
        "detection" => DocDetail {
            id: "detection",
            title: "Threat Detection Engine",
            category: "Detection",
            description: "Detection rules, profiles, thresholds, and credential redaction mechanisms.",
            content: include_str!("../../../docs/DETECTION.md"),
        },
        "security" => DocDetail {
            id: "security",
            title: "Security & Hardening",
            category: "Security",
            description: "Security controls, threat modeling, operational hardening checklist, and isolation.",
            content: include_str!("../../../docs/SECURITY.md"),
        },
        "auth" => DocDetail {
            id: "auth",
            title: "Authentication & RBAC",
            category: "Security",
            description: "JWT access tokens, rotating refresh cookies, CSRF protection, and role permissions.",
            content: include_str!("../../../docs/AUTH.md"),
        },
        "database" => DocDetail {
            id: "database",
            title: "Database Schema & Persistence",
            category: "Data",
            description: "PostgreSQL 16+ schemas, integrity constraints, SQLx offline mode, backup and restore.",
            content: include_str!("../../../docs/DATABASE.md"),
        },
        "worker" => DocDetail {
            id: "worker",
            title: "Go Remote Capture Worker",
            category: "Worker",
            description: "SSH execution worker protocol, allowlisting, remote capabilities, and capture lifecycle.",
            content: include_str!("../../../docs/WORKER.md"),
        },
        "ssh-remote-setup" => DocDetail {
            id: "ssh-remote-setup",
            title: "SSH & Remote Host Setup",
            category: "Operations",
            description: "Step-by-step guide to generating SSH keys, remote capture account setup, CAP_NET_RAW, and known_hosts.",
            content: include_str!("../../../docs/SSH_REMOTE_SETUP.md"),
        },
        _ => return Err(AppError::NotFound),
    };
    Ok(Json(doc))
}


#[cfg(test)]
mod tests {
    use axum::{body::Body, http::{Request, StatusCode}};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::{routes, state::AppState};

    fn test_app() -> axum::Router {
        routes::router(AppState::unreachable_for_tests())
    }

    #[tokio::test]
    async fn test_list_docs() {
        let app = test_app();
        let res = app
            .oneshot(Request::get("/api/docs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let docs: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(docs.as_array().unwrap().len() >= 7);
    }

    #[tokio::test]
    async fn test_get_architecture_doc() {
        let app = test_app();
        let res = app
            .oneshot(Request::get("/api/docs/architecture").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["id"], "architecture");
        assert!(doc["content"].as_str().unwrap().contains("Architecture"));
    }
}
