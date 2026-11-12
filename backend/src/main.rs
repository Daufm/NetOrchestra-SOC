use std::net::SocketAddr;

use netorchestra_backend::{config::Config, db, routes, state::AppState};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::from_env()?;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if cfg.log_json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    if !cfg.cookie_secure {
        tracing::warn!(
            "NETO_COOKIE_SECURE=false: refresh cookies are not marked Secure (development only)"
        );
    }

    let pool = db::connect(&cfg).await?;
    tracing::info!("database connection established");
    if cfg.run_migrations {
        db::migrate(&pool).await?;
        tracing::info!("database migrations applied");
    }

    for dir in [&cfg.evidence_dir, &cfg.workspace_dir] {
        tokio::fs::create_dir_all(dir).await?;
    }
    let orphaned = netorchestra_backend::jobs::recover_orphans(&pool).await?;
    if orphaned > 0 {
        tracing::warn!(
            orphaned,
            "marked jobs interrupted by a previous shutdown as failed"
        );
    }
    if cfg.worker_bin.is_none() {
        tracing::info!(
            "NETO_WORKER_BIN not set: remote packet streaming is disabled (uploads still work)"
        );
    }
    if cfg.allowed_targets.is_empty() {
        tracing::info!(
            "NETO_ALLOWED_TARGETS is empty: remote capture targets are denied until configured"
        );
    }

    let bind_addr = cfg.bind_addr;
    let state = AppState::new(pool.clone(), cfg)?;
    let app = routes::router(state).into_make_service_with_connect_info::<SocketAddr>();

    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!(addr = %bind_addr, "netorchestra-backend listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    pool.close().await;
    tracing::info!("shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}
