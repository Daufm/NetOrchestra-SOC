use std::sync::Arc;

use sqlx::PgPool;

use crate::{
    auth::{jwt::JwtKeys, limiter::RateLimiter, password},
    config::Config,
    error::AppError,
    events::EventBus,
    jobs::JobManager,
};

/// Shared application state, cloned cheaply into each handler.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub jwt: Arc<JwtKeys>,
    pub limiter: Arc<RateLimiter>,
    /// Valid Argon2id hash verified against when a username does not exist, so that
    /// "unknown user" and "wrong password" take the same time.
    pub dummy_hash: Arc<String>,
    pub events: EventBus,
    pub jobs: Arc<JobManager>,
    /// Cached result of validating the installed TShark (version or error text).
    pub tshark_info: Arc<tokio::sync::OnceCell<Result<String, String>>>,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config) -> Result<Self, AppError> {
        let jwt = JwtKeys::new(
            config.jwt_secret.as_bytes(),
            &config.jwt_issuer,
            &config.jwt_audience,
        );
        let dummy_hash = password::hash_password(&crate::auth::tokens::random_token())?;
        let jobs = Arc::new(JobManager::new(config.max_concurrent_jobs));
        Ok(Self {
            pool,
            config: Arc::new(config),
            jwt: Arc::new(jwt),
            limiter: Arc::new(RateLimiter::new()),
            dummy_hash: Arc::new(dummy_hash),
            events: EventBus::new(2048),
            jobs,
            tshark_info: Arc::new(tokio::sync::OnceCell::new()),
        })
    }
}

#[cfg(test)]
impl AppState {
    /// State whose pool points at a closed port so any query fails fast. Lets router
    /// tests run without a database.
    pub fn unreachable_for_tests() -> Self {
        use sqlx::postgres::PgPoolOptions;
        use std::time::Duration;
        let pool = PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(500))
            .connect_lazy("postgres://test:test@127.0.0.1:1/test")
            .expect("lazy pool");
        let cfg = Config::from_lookup(|k| match k {
            "DATABASE_URL" => Some("postgres://test:test@127.0.0.1:1/test".into()),
            "NETO_JWT_SECRET" => Some("0123456789abcdef0123456789abcdef0123".into()),
            _ => None,
        })
        .expect("test config");
        Self::new(pool, cfg).expect("state")
    }
}
