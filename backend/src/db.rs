//! PostgreSQL connection pool, migrations and health probing.
use std::time::Duration;

use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::config::Config;

/// Create the connection pool. Fails fast if the database is unreachable.
pub async fn connect(cfg: &Config) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(cfg.db_max_connections)
        .acquire_timeout(Duration::from_secs(cfg.db_acquire_timeout_secs))
        .connect(&cfg.database_url)
        .await
}

/// Apply embedded migrations from `backend/migrations`. The migration files are
/// compiled into the binary, so no database is needed at build time.
pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

/// Cheap round-trip used by the readiness probe.
pub async fn ping(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT 1").execute(pool).await.map(|_| ())
}
