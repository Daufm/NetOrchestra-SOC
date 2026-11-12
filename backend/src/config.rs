//! Environment-driven configuration. Secrets come only from the environment and are
//! redacted from `Debug` output.
use std::net::SocketAddr;

use crate::cidr::Cidr;

#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub log_json: bool,
    // database
    pub database_url: String,
    pub db_max_connections: u32,
    pub db_acquire_timeout_secs: u64,
    pub run_migrations: bool,
    // auth
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub access_ttl_secs: i64,
    pub refresh_ttl_secs: i64,
    pub cors_origins: Vec<String>,
    pub cookie_secure: bool,
    pub allow_registration: bool,
    pub bootstrap_token: Option<String>,
    pub trust_proxy: bool,
    pub login_max_failures: i32,
    pub login_lock_secs: i64,
    // forensics
    pub evidence_dir: String,
    pub workspace_dir: String,
    pub tshark_path: String,
    pub worker_bin: Option<String>,
    pub worker_keys_dir: Option<String>,
    pub max_upload_bytes: u64,
    pub max_concurrent_jobs: usize,
    pub max_capture_secs: i64,
    pub max_stream_bytes: u64,
    pub allowed_targets: Vec<Cidr>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("log_json", &self.log_json)
            .field("database_url", &"<redacted>")
            .field("db_max_connections", &self.db_max_connections)
            .field("run_migrations", &self.run_migrations)
            .field("jwt_secret", &"<redacted>")
            .field("jwt_issuer", &self.jwt_issuer)
            .field("jwt_audience", &self.jwt_audience)
            .field("access_ttl_secs", &self.access_ttl_secs)
            .field("refresh_ttl_secs", &self.refresh_ttl_secs)
            .field("cors_origins", &self.cors_origins)
            .field("cookie_secure", &self.cookie_secure)
            .field("allow_registration", &self.allow_registration)
            .field(
                "bootstrap_token",
                &self.bootstrap_token.as_ref().map(|_| "<redacted>"),
            )
            .field("trust_proxy", &self.trust_proxy)
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "configuration error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

fn parse_bounded<T>(
    raw: Option<String>,
    key: &str,
    default: T,
    min: T,
    max: T,
) -> Result<T, ConfigError>
where
    T: std::str::FromStr + PartialOrd + Copy + std::fmt::Display,
{
    match raw {
        None => Ok(default),
        Some(v) => {
            let n: T = v
                .parse()
                .map_err(|_| ConfigError(format!("{key} '{v}' is not a valid number")))?;
            if n < min || n > max {
                return Err(ConfigError(format!(
                    "{key} must be between {min} and {max}"
                )));
            }
            Ok(n)
        }
    }
}

fn parse_bool(raw: Option<String>, key: &str, default: bool) -> Result<bool, ConfigError> {
    match raw.as_deref().map(str::trim) {
        None | Some("") => Ok(default),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") => Ok(true),
        Some("0") | Some("false") | Some("FALSE") | Some("no") => Ok(false),
        Some(other) => Err(ConfigError(format!(
            "{key} '{other}' must be true or false"
        ))),
    }
}

fn parse_origins(raw: Option<String>) -> Result<Vec<String>, ConfigError> {
    let mut out = Vec::new();
    for o in raw.unwrap_or_default().split(',') {
        let o = o.trim().trim_end_matches('/');
        if o.is_empty() {
            continue;
        }
        if o == "*" || !(o.starts_with("http://") || o.starts_with("https://")) {
            return Err(ConfigError(format!(
                "NETO_CORS_ORIGINS entry '{o}' must be an explicit http(s) origin (wildcards are not allowed)"
            )));
        }
        out.push(o.to_string());
    }
    Ok(out)
}

impl Config {
    /// Build configuration from a lookup function (injectable for tests).
    pub fn from_lookup<F>(get: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let raw = get("NETO_BIND_ADDR").unwrap_or_else(|| "0.0.0.0:8080".to_string());
        let bind_addr = raw
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError(format!("NETO_BIND_ADDR '{raw}': {e}")))?;
        let log_json = parse_bool(get("NETO_LOG_JSON"), "NETO_LOG_JSON", false)?;

        let database_url = get("DATABASE_URL")
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| ConfigError("DATABASE_URL is required".to_string()))?;
        if !(database_url.starts_with("postgres://") || database_url.starts_with("postgresql://")) {
            return Err(ConfigError(
                "DATABASE_URL must start with postgres:// or postgresql://".to_string(),
            ));
        }
        let db_max_connections = parse_bounded(
            get("NETO_DB_MAX_CONNECTIONS"),
            "NETO_DB_MAX_CONNECTIONS",
            10u32,
            1,
            200,
        )?;
        let db_acquire_timeout_secs = parse_bounded(
            get("NETO_DB_ACQUIRE_TIMEOUT_SECS"),
            "NETO_DB_ACQUIRE_TIMEOUT_SECS",
            5u64,
            1,
            120,
        )?;
        let run_migrations = parse_bool(get("NETO_RUN_MIGRATIONS"), "NETO_RUN_MIGRATIONS", true)?;

        let jwt_secret = get("NETO_JWT_SECRET")
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| ConfigError("NETO_JWT_SECRET is required".to_string()))?;
        if jwt_secret.len() < 32 {
            return Err(ConfigError(
                "NETO_JWT_SECRET must be at least 32 bytes (try: openssl rand -base64 48)"
                    .to_string(),
            ));
        }
        if jwt_secret.to_ascii_lowercase().contains("change_me") {
            return Err(ConfigError(
                "NETO_JWT_SECRET still contains the CHANGE_ME placeholder".to_string(),
            ));
        }
        let jwt_issuer = get("NETO_JWT_ISSUER")
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "netorchestra".to_string());
        let jwt_audience = get("NETO_JWT_AUDIENCE")
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "netorchestra-api".to_string());
        let access_ttl_secs = parse_bounded(
            get("NETO_ACCESS_TTL_SECS"),
            "NETO_ACCESS_TTL_SECS",
            900i64,
            60,
            3600,
        )?;
        let refresh_ttl_secs = parse_bounded(
            get("NETO_REFRESH_TTL_SECS"),
            "NETO_REFRESH_TTL_SECS",
            604_800i64,
            3600,
            2_592_000,
        )?;
        let cors_origins = parse_origins(get("NETO_CORS_ORIGINS"))?;
        let cookie_secure = parse_bool(get("NETO_COOKIE_SECURE"), "NETO_COOKIE_SECURE", true)?;
        let allow_registration = parse_bool(
            get("NETO_ALLOW_REGISTRATION"),
            "NETO_ALLOW_REGISTRATION",
            false,
        )?;
        let bootstrap_token = get("NETO_BOOTSTRAP_TOKEN").filter(|v| !v.is_empty());
        if let Some(t) = &bootstrap_token {
            if t.len() < 24 {
                return Err(ConfigError(
                    "NETO_BOOTSTRAP_TOKEN must be at least 24 characters".to_string(),
                ));
            }
        }
        let trust_proxy = parse_bool(get("NETO_TRUST_PROXY"), "NETO_TRUST_PROXY", false)?;
        let login_max_failures = parse_bounded(
            get("NETO_LOGIN_MAX_FAILURES"),
            "NETO_LOGIN_MAX_FAILURES",
            5i32,
            3,
            20,
        )?;
        let login_lock_secs = parse_bounded(
            get("NETO_LOGIN_LOCK_SECS"),
            "NETO_LOGIN_LOCK_SECS",
            900i64,
            30,
            86_400,
        )?;

        let evidence_dir = get("NETO_EVIDENCE_DIR")
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "/var/lib/netorchestra/evidence".to_string());
        let workspace_dir = get("NETO_WORKSPACE_DIR")
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "/var/lib/netorchestra/workspace".to_string());
        let tshark_path = get("NETO_TSHARK_PATH")
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "tshark".to_string());
        let worker_bin = get("NETO_WORKER_BIN").filter(|v| !v.is_empty());
        let worker_keys_dir = get("NETO_WORKER_KEYS_DIR").filter(|v| !v.is_empty());
        let max_upload_bytes = parse_bounded(
            get("NETO_MAX_UPLOAD_BYTES"),
            "NETO_MAX_UPLOAD_BYTES",
            536_870_912u64,
            1024,
            10_737_418_240,
        )?;
        let max_concurrent_jobs = parse_bounded(
            get("NETO_MAX_CONCURRENT_JOBS"),
            "NETO_MAX_CONCURRENT_JOBS",
            4usize,
            1,
            64,
        )?;
        let max_capture_secs = parse_bounded(
            get("NETO_MAX_CAPTURE_SECS"),
            "NETO_MAX_CAPTURE_SECS",
            3600i64,
            5,
            86_400,
        )?;
        let max_stream_bytes = parse_bounded(
            get("NETO_MAX_STREAM_BYTES"),
            "NETO_MAX_STREAM_BYTES",
            536_870_912u64,
            1024,
            53_687_091_200,
        )?;
        let mut allowed_targets = Vec::new();
        for entry in get("NETO_ALLOWED_TARGETS").unwrap_or_default().split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            allowed_targets.push(
                Cidr::parse(entry)
                    .map_err(|e| ConfigError(format!("NETO_ALLOWED_TARGETS: {e}")))?,
            );
        }

        Ok(Self {
            bind_addr,
            log_json,
            database_url,
            db_max_connections,
            db_acquire_timeout_secs,
            run_migrations,
            jwt_secret,
            jwt_issuer,
            jwt_audience,
            access_ttl_secs,
            refresh_ttl_secs,
            cors_origins,
            cookie_secure,
            allow_registration,
            bootstrap_token,
            trust_proxy,
            login_max_failures,
            login_lock_secs,
            evidence_dir,
            workspace_dir,
            tshark_path,
            worker_bin,
            worker_keys_dir,
            max_upload_bytes,
            max_concurrent_jobs,
            max_capture_secs,
            max_stream_bytes,
            allowed_targets,
        })
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const SECRET: &str = "0123456789abcdef0123456789abcdef0123";

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let mut m: HashMap<String, String> = HashMap::from([
            (
                "DATABASE_URL".into(),
                "postgres://u:secret@db:5432/x".into(),
            ),
            ("NETO_JWT_SECRET".into(), SECRET.into()),
        ]);
        for (k, v) in pairs {
            m.insert(k.to_string(), v.to_string());
        }
        move |k| m.get(k).cloned()
    }

    #[test]
    fn defaults_are_secure() {
        let cfg = Config::from_lookup(env(&[])).unwrap();
        assert_eq!(cfg.bind_addr.port(), 8080);
        assert_eq!(cfg.access_ttl_secs, 900);
        assert_eq!(cfg.refresh_ttl_secs, 604_800);
        assert!(cfg.cookie_secure, "cookies are Secure by default");
        assert!(
            !cfg.allow_registration,
            "public registration is off by default"
        );
        assert!(!cfg.trust_proxy);
        assert!(cfg.cors_origins.is_empty());
        assert!(cfg.run_migrations);
    }

    #[test]
    fn database_url_is_required_and_validated() {
        let none = |_: &str| None;
        assert!(Config::from_lookup(none).is_err());
        assert!(Config::from_lookup(env(&[("DATABASE_URL", "mysql://x")])).is_err());
    }

    #[test]
    fn jwt_secret_rules() {
        assert!(Config::from_lookup(env(&[("NETO_JWT_SECRET", "short")])).is_err());
        assert!(Config::from_lookup(env(&[(
            "NETO_JWT_SECRET",
            "CHANGE_ME_generate_with_openssl_rand_base64_48"
        )]))
        .is_err());
        let missing = |k: &str| (k == "DATABASE_URL").then(|| "postgres://x@h/d".to_string());
        assert!(Config::from_lookup(missing).is_err());
    }

    #[test]
    fn cors_origins_reject_wildcards() {
        assert!(Config::from_lookup(env(&[("NETO_CORS_ORIGINS", "*")])).is_err());
        assert!(Config::from_lookup(env(&[("NETO_CORS_ORIGINS", "example.com")])).is_err());
        let cfg = Config::from_lookup(env(&[(
            "NETO_CORS_ORIGINS",
            "http://localhost:5173/, https://soc.example.com",
        )]))
        .unwrap();
        assert_eq!(
            cfg.cors_origins,
            ["http://localhost:5173", "https://soc.example.com"]
        );
    }

    #[test]
    fn ttl_and_lockout_bounds() {
        assert!(Config::from_lookup(env(&[("NETO_ACCESS_TTL_SECS", "5")])).is_err());
        assert!(Config::from_lookup(env(&[("NETO_REFRESH_TTL_SECS", "999999999")])).is_err());
        assert!(Config::from_lookup(env(&[("NETO_LOGIN_MAX_FAILURES", "1")])).is_err());
    }

    #[test]
    fn forensics_defaults_and_validation() {
        let cfg = Config::from_lookup(env(&[])).unwrap();
        assert_eq!(cfg.max_upload_bytes, 512 * 1024 * 1024);
        assert_eq!(cfg.max_stream_bytes, 512 * 1024 * 1024);
        assert_eq!(cfg.max_concurrent_jobs, 4);
        assert!(
            cfg.allowed_targets.is_empty(),
            "remote capture is deny-all until configured"
        );
        let cfg =
            Config::from_lookup(env(&[("NETO_ALLOWED_TARGETS", "10.0.0.0/8, 192.0.2.5")])).unwrap();
        assert_eq!(cfg.allowed_targets.len(), 2);
        assert!(Config::from_lookup(env(&[("NETO_ALLOWED_TARGETS", "garbage")])).is_err());
        assert!(Config::from_lookup(env(&[("NETO_MAX_CONCURRENT_JOBS", "0")])).is_err());
        assert!(Config::from_lookup(env(&[("NETO_MAX_UPLOAD_BYTES", "10")])).is_err());
    }

    #[test]
    fn bootstrap_token_must_be_long() {
        assert!(Config::from_lookup(env(&[("NETO_BOOTSTRAP_TOKEN", "short")])).is_err());
        assert!(Config::from_lookup(env(&[(
            "NETO_BOOTSTRAP_TOKEN",
            "a-long-enough-bootstrap-token-123"
        )]))
        .is_ok());
    }

    #[test]
    fn invalid_values_are_rejected() {
        assert!(Config::from_lookup(env(&[("NETO_BIND_ADDR", "nope")])).is_err());
        assert!(Config::from_lookup(env(&[("NETO_COOKIE_SECURE", "maybe")])).is_err());
        assert!(Config::from_lookup(env(&[("NETO_DB_MAX_CONNECTIONS", "0")])).is_err());
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let cfg = Config::from_lookup(env(&[
            ("DATABASE_URL", "postgres://u:hunter2pw@db:5432/x"),
            ("NETO_BOOTSTRAP_TOKEN", "a-long-enough-bootstrap-token-123"),
        ]))
        .unwrap();
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("hunter2pw"), "database password leaked");
        assert!(!dbg.contains(SECRET), "jwt secret leaked");
        assert!(!dbg.contains("bootstrap-token"), "bootstrap token leaked");
        assert!(dbg.contains("<redacted>"));
    }
}
