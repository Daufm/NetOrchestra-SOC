//! Cleartext HTTP credential exposure. Detects, but never stores, secrets: Authorization
//! headers are reduced to their scheme, form fields to their *names*, and query-string values
//! are replaced by `<redacted>` before any finding is created.
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use super::{push_frame, thr_strings, Detector, Finding, MAX_GROUPS};
use crate::analysis::model::PacketRecord;

struct Group {
    rule: &'static str,
    severity: &'static str,
    confidence: f64,
    title: String,
    explanation: String,
    src: String,
    dst: Option<String>,
    src_port: Option<i32>,
    dst_port: Option<i32>,
    first: DateTime<Utc>,
    count: u64,
    frames: Vec<i64>,
    evidence: Value,
}

pub struct CleartextHttp {
    sensitive: Vec<String>,
    flag_basic: bool,
    groups: HashMap<String, Group>,
    truncated: bool,
}

const LOGIN_PATHS: [&str; 5] = ["login", "signin", "logon", "auth", "session"];

/// Query-parameter names whose values are always redacted, whatever the detection profile.
pub const DEFAULT_SENSITIVE: [&str; 12] = [
    "password", "passwd", "pwd", "pass", "token", "apikey", "api_key", "secret", "auth", "session",
    "sid", "key",
];

/// Default list plus any `sensitive_params` configured on the profile.
pub fn sensitive_keys(thresholds: &Value) -> Vec<String> {
    let mut v: Vec<String> = DEFAULT_SENSITIVE.iter().map(|s| s.to_string()).collect();
    v.extend(thr_strings(thresholds, "sensitive_params", &[]));
    v.sort();
    v.dedup();
    v
}

/// The URI as it may be stored: sensitive query values replaced by `<redacted>`.
pub fn redact_uri(uri: &str, sensitive: &[String]) -> String {
    let (path, query, _) = redact_query(uri, sensitive);
    if uri.contains('?') {
        format!("{path}?{query}")
    } else {
        path
    }
}

/// Split a request URI into (path, redacted query, names of sensitive query keys).
pub(crate) fn redact_query(uri: &str, sensitive: &[String]) -> (String, String, Vec<String>) {
    let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
    let mut hit = Vec::new();
    let redacted: Vec<String> = query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let key = kv.split('=').next().unwrap_or("");
            if sensitive
                .iter()
                .any(|s| key.to_lowercase().contains(s.as_str()))
            {
                hit.push(key.to_string());
                format!("{key}=<redacted>")
            } else {
                kv.to_string()
            }
        })
        .collect();
    (path.to_string(), redacted.join("&"), hit)
}

impl CleartextHttp {
    pub fn new(t: &Value) -> Self {
        Self {
            sensitive: thr_strings(
                t,
                "sensitive_params",
                &["password", "passwd", "pwd", "token", "apikey"],
            ),
            flag_basic: t
                .get("flag_basic_auth")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            groups: HashMap::new(),
            truncated: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        key: String,
        p: &PacketRecord,
        rule: &'static str,
        severity: &'static str,
        confidence: f64,
        title: String,
        explanation: String,
        evidence: Value,
    ) {
        if !self.groups.contains_key(&key) && self.groups.len() >= MAX_GROUPS {
            self.truncated = true;
            return;
        }
        let g = self.groups.entry(key).or_insert_with(|| Group {
            rule,
            severity,
            confidence,
            title,
            explanation,
            src: p.src_ip.clone().unwrap_or_default(),
            dst: p.dst_ip.clone(),
            src_port: p.src_port,
            dst_port: p.dst_port,
            first: p.ts,
            count: 0,
            frames: vec![],
            evidence,
        });
        g.count += 1;
        push_frame(&mut g.frames, p.frame);
    }
}

impl Detector for CleartextHttp {
    fn observe(&mut self, p: &PacketRecord) {
        let Some(method) = p.http_method.as_deref() else {
            return;
        };
        if p.src_ip.is_none() {
            return;
        }
        let host = p
            .http_host
            .clone()
            .unwrap_or_else(|| p.dst_ip.clone().unwrap_or_default());
        let uri = p.http_uri.clone().unwrap_or_default();
        let (path, redacted_query, sens_query) = redact_query(&uri, &self.sensitive);
        let src = p.src_ip.clone().unwrap_or_default();
        let where_ = format!("{method} http://{host}{path}");

        if self.flag_basic {
            if let Some(auth) = &p.http_auth {
                if auth.to_lowercase().starts_with("basic ") {
                    self.add(
                        format!("http.basic_auth|{src}|{host}|{path}"),
                        p,
                        "http.basic_auth",
                        "high",
                        0.9,
                        format!("HTTP Basic credentials sent in cleartext to {host}"),
                        format!("{src} sent an HTTP Basic Authorization header over unencrypted HTTP ({where_}). Basic credentials are only base64-encoded and can be read by anyone on the path. The credential value was redacted."),
                        json!({"scheme": "Basic", "credential": "<redacted>", "host": host, "path": path}),
                    );
                }
            }
        }

        let sens_form: Vec<String> = p
            .form_keys
            .iter()
            .filter(|k| {
                self.sensitive
                    .iter()
                    .any(|s| k.to_lowercase().contains(s.as_str()))
            })
            .cloned()
            .collect();
        if method.eq_ignore_ascii_case("POST") && !sens_form.is_empty() {
            self.add(
                format!("http.cleartext_login|{src}|{host}|{path}"),
                p,
                "http.cleartext_login",
                "high",
                0.85,
                format!("Cleartext login form submission to {host}"),
                format!("{src} submitted a form containing {} to {host}{path} over unencrypted HTTP. Field values were not stored.", sens_form.join(", ")),
                json!({"method": method, "host": host, "path": path, "sensitive_fields": sens_form, "values": "<redacted>"}),
            );
        } else if method.eq_ignore_ascii_case("POST")
            && LOGIN_PATHS.iter().any(|l| path.to_lowercase().contains(l))
        {
            self.add(
                format!("http.login_post|{src}|{host}|{path}"),
                p,
                "http.login_post",
                "low",
                0.4,
                format!("Possible login request to {host}{path}"),
                format!("{src} sent a POST to a login-like path ({where_}) over unencrypted HTTP; no recognisable credential field was visible, so this is low confidence."),
                json!({"method": method, "host": host, "path": path}),
            );
        }

        if !sens_query.is_empty() {
            self.add(
                format!("http.sensitive_query|{src}|{host}|{path}"),
                p,
                "http.sensitive_query",
                "medium",
                0.7,
                format!("Sensitive parameter in URL query to {host}"),
                format!("{src} requested {host}{path} with sensitive-looking query parameter(s) {} in the URL. URLs are logged by proxies and servers. Values were redacted.", sens_query.join(", ")),
                json!({"host": host, "path": path, "query_redacted": redacted_query, "sensitive_params": sens_query}),
            );
        }
    }

    fn findings(&self) -> Vec<Finding> {
        self.groups
            .iter()
            .map(|(key, g)| {
                let mut ev = g.evidence.clone();
                if let Value::Object(m) = &mut ev {
                    m.insert("requests".into(), json!(g.count));
                }
                Finding {
                    key: key.clone(),
                    rule_id: g.rule,
                    severity: g.severity,
                    confidence: g.confidence,
                    title: g.title.clone(),
                    explanation: g.explanation.clone(),
                    src_ip: Some(g.src.clone()),
                    dst_ip: g.dst.clone(),
                    src_port: g.src_port,
                    dst_port: g.dst_port,
                    frames: g.frames.clone(),
                    evidence: ev,
                    detected_at: g.first,
                }
            })
            .collect()
    }

    fn truncated(&self) -> bool {
        self.truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(frame: i64, method: &str, uri: &str) -> PacketRecord {
        PacketRecord {
            frame,
            ts: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            src_ip: Some("192.0.2.30".into()),
            dst_ip: Some("198.51.100.80".into()),
            dst_port: Some(80),
            http_method: Some(method.into()),
            http_host: Some("intranet.example".into()),
            http_uri: Some(uri.into()),
            ..Default::default()
        }
    }

    fn det() -> CleartextHttp {
        CleartextHttp::new(&json!({}))
    }

    #[test]
    fn basic_auth_is_flagged_and_secret_never_appears() {
        let mut d = det();
        let mut p = req(1, "GET", "/admin");
        p.http_auth = Some("Basic YWxpY2U6U3VwZXJTZWNyZXQxMjM=".into());
        d.observe(&p);
        let f = d.findings();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "http.basic_auth");
        let all = format!("{f:?}");
        assert!(!all.contains("YWxpY2U6"), "base64 credential leaked: {all}");
        assert!(!all.contains("SuperSecret"));
        assert!(all.contains("<redacted>"));
    }

    #[test]
    fn login_post_with_password_field() {
        let mut d = det();
        let mut p = req(2, "POST", "/login");
        p.form_keys = vec!["username".into(), "password".into()];
        d.observe(&p);
        let f = d.findings();
        assert_eq!(f[0].rule_id, "http.cleartext_login");
        assert_eq!(f[0].evidence["sensitive_fields"], json!(["password"]));
        assert_eq!(f[0].evidence["values"], "<redacted>");
    }

    #[test]
    fn query_values_are_redacted() {
        let mut d = det();
        d.observe(&req(3, "GET", "/reset?user=bob&token=abc123secrettoken"));
        let f = d.findings();
        let ev = f[0].evidence.to_string();
        assert!(ev.contains("user=bob"));
        assert!(ev.contains("token=<redacted>"));
        assert!(!ev.contains("abc123secrettoken"));
        assert!(!f[0].explanation.contains("abc123secrettoken"));
    }

    #[test]
    fn benign_get_is_clean_and_repeats_aggregate() {
        let mut d = det();
        d.observe(&req(4, "GET", "/index.html"));
        assert!(d.findings().is_empty());
        let mut p = req(5, "POST", "/login");
        p.form_keys = vec!["password".into()];
        d.observe(&p);
        p.frame = 6;
        d.observe(&p);
        let f = d.findings();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].frames, vec![5, 6]);
        assert_eq!(f[0].evidence["requests"], 2);
    }

    #[test]
    fn redact_uri_for_storage() {
        let keys = sensitive_keys(&json!({"sensitive_params": ["otp"]}));
        assert_eq!(
            redact_uri("/a?user=bob&token=zzz&otp=1", &keys),
            "/a?user=bob&token=<redacted>&otp=<redacted>"
        );
        assert_eq!(redact_uri("/plain", &keys), "/plain");
        assert_eq!(redact_uri("/q?", &keys), "/q?");
    }

    #[test]
    fn redact_query_helper() {
        let (path, q, hit) = redact_query("/a/b?x=1&Password=zzz&y", &["password".into()]);
        assert_eq!(
            (path.as_str(), q.as_str()),
            ("/a/b", "x=1&Password=<redacted>&y")
        );
        assert_eq!(hit, ["Password"]);
    }
}
