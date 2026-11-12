//! Threat detectors. Each detector observes normalized packets, aggregates them into groups
//! (e.g. per source + domain) and reports findings with stable keys. Findings describe
//! *suspected* activity with a confidence score; nothing is ever labelled a confirmed
//! compromise. Credentials are redacted before a finding can be created.
use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::model::PacketRecord;

pub mod dns;
pub mod http;
pub mod remote;

/// Upper bounds that keep memory bounded on hostile or huge captures.
pub const MAX_GROUPS: usize = 50_000;
pub const MAX_FRAMES_PER_FINDING: usize = 50;

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// Stable identity of the finding within a job (rule + endpoints + key attributes).
    pub key: String,
    pub rule_id: &'static str,
    /// info | low | medium | high | critical
    pub severity: &'static str,
    /// 0.0 ..= 1.0
    pub confidence: f64,
    pub title: String,
    pub explanation: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    /// Frame numbers in the original PCAP (1-based), capped.
    pub frames: Vec<i64>,
    pub evidence: Value,
    pub detected_at: DateTime<Utc>,
}

pub trait Detector: Send + Sync {
    fn observe(&mut self, p: &PacketRecord);
    /// Current set of triggered findings. Called periodically while a capture is live and
    /// once more at the end; the pipeline de-duplicates by `key`.
    fn findings(&self) -> Vec<Finding>;
    /// True if some groups were dropped because a bound was hit.
    fn truncated(&self) -> bool {
        false
    }
}

pub fn for_profile(profile_id: &str, thresholds: &Value) -> Option<Box<dyn Detector>> {
    match profile_id {
        "dns_tunnel" => Some(Box::new(dns::DnsTunnel::new(thresholds))),
        "cleartext_http" => Some(Box::new(http::CleartextHttp::new(thresholds))),
        "remote_access" => Some(Box::new(remote::RemoteAccess::new(thresholds))),
        _ => None,
    }
}

pub(crate) fn thr_f64(t: &Value, key: &str, default: f64) -> f64 {
    t.get(key).and_then(Value::as_f64).unwrap_or(default)
}

pub(crate) fn thr_strings(t: &Value, key: &str, default: &[&str]) -> Vec<String> {
    t.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                .collect()
        })
        .unwrap_or_else(|| default.iter().map(|s| s.to_string()).collect())
}

pub(crate) fn push_frame(frames: &mut Vec<i64>, frame: i64) {
    if frames.len() < MAX_FRAMES_PER_FINDING && !frames.contains(&frame) {
        frames.push(frame);
    }
}

pub(crate) fn clamp01(x: f64) -> f64 {
    (x.clamp(0.0, 1.0) * 1000.0).round() / 1000.0
}

#[allow(dead_code)]
pub(crate) fn dedupe(v: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    v.into_iter().filter(|s| seen.insert(s.clone())).collect()
}
