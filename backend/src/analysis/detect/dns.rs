//! DNS tunnelling: overlong labels, encoded-looking (high entropy) labels, query bursts and
//! TXT-heavy traffic, grouped per (client, registered domain). The registered domain is the
//! last two labels (a Public Suffix List is deliberately not bundled), which is adequate for
//! grouping but means e.g. `co.uk` zones group together.
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use super::{clamp01, push_frame, thr_f64, Detector, Finding, MAX_GROUPS};
use crate::analysis::model::PacketRecord;

const TXT: i32 = 16;

struct Group {
    src: String,
    dst: Option<String>,
    domain: String,
    count: u64,
    first: DateTime<Utc>,
    last: DateTime<Utc>,
    max_label: usize,
    long_count: u64,
    entropy_count: u64,
    max_entropy: f64,
    txt_count: u64,
    per_minute: HashMap<i64, u32>,
    frames_long: Vec<i64>,
    frames_entropy: Vec<i64>,
    frames_txt: Vec<i64>,
    frames_all: Vec<i64>,
    samples: Vec<String>,
}

pub struct DnsTunnel {
    max_label_len: usize,
    min_entropy: f64,
    queries_per_minute: f64,
    txt_ratio: f64,
    groups: HashMap<(String, String), Group>,
    truncated: bool,
}

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c.to_ascii_lowercase()).or_default() += 1;
    }
    let n = s.chars().count() as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn registered_domain(name: &str) -> String {
    let labels: Vec<&str> = name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
        .collect();
    let n = labels.len();
    if n <= 2 {
        labels.join(".").to_lowercase()
    } else {
        labels[n - 2..].join(".").to_lowercase()
    }
}

impl DnsTunnel {
    pub fn new(t: &Value) -> Self {
        Self {
            max_label_len: thr_f64(t, "max_label_len", 50.0) as usize,
            min_entropy: thr_f64(t, "min_entropy", 3.5),
            queries_per_minute: thr_f64(t, "queries_per_minute", 120.0),
            txt_ratio: thr_f64(t, "txt_ratio", 0.3),
            groups: HashMap::new(),
            truncated: false,
        }
    }
}

impl Detector for DnsTunnel {
    fn observe(&mut self, p: &PacketRecord) {
        if p.dns_is_response || p.dns_queries.is_empty() {
            return;
        }
        let Some(src) = p.src_ip.clone() else { return };
        for (name, qtype) in &p.dns_queries {
            let domain = registered_domain(name);
            let key = (src.clone(), domain.clone());
            if !self.groups.contains_key(&key) && self.groups.len() >= MAX_GROUPS {
                self.truncated = true;
                continue;
            }
            let g = self.groups.entry(key).or_insert_with(|| Group {
                src: src.clone(),
                dst: p.dst_ip.clone(),
                domain,
                count: 0,
                first: p.ts,
                last: p.ts,
                max_label: 0,
                long_count: 0,
                entropy_count: 0,
                max_entropy: 0.0,
                txt_count: 0,
                per_minute: HashMap::new(),
                frames_long: vec![],
                frames_entropy: vec![],
                frames_txt: vec![],
                frames_all: vec![],
                samples: vec![],
            });
            g.count += 1;
            g.last = g.last.max(p.ts);
            g.first = g.first.min(p.ts);
            *g.per_minute
                .entry(p.ts.timestamp().div_euclid(60))
                .or_default() += 1;
            push_frame(&mut g.frames_all, p.frame);

            let longest = name.split('.').map(str::len).max().unwrap_or(0);
            g.max_label = g.max_label.max(longest);
            if longest > self.max_label_len {
                g.long_count += 1;
                push_frame(&mut g.frames_long, p.frame);
                if g.samples.len() < 3 {
                    g.samples.push(name.chars().take(120).collect());
                }
            }
            // Entropy is judged on the leftmost (most attacker-controlled) label.
            if let Some(label) = name.split('.').next() {
                if label.len() >= 16 {
                    let e = shannon_entropy(label);
                    g.max_entropy = g.max_entropy.max(e);
                    if e >= self.min_entropy {
                        g.entropy_count += 1;
                        push_frame(&mut g.frames_entropy, p.frame);
                    }
                }
            }
            if *qtype == Some(TXT) {
                g.txt_count += 1;
                push_frame(&mut g.frames_txt, p.frame);
            }
        }
    }

    fn findings(&self) -> Vec<Finding> {
        let mut out = Vec::new();
        for g in self.groups.values() {
            let base = |rule: &'static str,
                        sev: &'static str,
                        conf: f64,
                        title: String,
                        expl: String,
                        frames: &[i64],
                        extra: Value| {
                Finding {
                    key: format!("{rule}|{}|{}", g.src, g.domain),
                    rule_id: rule,
                    severity: sev,
                    confidence: clamp01(conf),
                    title,
                    explanation: expl,
                    src_ip: Some(g.src.clone()),
                    dst_ip: g.dst.clone(),
                    src_port: None,
                    dst_port: Some(53),
                    frames: frames.to_vec(),
                    evidence: json!({
                        "domain": g.domain, "queries": g.count,
                        "first_seen": g.first, "last_seen": g.last,
                        "detail": extra,
                    }),
                    detected_at: g.first,
                }
            };

            if g.long_count > 0 {
                let conf = 0.5
                    + 0.2 * (g.long_count as f64 / 5.0).min(1.0)
                    + if g.entropy_count > 0 { 0.15 } else { 0.0 };
                out.push(base(
                    "dns.long_label",
                    if g.max_label >= 60 { "high" } else { "medium" },
                    conf,
                    format!("Suspected DNS tunnelling: oversized labels under {}", g.domain),
                    format!(
                        "{} queried {} names under {} with a label up to {} characters (threshold {}). Very long labels are a common way to smuggle data in DNS. This is an indicator, not proof of exfiltration.",
                        g.src, g.long_count, g.domain, g.max_label, self.max_label_len
                    ),
                    &g.frames_long,
                    json!({"max_label_len": g.max_label, "threshold": self.max_label_len, "long_queries": g.long_count, "sample_names": g.samples}),
                ));
            }
            if g.entropy_count >= 5 {
                out.push(base(
                    "dns.high_entropy",
                    if g.entropy_count >= 20 { "high" } else { "medium" },
                    0.6 + (g.entropy_count as f64 / 100.0).min(0.3),
                    format!("Encoded-looking DNS labels under {}", g.domain),
                    format!(
                        "{} sent {} queries under {} whose leftmost label has high character entropy (max {:.2} bits, threshold {:.2}), which resembles base32/hex/base64-encoded data.",
                        g.src, g.entropy_count, g.domain, g.max_entropy, self.min_entropy
                    ),
                    &g.frames_entropy,
                    json!({"max_entropy_bits": (g.max_entropy * 100.0).round() / 100.0, "threshold": self.min_entropy, "queries": g.entropy_count}),
                ));
            }
            let peak = g.per_minute.values().copied().max().unwrap_or(0);
            if peak as f64 > self.queries_per_minute {
                out.push(base(
                    "dns.high_rate",
                    if peak as f64 > self.queries_per_minute * 3.0 {
                        "high"
                    } else {
                        "medium"
                    },
                    0.45 + (peak as f64 / (self.queries_per_minute * 4.0)).min(0.4),
                    format!("High DNS query rate to {}", g.domain),
                    format!(
                        "{} issued up to {} queries per minute under {} (threshold {}).",
                        g.src, peak, g.domain, self.queries_per_minute
                    ),
                    &g.frames_all,
                    json!({"peak_queries_per_minute": peak, "threshold": self.queries_per_minute}),
                ));
            }
            if g.txt_count >= 10 && (g.txt_count as f64 / g.count as f64) >= self.txt_ratio {
                out.push(base(
                    "dns.txt_heavy",
                    "medium",
                    0.5 + (g.txt_count as f64 / 200.0).min(0.3),
                    format!("TXT-heavy DNS traffic to {}", g.domain),
                    format!(
                        "{} of {} queries from {} to {} were TXT lookups (ratio {:.0}%, threshold {:.0}%). TXT records are a frequent covert-channel carrier.",
                        g.txt_count, g.count, g.src, g.domain,
                        100.0 * g.txt_count as f64 / g.count as f64, 100.0 * self.txt_ratio
                    ),
                    &g.frames_txt,
                    json!({"txt_queries": g.txt_count, "total_queries": g.count}),
                ));
            }
        }
        out
    }

    fn truncated(&self) -> bool {
        self.truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(frame: i64, secs: i64, src: &str, name: &str, qtype: i32) -> PacketRecord {
        PacketRecord {
            frame,
            ts: DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap(),
            src_ip: Some(src.into()),
            dst_ip: Some("192.0.2.53".into()),
            dns_queries: vec![(name.into(), Some(qtype))],
            ..Default::default()
        }
    }

    fn det() -> DnsTunnel {
        DnsTunnel::new(
            &json!({"max_label_len": 50, "min_entropy": 3.5, "queries_per_minute": 120, "txt_ratio": 0.3}),
        )
    }

    #[test]
    fn entropy_values() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert!(shannon_entropy("aaaaaaaaaaaaaaaa") < 0.01);
        assert!(shannon_entropy("a1b2c3d4e5f6g7h8i9j0") > 3.0);
    }

    #[test]
    fn registered_domain_grouping() {
        assert_eq!(registered_domain("a.b.Evil.Example."), "evil.example");
        assert_eq!(registered_domain("example.com"), "example.com");
    }

    #[test]
    fn flags_tunnelling_with_frame_references() {
        let mut d = det();
        for i in 0..30 {
            // xorshift: pseudo-random, so the labels genuinely look like encoded data
            let mut x: u64 =
                0x9E37_79B9_7F4A_7C15 ^ (i as u64 + 1).wrapping_mul(0xD134_2543_DE82_EF95);
            let label: String = (0..58)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    char::from(b'a' + (x % 26) as u8)
                })
                .collect();
            d.observe(&q(
                i + 1,
                i,
                "192.0.2.10",
                &format!("{label}.t.evil.example."),
                if i % 2 == 0 { 16 } else { 1 },
            ));
        }
        let f = d.findings();
        let rules: Vec<_> = f.iter().map(|x| x.rule_id).collect();
        assert!(rules.contains(&"dns.long_label"));
        assert!(rules.contains(&"dns.high_entropy"));
        assert!(rules.contains(&"dns.txt_heavy"));
        for x in &f {
            assert!(!x.frames.is_empty() && x.frames.len() <= 50);
            assert!((0.0..=1.0).contains(&x.confidence));
            assert!(x.explanation.contains("192.0.2.10"));
        }
    }

    #[test]
    fn benign_lookups_produce_nothing() {
        let mut d = det();
        for (i, n) in ["www.example.com.", "mail.example.org.", "docs.example.net."]
            .iter()
            .enumerate()
        {
            d.observe(&q(i as i64 + 1, i as i64, "192.0.2.20", n, 1));
        }
        assert!(d.findings().is_empty());
    }

    #[test]
    fn responses_are_ignored() {
        let mut d = det();
        let mut p = q(
            1,
            0,
            "192.0.2.10",
            &format!("{}.evil.example.", "x".repeat(60)),
            1,
        );
        p.dns_is_response = true;
        d.observe(&p);
        assert!(d.findings().is_empty());
    }

    #[test]
    fn rate_rule_uses_per_minute_peak() {
        let mut d = DnsTunnel::new(&json!({"queries_per_minute": 10}));
        for i in 0..30 {
            d.observe(&q(
                i + 1,
                0,
                "192.0.2.10",
                &format!("h{i}.busy.example."),
                1,
            ));
        }
        assert!(d.findings().iter().any(|f| f.rule_id == "dns.high_rate"));
    }
}
