//! Suspicious remote-access traffic (SSH/RDP): connection bursts, many sources hitting one
//! service, services on unexpected ports (when TShark dissects SSH/RDP there), and an
//! informational record of observed sessions. Connection attempts are TCP SYNs without ACK.
use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use super::{clamp01, push_frame, thr_f64, Detector, Finding, MAX_GROUPS};
use crate::analysis::model::PacketRecord;

type FlowKey = (String, String, i32); // src, dst, dst_port

#[derive(Default)]
struct Flow {
    first: Option<DateTime<Utc>>,
    last: Option<DateTime<Utc>>,
    syn_per_minute: HashMap<i64, u32>,
    syns: u64,
    packets: u64,
    frames_syn: Vec<i64>,
    frames_any: Vec<i64>,
}

#[derive(Default)]
struct Service {
    sources: HashSet<String>,
    frames: Vec<i64>,
    first: Option<DateTime<Utc>>,
}

pub struct RemoteAccess {
    ports: Vec<i32>,
    burst_per_minute: f64,
    distinct_sources: usize,
    flows: HashMap<FlowKey, Flow>,
    services: HashMap<(String, i32), Service>,
    nonstandard: HashMap<FlowKey, (&'static str, Vec<i64>, DateTime<Utc>)>,
    truncated: bool,
}

fn service_name(port: i32) -> &'static str {
    match port {
        22 => "SSH",
        3389 => "RDP",
        _ => "remote access",
    }
}

impl RemoteAccess {
    pub fn new(t: &Value) -> Self {
        let ports = t
            .get("ports")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_i64().map(|n| n as i32))
                    .collect()
            })
            .unwrap_or_else(|| vec![22, 3389]);
        Self {
            ports,
            burst_per_minute: thr_f64(t, "connections_per_minute", 30.0),
            distinct_sources: thr_f64(t, "distinct_sources", 10.0) as usize,
            flows: HashMap::new(),
            services: HashMap::new(),
            nonstandard: HashMap::new(),
            truncated: false,
        }
    }
}

impl Detector for RemoteAccess {
    fn observe(&mut self, p: &PacketRecord) {
        if p.transport != Some("tcp") {
            return;
        }
        let (Some(src), Some(dst), Some(dport)) = (p.src_ip.clone(), p.dst_ip.clone(), p.dst_port)
        else {
            return;
        };
        let stack: Vec<&str> = p.protocols.split(':').collect();

        // SSH/RDP dissected on a port we do not expect.
        let dissected = if stack.contains(&"ssh") {
            Some("SSH")
        } else if stack.contains(&"rdp") {
            Some("RDP")
        } else {
            None
        };
        if let Some(name) = dissected {
            if !self.ports.contains(&dport) && self.nonstandard.len() < MAX_GROUPS {
                let e = self
                    .nonstandard
                    .entry((src.clone(), dst.clone(), dport))
                    .or_insert((name, vec![], p.ts));
                push_frame(&mut e.1, p.frame);
            }
        }

        if !self.ports.contains(&dport) {
            return;
        }
        let key = (src.clone(), dst.clone(), dport);
        if !self.flows.contains_key(&key) && self.flows.len() >= MAX_GROUPS {
            self.truncated = true;
            return;
        }
        let f = self.flows.entry(key).or_default();
        f.first = Some(f.first.map_or(p.ts, |t| t.min(p.ts)));
        f.last = Some(f.last.map_or(p.ts, |t| t.max(p.ts)));
        f.packets += 1;
        push_frame(&mut f.frames_any, p.frame);

        if p.tcp_syn && !p.tcp_ack {
            f.syns += 1;
            *f.syn_per_minute
                .entry(p.ts.timestamp().div_euclid(60))
                .or_default() += 1;
            push_frame(&mut f.frames_syn, p.frame);
            let skey = (dst, dport);
            if self.services.contains_key(&skey) || self.services.len() < MAX_GROUPS {
                let s = self.services.entry(skey).or_default();
                if s.sources.len() < 10_000 {
                    s.sources.insert(src);
                }
                push_frame(&mut s.frames, p.frame);
                s.first.get_or_insert(p.ts);
            }
        }
    }

    fn findings(&self) -> Vec<Finding> {
        let mut out = Vec::new();
        for ((src, dst, port), f) in &self.flows {
            let svc = service_name(*port);
            let peak = f.syn_per_minute.values().copied().max().unwrap_or(0);
            if peak as f64 >= self.burst_per_minute {
                out.push(Finding {
                    key: format!("remote.conn_burst|{src}|{dst}|{port}"),
                    rule_id: "remote.conn_burst",
                    severity: if peak as f64 >= self.burst_per_minute * 2.0 { "high" } else { "medium" },
                    confidence: clamp01(0.55 + (peak as f64 / (self.burst_per_minute * 4.0)).min(0.35)),
                    title: format!("Burst of {svc} connection attempts to {dst}"),
                    explanation: format!(
                        "{src} opened up to {peak} new {svc} connections per minute to {dst}:{port} ({} SYNs in total; threshold {}). Rapid repeated connection attempts are typical of password guessing or scanning, but can also be automation.",
                        f.syns, self.burst_per_minute
                    ),
                    src_ip: Some(src.clone()),
                    dst_ip: Some(dst.clone()),
                    src_port: None,
                    dst_port: Some(*port),
                    frames: f.frames_syn.clone(),
                    evidence: json!({"service": svc, "peak_per_minute": peak, "syn_total": f.syns, "threshold": self.burst_per_minute, "first_seen": f.first, "last_seen": f.last}),
                    detected_at: f.first.unwrap_or_else(Utc::now),
                });
            }
            if f.packets > f.syns {
                out.push(Finding {
                    key: format!("remote.session_seen|{src}|{dst}|{port}"),
                    rule_id: "remote.session_seen",
                    severity: "info",
                    confidence: 0.3,
                    title: format!("{svc} session observed: {src} to {dst}"),
                    explanation: format!("{src} exchanged {} packets with {dst}:{port} ({svc}). Recorded for context; remote administration is normal in many environments.", f.packets),
                    src_ip: Some(src.clone()),
                    dst_ip: Some(dst.clone()),
                    src_port: None,
                    dst_port: Some(*port),
                    frames: f.frames_any.clone(),
                    evidence: json!({"service": svc, "packets": f.packets, "first_seen": f.first, "last_seen": f.last}),
                    detected_at: f.first.unwrap_or_else(Utc::now),
                });
            }
        }
        for ((dst, port), s) in &self.services {
            if s.sources.len() >= self.distinct_sources {
                let svc = service_name(*port);
                let mut sample: Vec<&String> = s.sources.iter().collect();
                sample.sort();
                out.push(Finding {
                    key: format!("remote.many_sources|{dst}|{port}"),
                    rule_id: "remote.many_sources",
                    severity: "medium",
                    confidence: clamp01(0.5 + (s.sources.len() as f64 / (self.distinct_sources as f64 * 4.0)).min(0.3)),
                    title: format!("Many sources connecting to {svc} on {dst}"),
                    explanation: format!(
                        "{} distinct sources attempted {svc} connections to {dst}:{port} (threshold {}). A wide set of sources can indicate a distributed guessing attempt or a shared jump-host pattern.",
                        s.sources.len(), self.distinct_sources
                    ),
                    src_ip: None,
                    dst_ip: Some(dst.clone()),
                    src_port: None,
                    dst_port: Some(*port),
                    frames: s.frames.clone(),
                    evidence: json!({"service": svc, "distinct_sources": s.sources.len(), "sample_sources": sample.into_iter().take(10).collect::<Vec<_>>()}),
                    detected_at: s.first.unwrap_or_else(Utc::now),
                });
            }
        }
        for ((src, dst, port), (name, frames, ts)) in &self.nonstandard {
            out.push(Finding {
                key: format!("remote.nonstandard_port|{src}|{dst}|{port}"),
                rule_id: "remote.nonstandard_port",
                severity: "medium",
                confidence: 0.6,
                title: format!("{name} on non-standard port {port}"),
                explanation: format!("{src} to {dst}:{port} was dissected as {name}, but the port is not one of the monitored ports {:?}. Remote access on unusual ports is sometimes used to evade filtering.", self.ports),
                src_ip: Some(src.clone()),
                dst_ip: Some(dst.clone()),
                src_port: None,
                dst_port: Some(*port),
                frames: frames.clone(),
                evidence: json!({"service": name, "monitored_ports": self.ports}),
                detected_at: *ts,
            });
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

    fn syn(frame: i64, secs: i64, src: &str, dst: &str, port: i32) -> PacketRecord {
        PacketRecord {
            frame,
            ts: DateTime::from_timestamp(1_700_000_040 + secs, 0).unwrap(),
            src_ip: Some(src.into()),
            dst_ip: Some(dst.into()),
            transport: Some("tcp"),
            dst_port: Some(port),
            tcp_syn: true,
            protocols: "eth:ip:tcp".into(),
            ..Default::default()
        }
    }

    #[test]
    fn syn_burst_is_flagged() {
        let mut d = RemoteAccess::new(&json!({}));
        for i in 0..60 {
            d.observe(&syn(i + 1, i / 4, "192.0.2.40", "198.51.100.22", 22));
        }
        let f = d.findings();
        let b = f
            .iter()
            .find(|x| x.rule_id == "remote.conn_burst")
            .expect("burst");
        assert_eq!(b.severity, "high");
        assert_eq!(b.dst_port, Some(22));
        assert!(b.frames.len() <= 50 && !b.frames.is_empty());
    }

    #[test]
    fn few_connections_are_not_flagged() {
        let mut d = RemoteAccess::new(&json!({}));
        for i in 0..5 {
            d.observe(&syn(i + 1, i, "192.0.2.40", "198.51.100.22", 22));
        }
        assert!(d
            .findings()
            .iter()
            .all(|f| f.rule_id != "remote.conn_burst"));
    }

    #[test]
    fn many_sources_rule() {
        let mut d = RemoteAccess::new(&json!({"distinct_sources": 10}));
        for i in 0..12 {
            d.observe(&syn(
                i + 1,
                i,
                &format!("192.0.2.{}", 100 + i),
                "198.51.100.33",
                3389,
            ));
        }
        let f = d.findings();
        let m = f
            .iter()
            .find(|x| x.rule_id == "remote.many_sources")
            .unwrap();
        assert_eq!(m.evidence["distinct_sources"], 12);
    }

    #[test]
    fn ssh_dissected_on_odd_port() {
        let mut d = RemoteAccess::new(&json!({}));
        let mut p = syn(1, 0, "192.0.2.50", "198.51.100.44", 2222);
        p.tcp_syn = false;
        p.protocols = "eth:ip:tcp:ssh".into();
        d.observe(&p);
        assert!(d
            .findings()
            .iter()
            .any(|f| f.rule_id == "remote.nonstandard_port"));
    }

    #[test]
    fn unrelated_tcp_is_ignored() {
        let mut d = RemoteAccess::new(&json!({}));
        d.observe(&syn(1, 0, "192.0.2.1", "198.51.100.1", 443));
        assert!(d.findings().is_empty());
    }
}
