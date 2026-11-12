//! Normalized packet model built from `tshark -T fields` output.
//!
//! Extraction uses explicit `-e` fields with control-character delimiters
//! (`\x1e` between fields, `\x1f` between repeated occurrences) so values never need quoting.
//! Missing fields are empty strings, repeated fields are split on the aggregator, and only the
//! first IP layer is used when packets are tunnelled. Human-readable TShark output is never parsed.
use chrono::{DateTime, Utc};

pub const SEP: char = '\u{1e}';
pub const AGG: char = '\u{1f}';

/// Fields requested from TShark, in column order. Availability is validated against the
/// installed TShark (`tshark -G fields`) before the first analysis.
pub const FIELDS: [&str; 31] = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "dns.qry.name",
    "dns.qry.type",
    "dns.flags.response",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.authorization",
    "urlencoded-form.key",
    "tls.handshake.extensions_server_name",
    "http.user_agent",
    "http.content_type",
    "dns.flags.rcode",
    "arp.opcode",
    "tls.handshake.certificate",
    "x509af.notBefore",
    "x509af.notAfter",
    "x509af.issuer",
];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PacketRecord {
    pub frame: i64,
    pub ts: DateTime<Utc>,
    pub len: i32,
    pub protocols: String,
    pub top_protocol: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub ip_version: Option<i16>,
    pub transport: Option<&'static str>,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    pub tcp_syn: bool,
    pub tcp_ack: bool,
    pub dns_is_response: bool,
    /// (query name, query type) pairs.
    pub dns_queries: Vec<(String, Option<i32>)>,
    pub http_method: Option<String>,
    pub http_host: Option<String>,
    pub http_uri: Option<String>,
    /// Raw Authorization header. Used only in memory by detectors; NEVER persisted.
    pub http_auth: Option<String>,
    /// Names (not values) of urlencoded form fields.
    pub form_keys: Vec<String>,
    pub tls_sni: Option<String>,
    pub http_user_agent: Option<String>,
    pub http_content_type: Option<String>,
    pub dns_response_code: Option<i32>,
    pub arp_opcode: Option<i32>,
    pub tls_certificate: Option<String>,
    pub tls_not_before: Option<String>,
    pub tls_not_after: Option<String>,
    pub tls_issuer: Option<String>,
}

#[derive(Debug, PartialEq)]
pub struct ParseError(pub String);

fn nonempty(s: &str) -> Option<&str> {
    let s = s.trim();
    (!s.is_empty()).then_some(s)
}

fn first(s: &str) -> Option<&str> {
    nonempty(s.split(AGG).next().unwrap_or(""))
}

fn truthy(s: &str) -> bool {
    matches!(s.split(AGG).next().unwrap_or(""), "1" | "True" | "true")
}

fn int<T: std::str::FromStr>(s: &str) -> Option<T> {
    first(s).and_then(|v| v.parse().ok())
}

fn parse_epoch(s: &str) -> Option<DateTime<Utc>> {
    let s = first(s)?;
    let (secs, frac) = s.split_once('.').unwrap_or((s, "0"));
    let secs: i64 = secs.parse().ok()?;
    let mut nanos = frac.chars().take(9).collect::<String>();
    while nanos.len() < 9 {
        nanos.push('0');
    }
    DateTime::from_timestamp(secs, nanos.parse().ok()?)
}

/// Application protocol shown to analysts: the deepest layer that is not a payload wrapper.
fn top_protocol(stack: &str) -> Option<String> {
    const WRAPPERS: [&str; 7] = [
        "data",
        "urlencoded-form",
        "media",
        "json",
        "xml",
        "line-based-text",
        "mime_multipart",
    ];
    stack
        .rsplit(':')
        .find(|p| !p.is_empty() && !WRAPPERS.contains(p))
        .map(str::to_string)
}

pub fn parse_line(line: &str) -> Result<PacketRecord, ParseError> {
    let c: Vec<&str> = line.split(SEP).collect();
    if c.len() != FIELDS.len() {
        return Err(ParseError(format!(
            "expected {} columns, got {}",
            FIELDS.len(),
            c.len()
        )));
    }
    let frame: i64 = int(c[0]).ok_or_else(|| ParseError("bad frame.number".into()))?;
    let ts = parse_epoch(c[1]).ok_or_else(|| ParseError("bad frame.time_epoch".into()))?;
    let len: i32 = int(c[2]).unwrap_or(0);
    let protocols = c[3].trim().to_string();

    let (src_ip, dst_ip, ip_version) = if let Some(s) = first(c[4]) {
        (
            Some(s.to_string()),
            first(c[5]).map(str::to_string),
            Some(4),
        )
    } else if let Some(s) = first(c[6]) {
        (
            Some(s.to_string()),
            first(c[7]).map(str::to_string),
            Some(6),
        )
    } else {
        (None, None, None)
    };

    let (transport, src_port, dst_port) = if first(c[8]).is_some() || first(c[9]).is_some() {
        (Some("tcp"), int(c[8]), int(c[9]))
    } else if first(c[10]).is_some() || first(c[11]).is_some() {
        (Some("udp"), int(c[10]), int(c[11]))
    } else if protocols.split(':').any(|p| p == "icmp") {
        (Some("icmp"), None, None)
    } else if protocols.split(':').any(|p| p == "icmpv6") {
        (Some("icmpv6"), None, None)
    } else if ip_version.is_some() {
        (Some("other"), None, None)
    } else {
        (None, None, None)
    };

    let names: Vec<&str> = c[14].split(AGG).filter(|s| !s.trim().is_empty()).collect();
    let types: Vec<&str> = c[15].split(AGG).collect();
    let dns_queries = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            (
                n.trim().to_string(),
                types.get(i).and_then(|t| t.trim().parse().ok()),
            )
        })
        .collect();

    Ok(PacketRecord {
        frame,
        ts,
        len,
        top_protocol: top_protocol(&protocols),
        protocols,
        src_ip,
        dst_ip,
        ip_version,
        transport,
        src_port,
        dst_port,
        tcp_syn: truthy(c[12]),
        tcp_ack: truthy(c[13]),
        dns_is_response: truthy(c[16]),
        dns_queries,
        http_method: first(c[17]).map(str::to_string),
        http_host: first(c[18]).map(str::to_string),
        http_uri: first(c[19]).map(str::to_string),
        http_auth: first(c[20]).map(str::to_string),
        form_keys: c[21]
            .split(AGG)
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .collect(),
        tls_sni: first(c[22]).map(str::to_string),
        http_user_agent: first(c[23]).map(str::to_string),
        http_content_type: first(c[24]).map(str::to_string),
        dns_response_code: int(c[25]),
        arp_opcode: int(c[26]),
        tls_certificate: first(c[27]).map(str::to_string),
        tls_not_before: first(c[28]).map(str::to_string),
        tls_not_after: first(c[29]).map(str::to_string),
        tls_issuer: first(c[30]).map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(overrides: &[(usize, &str)]) -> String {
        let mut cols = vec![String::new(); FIELDS.len()];
        cols[0] = "7".into();
        cols[1] = "1700000000.123456789".into();
        cols[2] = "60".into();
        cols[3] = "eth:ethertype:ip:udp:dns".into();
        for (i, v) in overrides {
            cols[*i] = v.to_string();
        }
        cols.join(&SEP.to_string())
    }

    #[test]
    fn parses_basic_udp_dns() {
        let l = line(&[
            (4, "192.0.2.1"),
            (5, "192.0.2.53"),
            (10, "4000"),
            (11, "53"),
            (14, "a.example.com"),
            (15, "16"),
            (16, "False"),
        ]);
        let p = parse_line(&l).unwrap();
        assert_eq!(p.frame, 7);
        assert_eq!(p.ts.timestamp(), 1_700_000_000);
        assert_eq!(p.ts.timestamp_subsec_nanos(), 123_456_789);
        assert_eq!(
            (p.src_ip.as_deref(), p.ip_version),
            (Some("192.0.2.1"), Some(4))
        );
        assert_eq!((p.transport, p.dst_port), (Some("udp"), Some(53)));
        assert_eq!(p.dns_queries, vec![("a.example.com".to_string(), Some(16))]);
        assert!(!p.dns_is_response);
        assert_eq!(p.top_protocol.as_deref(), Some("dns"));
    }

    #[test]
    fn ipv6_tcp_flags_and_repeated_fields() {
        let l = line(&[
            (3, "eth:ethertype:ipv6:tcp"),
            (6, "2001:db8::5"),
            (7, "2001:db8::22"),
            (8, "48000"),
            (9, "22"),
            (12, "True"),
            (13, "False"),
            (14, &format!("a.example{AGG}b.example")),
            (15, &format!("1{AGG}28")),
            (21, &format!("user{AGG}password")),
        ]);
        let p = parse_line(&l).unwrap();
        assert_eq!(p.ip_version, Some(6));
        assert!(p.tcp_syn && !p.tcp_ack);
        assert_eq!(p.dns_queries.len(), 2);
        assert_eq!(p.dns_queries[1], ("b.example".to_string(), Some(28)));
        assert_eq!(p.form_keys, ["user", "password"]);
    }

    #[test]
    fn tunnelled_packets_use_first_ip_layer() {
        let l = line(&[
            (4, &format!("10.0.0.1{AGG}10.9.9.9")),
            (5, &format!("10.0.0.2{AGG}10.8.8.8")),
        ]);
        let p = parse_line(&l).unwrap();
        assert_eq!(p.src_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(p.dst_ip.as_deref(), Some("10.0.0.2"));
    }

    #[test]
    fn missing_fields_are_none_not_errors() {
        let p = parse_line(&line(&[(3, "eth:ethertype:arp")])).unwrap();
        assert_eq!((p.src_ip, p.transport, p.http_method), (None, None, None));
    }

    #[test]
    fn top_protocol_skips_payload_wrappers() {
        assert_eq!(
            top_protocol("eth:ethertype:ip:tcp:http:urlencoded-form").as_deref(),
            Some("http")
        );
        assert_eq!(top_protocol("eth:ip:tcp:data").as_deref(), Some("tcp"));
    }

    #[test]
    fn malformed_lines_are_rejected() {
        assert!(parse_line("garbage").is_err());
        assert!(parse_line(&line(&[(0, "x")])).is_err());
        assert!(parse_line(&line(&[(1, "")])).is_err());
    }

    #[test]
    fn short_fractional_seconds_are_padded() {
        let p = parse_line(&line(&[(1, "1700000000.5")])).unwrap();
        assert_eq!(p.ts.timestamp_subsec_nanos(), 500_000_000);
    }
}
