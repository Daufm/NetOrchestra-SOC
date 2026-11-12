//! Input validation for remote-capture requests. These values end up in a command executed
//! on a remote host, so validation is strict allow-listing, not escaping alone (the worker
//! additionally single-quotes every argument).
use std::net::IpAddr;

use crate::error::AppError;

fn bad(msg: &str) -> AppError {
    AppError::BadRequest(msg.to_string())
}

pub fn host(s: &str) -> Result<IpAddr, AppError> {
    s.trim()
        .parse()
        .map_err(|_| bad("target_host must be an IPv4 or IPv6 address"))
}

pub fn username(s: &str) -> Result<(), AppError> {
    let ok = !s.is_empty()
        && s.len() <= 32
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    ok.then_some(())
        .ok_or_else(|| bad("ssh_username contains unsupported characters"))
}

pub fn credential_ref(s: &str) -> Result<(), AppError> {
    let ok = !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    ok.then_some(()).ok_or_else(|| {
        bad("credential_ref must be 1-64 characters of letters, digits, '_', '-', '.'")
    })
}

pub fn interface(s: &str) -> Result<(), AppError> {
    let ok = !s.is_empty()
        && s.len() <= 32
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'));
    ok.then_some(())
        .ok_or_else(|| bad("remote_interface contains unsupported characters"))
}

/// BPF capture filter: a conservative character set with no quotes, backticks, `$`, `;`,
/// backslashes or newlines, so it can never break out of a quoted shell argument.
pub fn bpf_filter(s: &str) -> Result<(), AppError> {
    let ok = s.len() <= 512
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    ' ' | '.'
                        | ':'
                        | '/'
                        | '('
                        | ')'
                        | '!'
                        | '='
                        | '<'
                        | '>'
                        | '&'
                        | '|'
                        | '_'
                        | '-'
                        | '['
                        | ']'
                )
        });
    ok.then_some(())
        .ok_or_else(|| bad("capture_filter contains unsupported characters"))
}

/// File name for display only (never used as a path).
pub fn display_filename(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base.chars().filter(|c| !c.is_control()).take(200).collect();
    if cleaned.trim().is_empty() {
        "capture".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert!(host("192.0.2.1").is_ok() && host("2001:db8::1").is_ok());
        assert!(host("example.com").is_err() && host("1.2.3.4; id").is_err() && host("").is_err());
    }

    #[test]
    fn usernames_and_refs() {
        assert!(username("capture_user").is_ok() && username("a.b-c").is_ok());
        for bad in ["", "1abc", "a b", "a;b", "$(id)", "a`b`", &"x".repeat(33)] {
            assert!(username(bad).is_err(), "{bad}");
        }
        assert!(credential_ref("soc-key_1.prod").is_ok());
        for bad in ["", ".hidden", "../x", "a/b", "a b", &"x".repeat(65)] {
            assert!(credential_ref(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn interfaces() {
        assert!(
            interface("eth0").is_ok()
                && interface("br-lan.10").is_ok()
                && interface("eth0:1").is_ok()
        );
        for bad in [
            "",
            "eth0;reboot",
            "eth0 -w /x",
            "$(id)",
            "a/b",
            &"e".repeat(33),
        ] {
            assert!(interface(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn bpf_filters_block_shell_metacharacters() {
        assert!(bpf_filter("").is_ok());
        assert!(bpf_filter("tcp port 22 and not host 10.0.0.1").is_ok());
        assert!(bpf_filter("tcp[13] & 2 != 0 || udp").is_ok());
        for bad in [
            "port 22; reboot",
            "port 22 `id`",
            "$(id)",
            "a' ; id #",
            "a\"b",
            "x\ny",
            "a\\b",
            "{a}",
            "a*b",
            "a~b",
        ] {
            assert!(bpf_filter(bad).is_err(), "{bad:?}");
        }
        assert!(bpf_filter(&"a".repeat(513)).is_err());
    }

    #[test]
    fn filenames_are_sanitised() {
        assert_eq!(display_filename("../../etc/passwd"), "passwd");
        assert_eq!(display_filename("C:\\x\\cap.pcap"), "cap.pcap");
        assert_eq!(display_filename("a\u{0}b\nc.pcap"), "abc.pcap");
        assert_eq!(display_filename(""), "capture");
        assert!(display_filename(&"a".repeat(500)).len() <= 200);
    }
}
