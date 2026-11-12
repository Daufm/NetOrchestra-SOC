//! Minimal CIDR matching for the remote-capture target allow-list.
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

fn to_u128(ip: IpAddr) -> (u128, u8) {
    match ip {
        IpAddr::V4(v4) => (u32::from(v4) as u128, 32),
        IpAddr::V6(v6) => (u128::from(v6), 128),
    }
}

impl Cidr {
    /// Parse `a.b.c.d/len`, `x::y/len`, or a bare address (treated as a /32 or /128 host).
    pub fn parse(s: &str) -> Result<Self, String> {
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = ip
            .trim()
            .parse()
            .map_err(|_| format!("invalid address '{s}'"))?;
        let max = to_u128(addr).1;
        let prefix = match prefix {
            None => max,
            Some(p) => p
                .trim()
                .parse::<u8>()
                .map_err(|_| format!("invalid prefix in '{s}'"))?,
        };
        if prefix > max {
            return Err(format!("prefix too long in '{s}'"));
        }
        Ok(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        if self.addr.is_ipv4() != ip.is_ipv4() {
            return false;
        }
        let (net, bits) = to_u128(self.addr);
        let (cand, _) = to_u128(ip);
        let shift = (bits - self.prefix) as u32;
        if shift >= 128 {
            return true;
        }
        (net >> shift) == (cand >> shift)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn v4_ranges() {
        let c = Cidr::parse("10.1.0.0/16").unwrap();
        assert!(c.contains(ip("10.1.255.9")));
        assert!(!c.contains(ip("10.2.0.1")));
        assert!(!c.contains(ip("::1")));
    }

    #[test]
    fn host_and_everything() {
        assert!(Cidr::parse("192.0.2.7").unwrap().contains(ip("192.0.2.7")));
        assert!(!Cidr::parse("192.0.2.7").unwrap().contains(ip("192.0.2.8")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
    }

    #[test]
    fn v6_ranges() {
        let c = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains(ip("2001:db8:1::5")));
        assert!(!c.contains(ip("2001:db9::1")));
    }

    #[test]
    fn rejects_garbage() {
        assert!(Cidr::parse("nope").is_err());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("10.0.0.0/x").is_err());
    }
}
