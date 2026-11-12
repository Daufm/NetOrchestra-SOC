#!/usr/bin/env python3
"""Generate deterministic synthetic PCAPs for tests (no real traffic, RFC 5737/3849 documentation addresses)."""
import base64, random, sys
from scapy.all import Ether, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw, wrpcap
random.seed(1234)
out = sys.argv[1] if len(sys.argv) > 1 else "."
MAC = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
t0 = 1_700_000_000.0

def stamp(pkts, start, step):
    for i, p in enumerate(pkts):
        p.time = start + i * step
    return pkts

# --- DNS tunnelling: long, high-entropy labels + TXT queries to one domain, plus benign lookups
pkts = []
alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
for i in range(60):
    label = "".join(random.choice(alphabet) for _ in range(58))
    q = DNSQR(qname=f"{label}.t.evil-tunnel.example.", qtype="TXT" if i % 2 == 0 else "A")
    pkts.append(Ether(**MAC) / IP(src="192.0.2.10", dst="192.0.2.53") / UDP(sport=40000 + i, dport=53) / DNS(rd=1, qd=q))
for name in ["www.example.com.", "mail.example.org.", "docs.example.net."]:
    pkts.append(Ether(**MAC) / IP(src="192.0.2.20", dst="192.0.2.53") / UDP(sport=41000, dport=53) / DNS(rd=1, qd=DNSQR(qname=name)))
wrpcap(f"{out}/dns_tunnel.pcap", stamp(pkts, t0, 0.5))

# --- Cleartext HTTP: Basic auth, login POST, password in query string, plus a benign GET
def http(src, sport, payload):
    return Ether(**MAC) / IP(src=src, dst="198.51.100.80") / TCP(sport=sport, dport=80, flags="PA", seq=1, ack=1) / Raw(payload)
pkts = [
    http("192.0.2.30", 50001, b"GET /admin HTTP/1.1\r\nHost: intranet.example\r\nAuthorization: Basic " + base64.b64encode(b"alice:SuperSecret123") + b"\r\n\r\n"),
    http("192.0.2.30", 50002, b"POST /login HTTP/1.1\r\nHost: intranet.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 38\r\n\r\nusername=alice&password=Hunter2Hunter2"),
    http("192.0.2.31", 50003, b"GET /reset?user=bob&token=abc123secrettoken HTTP/1.1\r\nHost: intranet.example\r\n\r\n"),
    http("192.0.2.32", 50004, b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n"),
]
wrpcap(f"{out}/cleartext_http.pcap", stamp(pkts, t0, 1.0))

# --- Remote access: SYN burst to SSH (one source), many sources to RDP, an established SSH session, an IPv6 SSH SYN
pkts = []
for i in range(60):
    pkts.append(Ether(**MAC) / IP(src="192.0.2.40", dst="198.51.100.22") / TCP(sport=45000 + i, dport=22, flags="S", seq=i))
for i in range(12):
    pkts.append(Ether(**MAC) / IP(src=f"192.0.2.{100 + i}", dst="198.51.100.33") / TCP(sport=46000, dport=3389, flags="S", seq=i))
pkts.append(Ether(**MAC) / IP(src="192.0.2.50", dst="198.51.100.44") / TCP(sport=47000, dport=22, flags="PA", seq=1, ack=1) / Raw(b"SSH-2.0-OpenSSH_9.6\r\n"))
pkts.append(Ether(**MAC) / IPv6(src="2001:db8::5", dst="2001:db8::22") / TCP(sport=48000, dport=22, flags="S"))
wrpcap(f"{out}/remote_access.pcap", stamp(pkts, t0, 0.5))

# --- Benign mix: should produce no findings under any profile
pkts = [Ether(**MAC) / IP(src="192.0.2.60", dst="192.0.2.53") / UDP(sport=42000, dport=53) / DNS(rd=1, qd=DNSQR(qname="www.example.com."))]
pkts.append(Ether(**MAC) / IP(src="192.0.2.60", dst="198.51.100.80") / TCP(sport=51000, dport=80, flags="PA", seq=1, ack=1) / Raw(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"))
wrpcap(f"{out}/benign.pcap", stamp(pkts, t0, 1.0))
