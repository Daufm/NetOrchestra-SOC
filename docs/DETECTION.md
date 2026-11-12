# Detection rules

Findings are **indicators** (`status: open`, confidence 0-1), never confirmed compromise. Each has an id, profile,
rule, severity, confidence, timestamp, endpoints, explanation, `packet_frames` (original PCAP frame numbers, max 50)
and `supporting_evidence`. Thresholds live in `detection_profiles.thresholds` (JSONB) and can be changed without code.

## `dns_tunnel` (thresholds: `max_label_len` 50, `min_entropy` 3.5, `queries_per_minute` 120, `txt_ratio` 0.3)
Grouped per client + registered domain (last two labels; no Public Suffix List). Responses are ignored.
| Rule | Fires when |
|---|---|
| `dns.long_label` | any label longer than `max_label_len` (high if >= 60) |
| `dns.high_entropy` | >= 5 queries whose leftmost label (>= 16 chars) has Shannon entropy >= `min_entropy` (high at 20+) |
| `dns.high_rate` | peak queries in one minute > `queries_per_minute` |
| `dns.txt_heavy` | >= 10 TXT queries and TXT share >= `txt_ratio` |

## `cleartext_http` (thresholds: `sensitive_params`, `flag_basic_auth`)
| Rule | Fires when |
|---|---|
| `http.basic_auth` | request carries `Authorization: Basic` over HTTP (high) |
| `http.cleartext_login` | POST with a form field whose name contains a sensitive word (high) |
| `http.login_post` | POST to a login-like path with no visible credential field (low) |
| `http.sensitive_query` | sensitive-looking query parameter in the URL (medium) |
**Redaction:** Authorization values are never stored (only the scheme); form fields are stored as *names*; query values of
sensitive keys (built-in list + profile list) become `<redacted>` in findings **and** in stored packets. Not detectable: secrets in the URL path.

## `remote_access` (thresholds: `ports` [22, 3389], `connections_per_minute` 30, `distinct_sources` 10)
Connection attempt = TCP SYN without ACK to a monitored port.
| Rule | Fires when |
|---|---|
| `remote.conn_burst` | one source opens >= `connections_per_minute` connections/min to one service (high at 2x) |
| `remote.many_sources` | >= `distinct_sources` sources hit one service |
| `remote.session_seen` | informational: traffic beyond SYNs on a monitored port |
| `remote.nonstandard_port` | TShark dissects SSH/RDP on a port not in `ports` |
"Timing" is represented by per-minute bucketing and first/last-seen times; there is no off-hours rule yet.

## Adding a rule
Implement it in `analysis/detect/<profile>.rs` (observe -> group -> `findings()` with a stable `key`), add unit tests with
synthetic `PacketRecord`s and a fixture-based case in `tests/forensics_flow.rs`. Keep memory bounded (`MAX_GROUPS`).
