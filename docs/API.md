# API reference

Base path `/api`. JSON errors: `{"error":{"code","message"}}`. Authenticated routes need
`Authorization: Bearer <access JWT>`. Permissions come from the role (ADMIN all; ANALYST everything except user/session/audit/profile
management; VIEWER read-only: `investigations:read`, `jobs:read`, `findings:read`).

## Health and auth
| Route | Auth | Notes |
|---|---|---|
| `GET /health` | - | liveness |
| `GET /ready` | - | 200 when the DB answers, else 503 |
| `/auth/*` (10 routes) | see `AUTH.md` | register, login, refresh, logout, logout-all, me, change-password, admin/reset-password, sessions, sessions/:id |

## Forensics
| Route | Permission | Notes |
|---|---|---|
| `POST /upload` | `jobs:create` | multipart: field `profile` **first**, then `file` (PCAP/PCAPNG). 202 `{job_id, evidence_id, sha256, size_bytes}`. 400 bad type/size/profile; 429 at capacity |
| `POST /stream` | `jobs:create` | JSON `{target_host, ssh_port?, ssh_username, credential_ref?, password?, remote_interface, duration_secs, capture_filter?, profile}`; provide exactly one of `credential_ref` (worker key filename) or transient `password`. Passwords are not persisted or emitted in events; unknown fields are rejected. 503 if the worker is not configured, 403 if the target is not allow-listed |
| `GET /stream/keys` | `jobs:create` | Returns safe filenames from the mounted `NETO_WORKER_KEYS_DIR`; private-key contents are never returned. |
| `POST /stream/:job_id/stop` | `jobs:stop` | owner or admin; 202, 409 if not running |
| `GET /jobs` | `jobs:read` | `status`, `mode`, `limit`(<=200), `offset` -> `{items,total,limit,offset}` |
| `GET /jobs/:id` | `jobs:read` | job + `findings_by_severity` |
| `GET /jobs/:id/packets` | `jobs:read` | `limit`, `offset`, `src_ip`, `dst_ip`, `protocol`, `q`, `frame`, `related_to`, `filter` |
| `GET /jobs/:id/packets/:frame` | `jobs:read` + `evidence:read` | TShark JSON dissection with raw bytes (`layers.frame_raw`); records custody `accessed` |
| `GET /jobs/:id/protocols` | `jobs:read` | protocol counts and stack hierarchy |
| `GET /jobs/:id/evidence` | `evidence:read` | artifacts + custody trail + last verification (records `accessed`) |
| `POST /jobs/:id/evidence/:eid/verify` | `evidence:read` | re-hash and compare; always recorded |
| `GET /jobs/:id/evidence/:eid/download` | `evidence:export` | verifies first; 409 if tampered; records `exported` |
| `GET /findings` | `findings:read` | `job_id`, `profile`, `severity` (comma list), `status`, `q`, `sort` (`detected_at`,`severity`,`confidence`,`src_ip`,`dst_ip`,`rule_id`,`status`), `dir`, `limit`, `offset` |
| `GET /findings/export` | `findings:read` | same filters + `format=csv|json`, max 10 000 rows, formula-injection-safe CSV |
| `GET/PATCH /findings/:id` | `findings:read` / `findings:triage` | status: `open`, `triaged`, `false_positive`, `confirmed` |
| `GET /profiles` | `jobs:read` | detection profiles and thresholds |
| `GET /stats` | `jobs:read` | totals + findings by severity |
| `GET/POST /auth/admin/users` | `users:manage` | Admin-only user listing and creation; created accounts may be `ANALYST` or `VIEWER` and must change the temporary password |
| `PATCH /auth/admin/users/:id` | `users:manage` | Admin-only role change (`ADMIN`, `ANALYST`, `VIEWER`) and enable/disable |
| `POST /auth/admin/reset-password` | `users:manage` | Admin-only password reset; revokes sessions and requires a password change at next login |

Packet `filter` presets are server-side, allow-listed heuristics: `unexpected-protocols`,
`non-standard-ports`, `top-talkers`, `dns-tunneling`, `dga`, `c2-beaconing`,
`suspicious-user-agents`, `anomalous-tls`, `network-scans`, `lateral-movement`,
`malicious-downloads`, `web-attacks`, `cleartext-credentials`, and `asymmetric-flows`.
They return candidate packets for analyst review; they are not verdicts. Flow-level presets
use packet-level indicators until aggregated flow analytics are available.

## WebSocket `GET /ws`
1. Open the socket (browser `Origin` must be in `NETO_CORS_ORIGINS`).
2. Within 5 s send `{"type":"auth","token":"<access jwt>"}` -> `{"type":"auth_ok",...}` (needs `jobs:read`).
3. Receive events `{"id","type","job_id","ts","data"}`; types: `job_started`, `job_progress`, `packet_detected`,
   `threat_detected`, `capture_stopped`, `job_completed`, `job_failed`, `cleanup_completed`.
4. Control messages: `{"type":"resync","missed":N}` (you lagged: refetch), `{"type":"error","code":"token_expired"}`
   (reconnect with a new token), `pong` reply to a text `ping`.
WebSocket handler is live at `/api/ws`.
