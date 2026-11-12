# NetOrchestra-SOC

Network Forensics & Remote Orchestration Platform.

* **Backend:** Rust (Axum, Tokio, SQLx) + PostgreSQL 17+, first-party JWT auth, RBAC.
* **Analysis:** TShark (`-T fields` for bulk extraction, `-T json` for per-packet dissection).
* **Remote capture:** a Go SSH worker streams `tcpdump` output from authorised hosts.
* **Frontend:** React + Vite + Tailwind SOC dashboard .

> **Status:** Read the [Architecture](docs/ARCHITECTURE.md), [API Documentation](docs/API.md), and [Detection Guide](docs/DETECTION.md) for platform design, endpoints, and detection mechanics.

## What works today

* Upload a PCAP/PCAPNG (`POST /api/upload`) -> stored once as sealed evidence with SHA-256 and chain of custody
  -> analysed with TShark -> packets in PostgreSQL -> findings from the chosen detection profile.
* Three detection profiles: `dns_tunnel`, `cleartext_http` (credentials redacted), `remote_access` (SSH/RDP).
* Live remote capture API (`POST /api/stream`, `/stop`): input-validated, allow-listed targets, bounded
  streaming pipeline (worker -> evidence file + hasher + TShark). Verified against a mock worker.
* Evidence verification, tamper detection, verified export; every access recorded.
* Auth: Argon2id, 15-minute access JWT, rotating 7-day refresh cookie with reuse detection, CSRF, lockout,
  sessions, admin reset, first-admin bootstrap, append-only audit log.
* Findings API with search, filters, sorting, pagination, triage, CSV/JSON export.
* `GET /api/ws` live events (job_started, job_progress, packet_detected, threat_detected, capture_stopped,
  job_completed, job_failed, cleanup_completed).

## Requirements

| Tool | Version | Notes |
|---|---|---|
| Rust | >= 1.85 | edition-2024 crates in the dependency tree |
| PostgreSQL | 17+ target (tested on 16) | role needs `CREATEDB` for the test suite |
| TShark | 4.x (tested 4.2.2) | `apt install tshark`; must not run as root in production |
| Go | >= 1.22 | worker; see `docs/WORKER.md` about `GOPROXY` |
| Node | >= 20 | frontend |
| Python 3 + scapy | optional | only to regenerate test PCAPs |

## Quick start (Docker / GitHub Container Registry)

To run the pre-built container image from GitHub Container Registry (GHCR) without needing local build tools:

### 1. Download the Docker Compose file
```bash
mkdir netorchestra && cd netorchestra
curl -fsSL https://raw.githubusercontent.com/<YOUR_GITHUB_USER_OR_ORG>/netorchestra-soc/main/docker-compose.prod.yml -o docker-compose.yml
```

### 2. Create your `.env` file with required secrets
Create a `.env` file in the same directory:
```bash
cat <<EOF > .env
# Database configuration
POSTGRES_USER=netorchestra
POSTGRES_DB=netorchestra
POSTGRES_PASSWORD=$(openssl rand -hex 24)

# Security and Authentication
NETO_JWT_SECRET=$(openssl rand -base64 48)
NETO_BOOTSTRAP_TOKEN=$(openssl rand -hex 24)

# Port to expose (default: 8080)
NETO_HTTP_PORT=8080
EOF
```

### 3. Start the application
```bash
docker compose up -d
```
The application will be live at `http://localhost:8080`.

### 4. Create the initial Admin user
```bash
BOOTSTRAP_TOKEN=$(grep NETO_BOOTSTRAP_TOKEN .env | cut -d '=' -f2)

curl -X POST http://localhost:8080/api/auth/register \
  -H 'Content-Type: application/json' \
  -H "X-Bootstrap-Token: $BOOTSTRAP_TOKEN" \
  -d '{"username":"admin","password":"choose-a-strong-password-12+"}'
```

---

## Quick start (development)

```bash
cp .env.example .env             # then edit it (see below)
# generate real secrets:
openssl rand -base64 48          # -> NETO_JWT_SECRET
openssl rand -hex 24             # -> NETO_BOOTSTRAP_TOKEN
# in .env also set DATABASE_URL, and for plain-http local dev: NETO_COOKIE_SECURE=false
#   NETO_CORS_ORIGINS=http://localhost:5173
#   NETO_EVIDENCE_DIR=./data/evidence   NETO_WORKSPACE_DIR=./data/workspace

set -a; . ./.env; set +a
cd backend && cargo run          # migrates the DB on start; http://localhost:8080/api/health
```

Create the first admin (only works while the users table is empty):

```bash
curl -X POST http://localhost:8080/api/auth/register -H 'Content-Type: application/json' \
  -H "X-Bootstrap-Token: $NETO_BOOTSTRAP_TOKEN" \
  -d '{"username":"admin","password":"use-12-or-more-characters"}'
```

Try an upload:

```bash
TOKEN=$(curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"use-12-or-more-characters"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -X POST localhost:8080/api/upload -H "Authorization: Bearer $TOKEN" \
  -F profile=dns_tunnel -F file=@tests/fixtures/dns_tunnel.pcap     # profile field MUST come first
curl -H "Authorization: Bearer $TOKEN" 'localhost:8080/api/findings?sort=confidence&dir=desc'
```

## Testing

```bash
make check      # fmt/lint/build/test for backend, worker, frontend - needs no database
make test-db    # the 30 integration tests; needs DATABASE_URL (role with CREATEDB) and tshark installed
```

Expected: backend 72 unit tests; 30 integration tests; Go and frontend suites pass.

## Documentation

| File | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, data flows, system design |
| [docs/API.md](docs/API.md) | endpoints, parameters, permissions, responses |
| [docs/DETECTION.md](docs/DETECTION.md) | detection rules, profiles, thresholds, redaction |
| [docs/SECURITY.md](docs/SECURITY.md) | security controls, threat models, hardening checklist |
| [docs/AUTH.md](docs/AUTH.md) | tokens, CSRF, bootstrap, RBAC model |
| [docs/DATABASE.md](docs/DATABASE.md) | PostgreSQL schema, integrity rules, SQLx offline |
| [docs/WORKER.md](docs/WORKER.md) | Go worker protocol, SSH execution, remote host setup |
| [docs/SSH_REMOTE_SETUP.md](docs/SSH_REMOTE_SETUP.md) | Step-by-step SSH key generation, remote user setup, capabilities |

## Safety notes

Only capture traffic you are authorised to capture. Remote capture is disabled until the operator sets both
`NETO_WORKER_BIN` and `NETO_ALLOWED_TARGETS`. Findings are *indicators*, never confirmed compromise.
