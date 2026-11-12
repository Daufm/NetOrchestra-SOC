# NetOrchestra-SOC

[![CI](https://github.com/Daufm/NetOrchestra-SOC/actions/workflows/ci.yml/badge.svg)](https://github.com/Daufm/NetOrchestra-SOC/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg)](https://golang.org)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16%2B-336791.svg)](https://www.postgresql.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Enterprise Network Forensics & Remote Capture Orchestration Platform.**

Designed for Security Operations Centers (SOCs), incident response teams, and air-gapped banking/financial LANs requiring strict chain of custody, true least-privilege remote capture, and real-time threat detection.

---

## System Architecture

* **Core Backend:** Rust (Axum, Tokio, SQLx) + PostgreSQL 16/17, Argon2id authentication, rotating JWT/refresh sessions, and granular RBAC (`ADMIN`, `ANALYST`, `VIEWER`).
* **Forensic Ingestion & TShark Pipeline:** Bounded streaming pipeline with dual-mode TShark analysis (`-T fields` for bulk database extraction, `-T json` for per-frame dissection).
* **Dual Remote Capture Engine (Go Worker):**
  * **Primary:** `tcpdump` over authenticated SSH.
  * **Automatic Fallback (NETOU):** Native Linux `AF_PACKET` capture helper written in Go. Triggers automatically if `tcpdump` is absent or restricted.
  * **Least Privilege:** Neither engine requires `sudo` or `root`—both execute safely via Linux capabilities (`CAP_NET_RAW`).
* **Forensic Custody & Safeguards:**
  * Read-only evidence file sealing (`0400`) and immutable DB trigger protection (`forbid_mutation`).
  * Live kernel filesystem metrics (`libc::statvfs`) and automatic **<10% disk capacity cutoff** to prevent disk exhaustion and data corruption.
* **SOC Frontend:** Single-page application built with React 18, Vite, and Tailwind CSS. Features live WebSocket telemetry (`/api/ws`), hex frame inspector, and a dedicated **Executive / CISO Viewer Dashboard**.
* **Air-Gapped LAN Ready:** 100% self-contained appliance. Zero external CDN, web font, or Cloudflare dependencies required.

> **Technical Documentation:** Read the [Architecture Guide](docs/ARCHITECTURE.md), [API Specification](docs/API.md), [Detection Mechanics](docs/DETECTION.md), [SSH Remote Setup](docs/SSH_REMOTE_SETUP.md), and [Next Version Roadmap](docs/NEXT_VERSION_ROADMAP.md) for full design specifications.

---

## Key Capabilities

* **Sealed PCAP/PCAPNG Ingestion:** Upload captures (`POST /api/evidence/upload`) with on-the-fly streaming SHA-256 calculation, read-only file sealing, and tamper-detection verification (`POST /api/jobs/{id}/evidence/{evidence_id}/verify`).
* **Automated Dual-Engine Remote Capture:** Stream live network traffic over SSH (`POST /api/stream`). Detects remote capabilities and falls back gracefully from `tcpdump` to `netou` without admin intervention.
* **Automated Threat Detection Engines:**
  * `dns_tunnel`: Shannon entropy scoring, high-frequency subdomain counting, and TXT/NULL record inspection.
  * `cleartext_http`: Flags unencrypted credentials, Basic Auth tokens, and sensitive forms (redacts secrets before database insertion).
  * `remote_access`: Detects brute-force connection bursts and anomalous SSH/RDP services running on non-standard ports.
* **Interactive Forensic Packet Inspector:** 14 automated heuristic filter modules (C2 beacon candidates, DNS tunneling, lateral movement, SQLi/traversal web attacks, rogue TLS, and suspicious user-agents).
* **Forensic Storage Telemetry & Auto-Cutoff:** Real-time `/api/metrics/disk` monitoring tracks evidence volume, used percentage, and available bytes. If free storage falls below 10%, captures stop gracefully to safeguard system integrity.
* **Executive / CISO Oversight Dashboard:** Role-based dashboard for `VIEWER` accounts presenting high-level analytical metrics, monitored servers, investigator attribution, and threat distribution charts.
* **Production-Hardened Security:** Non-root execution (`neto:10001`), Docker capability drop (`cap_drop: ALL`), read-only root filesystems, PostgreSQL port isolation, and zero-leeway JWT claim verification.

---

## Technology Stack & Requirements

| Component | Minimum Version | Production Notes |
|---|---|---|
| **Rust** | $\ge$ 1.85 | Edition 2024 backend daemon (Axum, Tokio, SQLx) |
| **PostgreSQL** | 16+ (tested on 16/17) | Append-only forensic triggers; requires `CREATEDB` for integration tests |
| **TShark** | 4.x (tested 4.2.2) | Network packet dissection; runs unprivileged without SUID |
| **Go** | $\ge$ 1.22 | SSH worker and `netou` fallback binary |
| **Node.js** | $\ge$ 20 | Frontend compilation (React 18, Vite) |
| **Docker & Compose** | v2+ | Optional; recommended for self-contained appliance deployment |

---

## Quick Start (Production via Docker & GHCR)

Deploy the pre-built multi-service SOC stack using Docker Compose:

### 1. Download Compose Configuration
```bash
mkdir -p netorchestra && cd netorchestra
curl -fsSL https://raw.githubusercontent.com/Daufm/NetOrchestra-SOC/main/docker-compose.prod.yml -o docker-compose.yml
```

### 2. Generate Secrets & Environment Configuration
```bash
cat <<EOF > .env
# Database configuration
POSTGRES_USER=netorchestra
POSTGRES_DB=netorchestra
POSTGRES_PASSWORD=$(openssl rand -hex 24)

# Security and Authentication
NETO_JWT_SECRET=$(openssl rand -base64 48)
NETO_BOOTSTRAP_TOKEN=$(openssl rand -hex 24)

# Network and Port Exposure
NETO_HTTP_HOST=127.0.0.1
NETO_HTTP_PORT=9094
EOF
```

### 3. Launch Services
```bash
docker compose up -d
```
The SOC dashboard will be available at `http://localhost:9094`.

### 4. Provision Initial Administrator
```bash
BOOTSTRAP_TOKEN=$(grep NETO_BOOTSTRAP_TOKEN .env | cut -d '=' -f2)

curl -X POST http://localhost:9094/api/auth/register \
  -H 'Content-Type: application/json' \
  -H "X-Bootstrap-Token: $BOOTSTRAP_TOKEN" \
  -d '{"username":"soc_admin","password":"ChooseAStrongPassword123!"}'
```

---

## Quick Start (Local Development)

### 1. Configure Environment
```bash
cp .env.example .env

# Generate required cryptographic secrets
export NETO_JWT_SECRET=$(openssl rand -base64 48)
export NETO_BOOTSTRAP_TOKEN=$(openssl rand -hex 24)
export POSTGRES_PASSWORD=$(openssl rand -hex 24)
export DATABASE_URL="postgres://netorchestra:${POSTGRES_PASSWORD}@localhost:5432/netorchestra"

# Apply secrets to .env
sed -i "s|CHANGE_ME_generate_with_openssl_rand_base64_48|${NETO_JWT_SECRET}|g" .env
sed -i "s|CHANGE_ME_generate_with_openssl_rand|${POSTGRES_PASSWORD}|g" .env
```

### 2. Run Database & Backend
```bash
# Start PostgreSQL
docker compose up -d db

# Run backend migrations and start server
cd backend
cargo run
```

### 3. Run Frontend
```bash
cd frontend
npm install
npm run dev
```

---

## Testing & Quality Assurance

NetOrchestra-SOC enforces strict compile-time checks, comprehensive unit tests, and integration suites:

```bash
# Run unit tests across all crates (74 unit tests, offline SQLx validation)
cargo test --manifest-path backend/Cargo.toml --lib

# Build Go worker and NETOU fallback binaries
cd worker && go test ./... && go build ./cmd/worker && go build ./cmd/netou

# Run frontend ESLint and production Vite build
cd frontend && npm run lint && npm run build
```

---

## Project Documentation

Detailed architecture specifications, forensic schemas, and administration manuals:

| Document | Purpose & Scope |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Pipeline mechanics, streaming concurrency, data flows, and state machines |
| [docs/API.md](docs/API.md) | REST API endpoints, parameter schemas, permissions, and status codes |
| [docs/DETECTION.md](docs/DETECTION.md) | Heuristic algorithms, entropy formulas, thresholds, and credential redaction |
| [docs/SSH_REMOTE_SETUP.md](docs/SSH_REMOTE_SETUP.md) | Dedicated SSH user provisioning, key generation, and `CAP_NET_RAW` setup |
| [docs/WORKER.md](docs/WORKER.md) | Go worker RPC protocols, streaming buffers, and target allow-listing |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat models, capability drops, container sandboxing, and audit trails |
| [docs/AUTH.md](docs/AUTH.md) | Argon2id parameters, JWT claims, CSRF mitigation, and RBAC matrix |
| [docs/DATABASE.md](docs/DATABASE.md) | PostgreSQL schema, forensic triggers, indexing strategies, and migrations |
| [docs/NEXT_VERSION_ROADMAP.md](docs/NEXT_VERSION_ROADMAP.md) | Roadmap for upcoming features, multi-gigabit ring buffers, and clustering |

---

## Operational Safety & Legal Compliance

* **Authorized Monitoring Only:** NetOrchestra-SOC must only be deployed on networks and infrastructure you own or have explicit, documented authorization to monitor.
* **Target Isolation:** Remote capture is restricted by strict server-side CIDR allow-lists (`NETO_ALLOWED_TARGETS`).
* **Evidence Admissibility:** The platform records cryptographic checksums, analyst attributions, and immutable access timestamps to uphold judicial chain-of-custody standards.

---

## License

NetOrchestra-SOC is distributed under the terms of the [MIT License](LICENSE).
