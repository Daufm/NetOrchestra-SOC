# NetOrchestra-SOC — Next Version Roadmap (v0.2.0+)

> **Status**: Living document. Items marked `🎯` are quick wins; `🏗️` need design; `🔬` are research spikes.
> All new capabilities **must** preserve the existing privilege boundaries and evidence-integrity guarantees.

---

## 1. Core Forensic Enhancements

| ID | Feature | Description | Effort | Label |
|----|---------|-------------|--------|-------|
| F-01 | **Zeek (Bro) Integration** | Run Zeek as a sidecar container on ingested PCAPs → parse `conn.log`, `http.log`, `ssl.log`, `files.log` → insert into `zeek_connections`, `zeek_http`, `zeek_tls`, `zeek_files` tables. Expose via `/api/zeek/*` endpoints and UI tabs. | Medium | 🏗️ |
| F-02 | **File/Object Extraction & Sandbox Hook** | Carve files from HTTP, SMTP, FTP, SMB using Zeek `files.log` or TShark `--export-objects`. Compute SHA-256, store in object storage (MinIO/S3), record in `extracted_files` table. Optional: submit to VirusTotal API / local YARA / CAPE sandbox → enrich findings with `malware_family`, `iocs`. | Medium-High | 🏗️ |
| F-03 | **Session / Conversation Reconstruction** | Derive `sessions` table (5-tuple + start/end + byte/packet counts + app proto + findings) from `packets` at ingest end. UI: session list, timeline (mermaid/sequence diagram), per-session packet filter, MITRE ATT&CK tags. | Medium | 🏗️ |
| F-04 | **Multi-PCAP Correlation Engine** | Cross-job queries: “Show all jobs where IP `10.0.0.5` resolved `bad-domain.xyz` in last 30d.” Implement via materialized view `packet_index` (job_id, src_ip, dst_ip, dns_query, tls_sni, http_host) + `/api/correlate` endpoint. | Medium | 🏗️ |
| F-05 | **Case / Investigation Workspace** | Group jobs, analyst notes, tags, evidence links. Export **forensic bundle**: manifest (JSON + hashes), selected PCAPs, findings CSV, timeline, chain-of-custody PDF. API: `POST /api/cases`, `POST /api/cases/:id/bundle`. | Medium | 🏗️ |

---

## 2. Detection & Intelligence

| ID | Feature | Description | Effort | Label |
|----|---------|-------------|--------|-------|
| D-01 | **MITRE ATT&CK Mapping** | Add `mitre_technique` (e.g., `T1071.004`) and `tactic` (e.g., `command-and-control`) to each detector rule. Seed data in `detection_profiles.thresholds` JSONB. UI: coverage heatmap, filter by technique. | Low | 🎯 |
| D-02 | **GeoIP / ASN Enrichment** | Embed MaxMind GeoLite2-Country + ASN DB (mmdb). At ingest, enrich `src_ip`/`dst_ip` → `geo_country`, `asn`, `asn_name`. Findings + packet grid show badges. | Low | 🎯 |
| D-03 | **Sigma / Suricata Rule Import** | Option A: Compile Sigma YAML → Rust detector module (codegen). Option B: Run Suricata in IDS mode (`-r file.pcap -l eve.json`) alongside TShark → ingest `eve.json` alerts as `external_findings`. Start with Option B. | High | 🔬 |
| D-04 | **Baseline / Off-Hours Profiling** | Per-subnet learning window (7–30d): top ports, DNS qpm, TLS SNI set, HTTP host set. Flag deviations (new SNI, port spike, DNS rate anomaly) as `baseline_deviation` findings. Configurable sensitivity. | Medium | 🏗️ |
| D-05 | **Public Suffix List for DNS Tunnel Detector** | Replace “last two labels” with `publicsuffix` crate → accurate registered domain extraction (handles `.co.uk`, `.github.io`, etc.). Reduces false positives. | Low | 🎯 |

---

## 3. Remote Capture & Sensor Fleet

| ID | Feature | Description | Effort | Label |
|----|---------|-------------|--------|-------|
| R-01 | **ARM64 / Sensor Image** | Publish `ghcr.io/<org>/netorchestra-sensor:latest` (worker + NETOU + SSH key + systemd unit). One-command enroll: `curl -fsSL .../enroll.sh | sudo bash -s <controller_url> <token>`. Docs: `docs/SENSOR_DEPLOYMENT.md`. | Low (packaging) | 🎯 |
| R-02 | **Sensor Health Telemetry** | Worker emits periodic `heartbeat` event (CPU, mem, disk, interface stats, capture backend). Backend stores in `sensor_health` table. UI: sensor fleet view, offline alert. | Low | 🎯 |
| R-03 | **WireGuard / Tailscale Overlay Option** | Document / script zero-trust tunnel between controller and sensors (alternative to raw SSH over Internet). | Low | 📝 |
| R-04 | **Capture Scheduling / Cron** | `POST /api/stream/schedule` with cron expression, duration, filter → recurring jobs. Backend uses `tokio-cron-scheduler`. | Medium | 🏗️ |

---

## 4. Analyst Experience (Frontend)

| ID | Feature | Description | Effort | Label |
|----|---------|-------------|--------|-------|
| U-01 | **Saved Filter Presets** | Per-user saved column sets, filters, sort orders for Findings / Packets / Jobs grids. Persist in `user_preferences` JSONB. | Low | 🎯 |
| U-02 | **Keyboard Shortcuts & Command Palette** | `?` → help, `/` → focus search, `j/k` → navigate rows, `Enter` → open inspector, `Esc` → close modal. | Low | 🎯 |
| U-03 | **Dark/Light Theme Toggle** | Tailwind `dark:` mode + `localStorage` persistence. | Low | 🎯 |
| U-04 | **Real-Time Collaboration Cursors** | Show other analysts’ selections in Packet Inspector / Threat Grid (WebSocket presence). | Medium | 🔬 |
| U-05 | **Evidence Hash Re-Verify Button** | One-click “Verify Integrity” on evidence detail → streams file through SHA-256 → compares to DB → toast result. | Low | 🎯 |

---

## 5. Platform & Operations

| ID | Feature | Description | Effort | Label |
|----|---------|-------------|--------|-------|
| P-01 | **Object Storage Backend for Evidence** | Pluggable `EvidenceStore` trait: `LocalFs` (current), `S3Compatible` (MinIO, AWS, GCS), `AzureBlob`. Evidence files never in DB; only metadata + hash + storage URI. | Medium | 🏗️ |
| P-02 | **Structured Audit Log Export** | `GET /api/audit/export?from=&to=&format=jsonl|csv` → streaming download. Include request-id correlation. | Low | 🎯 |
| P-03 | **Automated Dependency Audits in CI** | `cargo audit`, `npm audit`, `govulncheck` as required CI gates. Fail build on `high`/`critical`. | Low | 🎯 |
| P-04 | **Database Backup/Restore Test in CI** | Nightly: `pg_dump` → restore to temp DB → run integration tests → verify hash manifests. | Medium | 🏗️ |
| P-05 | **OpenTelemetry / Prometheus Metrics** | Export `http_requests_total`, `capture_job_duration_seconds`, `packets_per_second`, `detection_findings_total`, `worker_health`. Grafana dashboard JSON in `deploy/grafana/`. | Medium | 🏗️ |

---

## 6. Compliance & Legal

| ID | Feature | Description | Effort | Label |
|----|---------|-------------|--------|-------|
| C-01 | **Chain-of-Custody PDF Generator** | `GET /api/evidence/:id/custody.pdf` → signed PDF with hash, timestamps, analyst names, actions (ingest, verify, export, analyze). Uses `printpdf` crate. | Low | 🎯 |
| C-02 | **GDPR / Data Retention Policies** | Configurable TTL per table (`packets`, `threat_findings`, `audit_logs`). Cron job purges + logs audit entry. Admin UI to set policies. | Medium | 🏗️ |
| C-03 | **FIPS 140-3 Mode Toggle** | Build flag `fips` → forces `aws-lc-rs` / `ring` for crypto, disables non-FIPS algorithms. Document limitations. | High | 🔬 |

---

## 7. Prioritised Sprint Plan (Suggested)

| Sprint | Theme | Items | Target |
|--------|-------|-------|--------|
| **Sprint 1** | **Quick Wins & Intel** | D-01, D-02, D-05, U-01, U-05, P-02, C-01 | 2 weeks |
| **Sprint 2** | **Sensor Fleet** | R-01, R-02, R-03 | 2 weeks |
| **Sprint 3** | **Zeek + File Extraction** | F-01, F-02 (Zeek path only) | 3 weeks |
| **Sprint 4** | **Session Graph + Correlation** | F-03, F-04 | 3 weeks |
| **Sprint 5** | **Case Workspace + Sigma/Suricata** | F-05, D-03 (Option B) | 3 weeks |
| **Sprint 6** | **Platform Hardening** | P-01, P-03, P-04, P-05 | 2 weeks |

---

## 8. Architectural Guardrails (Non-Negotiable)

1. **Privilege Boundaries Stay Intact**
   - New heavy parsers (Zeek, Suricata, YARA, CAPE) run in **separate containers/processes**, never in the Rust API.
   - Communication via gRPC / JSON over Unix sockets / object storage events.

2. **Evidence Never Enters the Database**
   - PCAPs, carved files, Zeek logs, Suricata eve.json → **object storage** (S3/MinIO/local).
   - DB stores only: metadata, SHA-256, storage URI, custody records.

3. **Detectors Remain Pluggable**
   - New profile = new Rust module implementing `Detector` trait in `analysis/detect/`.
   - Zero changes to `pipeline.rs` or `runner.rs`.

4. **SQLx Compile-Time Safety**
   - Every new table → migration + `query_as!` / `query!` macros.
   - CI runs `cargo sqlx prepare --check --all-targets` (offline mode).

5. **Resource Bounds Everywhere**
   - Channels: bounded (`tokio::sync::mpsc::channel(32)`).
   - Groups/Frames/Findings: hard caps (`MAX_GROUPS`, `MAX_FRAMES_PER_FINDING`, `MAX_FINDINGS_PER_JOB`).
   - Concurrency: semaphore slots (`NETO_MAX_CONCURRENT_JOBS`).

6. **Secrets Management**
   - No hardcoded secrets. All via env / Docker secrets / Vault.
   - Startup validates entropy (rejects placeholder values).

---

## 9. Contribution Guidelines for New Features

| Step | Action |
|------|--------|
| 1 | Open GitHub Issue with `rfc` label → design discussion. |
| 2 | Add migration (if DB change) in `backend/migrations/NNNN_description.sql`. |
| 3 | Implement behind feature flag (e.g., `NETO_ENABLE_ZEEK=true`). |
| 4 | Unit tests (Rust/Go) + integration test in `tests/forensics_flow.rs`. |
| 5 | Update relevant docs (ARCHITECTURE, API, DETECTION, SECURITY, WORKER). |
| 6 | `make check` passes (fmt, lint, build, test, sqlx-check). |
| 7 | PR with screenshots/demo video for UI changes. |

---

## 10. Versioning & Release Cadence

| Version | Target Date | Focus |
|---------|-------------|-------|
| **v0.2.0** | Q3 2025 | Quick wins (D-01, D-02, D-05, U-01, U-05, R-01, R-02, P-02, C-01) |
| **v0.3.0** | Q4 2025 | Zeek + File Extraction + Sensor Fleet |
| **v0.4.0** | Q1 2026 | Session Graph + Correlation + Case Workspace |
| **v1.0.0** | Q2 2026 | Sigma/Suricata + Object Storage + FIPS + Hardening + Audit |

> **SemVer**: Minor = new features, Patch = fixes, Major = breaking API/DB changes (avoid until 1.0).

---

## 11. Appendix: Related Files to Touch

| Feature Area | Files Likely Modified |
|--------------|----------------------|
| Zeek Integration | `backend/src/analysis/pipeline.rs`, `backend/src/analysis/zeek/`, `backend/migrations/`, `frontend/src/components/ZeekTab.jsx` |
| File Extraction | `backend/src/analysis/extract/`, `backend/src/evidence.rs`, `backend/src/routes/forensics.rs` |
| Session Graph | `backend/src/analysis/session.rs`, `backend/migrations/`, `frontend/src/components/SessionGraph.jsx` |
| Sensor Image | `docker/Dockerfile.sensor`, `scripts/enroll_sensor.sh`, `docs/SENSOR_DEPLOYMENT.md` |
| MITRE/GeoIP | `backend/src/analysis/detect/mod.rs`, `backend/migrations/`, `frontend/src/components/MitreBadge.jsx` |
| Object Storage | `backend/src/evidence.rs` (trait), `backend/src/config.rs`, `docker-compose.yml` (MinIO) |

---

*Last updated: 2025-01-XX*  
*Maintainer: @core-team*