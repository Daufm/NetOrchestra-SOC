# System Architecture & Technical Design

NetOrchestra-SOC is a high-performance network forensics, threat detection, and remote packet acquisition platform. It couples a low-latency Rust/Axum API engine with asynchronous TShark packet dissection, an unprivileged Go remote capture worker featuring automatic AF_PACKET fallback (NETOU), PostgreSQL persistence with immutable chains of custody, and a real-time reactive React dashboard.

---

## 1. High-Level Architectural Diagram

```
                                      ANALYST BROWSER
                         ┌─────────────────────────────────────────┐
                         │  React 18 + Vite + Tailwind Dashboard  │
                         │  - Live Threat Grid & Metrics Ribbon    │
                         │  - Multi-Filter Packet Inspector        │
                         │  - In-Browser System Documentation      │
                         └────────────────────┬────────────────────┘
                                              │ HTTPS / WebSocket (/api/ws)
                                              ▼
                                   CONTAINER EDGE (NGINX)
                         ┌─────────────────────────────────────────┐
                         │  Nginx Reverse Proxy & Static Host      │
                         │  - client_max_body_size: 2M (API)       │
                         │  - /api/upload: 512M streaming          │
                         │  - CSP, HSTS, frame-ancestors: 'none'   │
                         └────────────────────┬────────────────────┘
                                              │ http://127.0.0.1:8080
                                              ▼
                                   CORE BACKEND (RUST / AXUM)
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                                 │
│  [API Routing & Auth]              [Job & Concurrency Manager]         [Real-Time Event Bus]    │
│  - Argon2id & HS256 JWT            - Bounded Task Slots (Semaphore)    - Tokio Broadcast Channel│
│  - Rotating Refresh Cookies        - Graceful Cancellation Tokens      - WebSocket Session Lag  │
│  - SSRF-Guarded Target Validation  - Orphan Recovery on Startup          Protection             │
│                                                                                                 │
│  [Evidence Ingestion Engine]       [Analysis Pipeline]                 [Dissection Engine]      │
│  - Multi-part Stream / Disk Write  - Bounded In-Memory Channel (32)    - TShark Child Process   │
│  - On-the-fly SHA-256 Hashing      - Batched UNNEST Inserts (1000)     - '-T fields' Streaming  │
│  - Immediate File Sealing (0400)   - Stateful Threat Detectors         - '-T json' On-Demand    │
│                                                                                                 │
└──────────────┬──────────────────────────────────┬───────────────────────────────┬───────────────┘
               │                                  │                               │
               ▼                                  ▼                               ▼
       POSTGRESQL 16+                     LOCAL EVIDENCE DISK               ISOLATED GO WORKER
┌──────────────────────────────┐   ┌──────────────────────────────┐   ┌───────────────────────────┐
│ - Users, Roles, Sessions     │   │ - Directory: /var/lib/...    │   │ - Subprocess per capture  │
│ - Capture Jobs & Sessions    │   │ - Sealed files: mode 0400    │   │ - Stdin/Stdout/Stderr     │
│ - Packets (Metadata & Proto) │   │ - Hash verified on load      │   │   JSON IPC Protocol       │
│ - Threat Findings & Triage   │   │ - Never stored in DB blobs   │   │ - Strict SSH Key &        │
│ - Append-only Custody Logs   │   │ - Retained across containers │   │   known_hosts checks      │
│ - Append-only Audit Trail    │   │   via named Docker volumes   │   └─────────────┬─────────────┘
└──────────────────────────────┘   └──────────────────────────────┘                 │
                                                                                    │ SSH (Encrypted)
                                                                                    ▼
                                                                        REMOTE MONITORED LINUX HOST
                                                                      ┌───────────────────────────┐
                                                                      │ neto-capture user (No root│
                                                                      │                           │
                                                                      │ Primary:                  │
                                                                      │  tcpdump (cap_net_raw)    │
                                                                      │            OR             │
                                                                      │ Secondary Fallback:       │
                                                                      │  NETOU AF_PACKET helper   │
                                                                      └───────────────────────────┘
```

---

## 2. Core System Components

### 2.1 Backend Engine (`backend/`)
Built with **Rust 1.85+**, **Axum**, and **Tokio**. Designed for zero-panic stability, strict memory safety, and high-throughput I/O.
* **`routes/`**: Modular REST endpoints partitioned into:
  * `auth`: Argon2id password hashing, rotating refresh tokens, session lifecycle, admin resets.
  * `forensics`: File uploads, remote streaming commands, packet search, export, triage.
  * `health`: `/api/health` (liveness) and `/api/ready` (database connectivity).
  * `ws`: WebSocket connection upgrade with token authentication within 5 seconds.
  * `docs`: In-browser technical documentation catalog and compiled markdown delivery.
* **`runner.rs`**: Orchestrates capture execution:
  * Enforces job concurrency limits via an internal semaphore.
  * Manages streaming pipelines with backpressure.
  * Automatically recovers or marks failed orphan jobs on startup.
* **`analysis/`**:
  * `pipeline.rs`: Consumes stdout from TShark, parses tab-separated fields into structured `PacketRecord` structs, feeds detectors, and writes to PostgreSQL in 1,000-packet batches using PostgreSQL `UNNEST` arrays.
  * `detect/`: Pluggable threat detection rules (`dns_tunnel`, `cleartext_http`, `remote_access`) that evaluate packet streams in single-pass memory windows.
* **`evidence.rs`**:
  * Enforces evidence integrity: magic number verification (PCAP/PCAPNG), streaming SHA-256 calculation, read-only file sealing (`chmod 0400`), and append-only chain of custody records.

### 2.2 Remote Capture Subsystem (`worker/`)
An isolated **Go (1.22+)** binary (`netorchestra-worker`) executed as an unprivileged child process by the Rust backend for remote acquisitions.
* **Privilege Separation:** The worker runs isolated from the web server. Remote SSH credentials never leave the worker process memory.
* **JSON IPC Protocol:**
  * `stdin`: Receives job specification JSON (`host`, `port`, `username`, `credential_ref`, `interface`, `duration_secs`, `filter`, `max_bytes`). Later lines accept `{"cmd":"stop"}` for graceful termination.
  * `stdout`: Dedicated exclusively to the binary raw PCAP stream. No log lines or text output ever enter stdout.
  * `stderr`: Emits structured JSON events (`started`, `progress`, `error`, `stopped`, `cleanup`) consumed by the backend event bus.
* **Dual Capture Engines & Automatic Preflight Fallback:**
  * **Primary (tcpdump):** Executes `exec tcpdump -n -U -s 0 -i <iface> -w -`. Requires `CAP_NET_RAW` or root on the target.
  * **Secondary Fallback (NETOU):** If `tcpdump` is absent or lacks capabilities, the worker automatically checks for `netou`. If verified operational via `netou -check`, it executes `exec netou -i <iface>`.
  * **Zero Remote Mutation:** Neither engine modifies remote interfaces, creates virtual taps, or writes remote files. Terminating the SSH connection causes the Linux kernel to immediately reclaim socket resources.

### 2.3 NETOU: Lightweight Linux AF_PACKET Capture Helper (`worker/cmd/netou`)
A standalone, dependency-free Go binary for target Linux hosts lacking `tcpdump` or `libpcap`:
* Uses native `syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, htons(ETH_P_ALL))`.
* Binds directly to the target network interface using `syscall.SockaddrLinklayer`.
* Attaches socket-level classic BPF filters via `SO_ATTACH_FILTER` when custom BPF is specified.
* Writes valid PCAP 2.4 binary frames directly to `stdout`.
* Requires only `CAP_NET_RAW` (`sudo setcap cap_net_raw+ep netou`), allowing completely unprivileged execution under a standard user account.

### 2.4 Dissection & Deep Inspection Engine (TShark)
* **Bulk Processing (`-T fields`):** During capture or upload ingestion, TShark runs as a stream processor:
  ```bash
  tshark -l -n -q -T fields -E separator=$'\t' -E occurrence=f \
    -e frame.number -e frame.time_epoch -e frame.len \
    -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst \
    -e _ws.col.Protocol -e tcp.srcport -e tcp.dstport \
    -e udp.srcport -e udp.dstport -r -
  ```
  This extracts metadata at tens of thousands of packets per second without memory bloating.
* **On-Demand Frame Dissection (`-T json`):** When an analyst selects a specific frame in the UI, TShark is invoked for only that single frame:
  ```bash
  tshark -r <evidence_pcap> -Y "frame.number == <N>" -T json -x
  ```
  Returns the complete protocol dissection tree and raw packet hex dump directly to the browser.

### 2.5 Database & Storage Architecture (PostgreSQL 16+)
Authoritative store for all structured forensic data. Evidence binary files are **never** stored inside the database.
* **Key Entities:**
  * `capture_jobs`: Tracks ingestion mode (`upload` vs `stream`), status, parameters, progress percentage, and capture backend (`tcpdump` vs `NETOU (AF_PACKET)`).
  * `packets`: Flattened protocol metadata, layer stack, transport ports, and JSONB protocol-specific fields.
  * `threat_findings`: Detections generated by profiles, associated confidence ratings, severity, and packet frame references.
  * `evidence_artifacts`: File metadata, original filename, storage path, byte size, and SHA-256 hash.
  * `evidence_hashes` & `evidence_custody`: Append-only audit trail protected by database triggers that reject `UPDATE` or `DELETE` operations.
* **Write Optimization:** High-throughput batching (`INSERT INTO packets SELECT * FROM UNNEST(...)`) prevents transaction log bottlenecking during live packet streaming.

---

## 3. Data Flow Pipelines

### 3.1 Live Remote Capture Pipeline
```
1. Operator clicks "Start Capture" -> POST /api/stream
2. Axum validates input, verifies target IP matches NETO_ALLOWED_TARGETS CIDR
3. Semaphore allocates a capture slot -> Capture job created in DB ('queued')
4. Backend spawns Go worker subprocess with spec on stdin
5. Worker dials SSH using keys from /run/secrets/ssh and verifies known_hosts
6. Worker executes Preflight:
   ├── Checks interface in /sys/class/net/
   ├── Tests tcpdump availability and CAP_NET_RAW
   │     └── If OK -> Selected Backend = tcpdump
   └── If tcpdump missing/unprivileged -> Checks netou -check
         └── If OK -> Selected Backend = NETOU (AF_PACKET)
7. Worker emits 'started' JSON event on stderr with host key & selected backend
8. Capture process executes on remote host -> Streams PCAP bytes over SSH stdout
9. Backend Reader Task splits incoming stream:
   ├── Write Branch: Appends bytes directly to /evidence/<job_id>/original.pcap & updates SHA-256
   └── Analysis Branch: Sends chunks through bounded mpsc channel to TShark stdin
10. TShark dissects packets -> Emits tab-separated fields on stdout
11. Pipeline groups records into 1,000-packet batches -> Executes UNNEST batch insert into DB
12. Detectors evaluate traffic in real-time -> Emits threat findings & updates DB
13. Backend publishes WebSocket events (job_progress, threat_detected) to UI clients
14. Capture terminates (timer, byte limit, or user stop):
    ├── Backend sends {"cmd":"stop"} to worker stdin
    ├── Worker sends SIGINT to remote process -> Flushes remaining buffer
    ├── Evidence file is sealed (mode 0400) and SHA-256 hash recorded in DB
    └── CaptureStopped event broadcasted with total bytes and final backend status
```

### 3.2 PCAP Upload Pipeline
```
1. Operator submits PCAP file via multipart form -> POST /api/upload
2. Backend streams file directly to disk (/evidence/<job_id>/original.tmp)
   ├── Enforces NETO_MAX_UPLOAD_BYTES limit on-the-fly
   ├── Computes streaming SHA-256 digest
   └── Verifies PCAP/PCAPNG magic bytes within the first 4 bytes
3. File is renamed to original.pcap and sealed read-only (chmod 0400)
4. Database transaction registers job, artifact, SHA-256 hash, and custody record ('ingested')
5. Asynchronous background analysis worker triggers:
   ├── Verifies file hash matches recorded digest
   ├── Spawns TShark -T fields on sealed file
   ├── Runs detector pipeline and writes packet metadata to PostgreSQL
   └── Updates job status to 'completed' and broadcasts via WebSocket
```

---

## 4. Security & Hardening Architecture

1. **Defense-in-Depth Privilege Model:**
   * Container supervisor starts under `tini` as PID 1 to reap zombie processes.
   * `setpriv` drops Rust backend and Go worker execution to unprivileged user `neto` (UID 10001).
   * Container drops all Linux capabilities (`cap_drop: ALL`) and retains only minimum required capabilities (`NET_BIND_SERVICE`, `CHOWN`, `DAC_OVERRIDE`, `SETUID`, `SETGID`).
   * `no-new-privileges: true` flag prevents privilege escalation.
2. **Strict SSH & Network Isolation:**
   * Private keys mounted read-only (`:ro`) and validated for strict permissions (`0600`/`0400`).
   * Remote capture requires **both** `NETO_WORKER_BIN` and `NETO_ALLOWED_TARGETS` CIDR allow-lists to prevent Server-Side Request Forgery (SSRF).
   * Remote servers run with unprivileged accounts (`neto-capture`) holding file capabilities (`CAP_NET_RAW`), eliminating `sudo` or root requirements.
3. **Forensic Evidence Tamper Resistance:**
   * Evidence captures are written once and sealed `0400`.
   * Database triggers (`forbid_mutation()`) prevent modification or deletion of hash and custody tables.
   * On-demand verification recalculates SHA-256 from disk and compares against immutable DB records.
4. **Credential Redaction Engine:**
   * Plaintext passwords in HTTP Basic Auth, forms, and URIs are stripped or redacted before persistence in database records or log events.
