# Go worker

Status: spec validation, SSH client, capture logic and executable worker lifecycle are implemented and tested.

## Process protocol (backend <-> worker)
* **stdin, line 1:** JSON spec `{job_id, host, port, username, credential_ref, interface, duration_secs, filter, max_bytes}`.
  The spec can use either a key reference (`credential_ref`) or an in-memory SSH password.
  Passwords are never stored in the database, logs, events, or audit details.
* **stdin, later lines:** `{"cmd":"stop"}` = finish gracefully. stdin EOF = also stop (parent died).
* **stdout:** raw PCAP stream **only**.
* **stderr:** JSON lines `{"event": ..., "ts": ...}`: `started{host_key}`, `progress{bytes}`, `error{message}`, `stopped{reason,bytes}`,
  `cleanup`. The backend consumes `started`, `progress`, `error`, `cleanup`; non-JSON stderr is treated as diagnostics.
* **exit:** 0 ok, 1 runtime error, 2 invalid spec.
* Environment passed through by the backend: `PATH`, `NETO_WORKER_KEYS_DIR`, `NETO_WORKER_KNOWN_HOSTS` (everything else is cleared).

## Safety properties
Strict host keys (`known_hosts` mandatory; unknown or changed key = refuse; hashed entries supported), key-file checks (regular file, no
symlink, mode 0600, not encrypted, no path traversal), allow-list validation then single-quoting of every remote argument,
preflight (interface exists, tcpdump present, root or `cap_net_raw`), no sudo, no remote changes, bounded copy loop with backpressure.

## Remote host setup (per capture host)
1. Dedicated user, e.g. `neto-capture`, no shell privileges beyond what packet capture needs.
2. Primary capture engine (`tcpdump`):
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip $(command -v tcpdump)
   ```
3. Secondary fallback capture engine (`netou`):
   When `tcpdump` is not installed or lacks capture capabilities, the worker automatically checks for `netou`:
   ```bash
   sudo install -o root -g root -m 0755 netou /usr/local/bin/netou
   sudo setcap cap_net_raw+ep /usr/local/bin/netou
   ```
4. `authorized_keys`: the worker's public key with `restrict,from="<backend-ip>"`.
5. On the SOC server: `ssh-keygen -t ed25519 -f keys/soc-key -N ''` (mode 0600; the credential_ref is `soc-key`);
   `ssh-keyscan -p 22 <host> >> known_hosts` and **verify the fingerprint through another channel**.
6. Backend env: `NETO_WORKER_BIN`, `NETO_ALLOWED_TARGETS`, `NETO_WORKER_KEYS_DIR`, `NETO_WORKER_KNOWN_HOSTS`.

## Go dependencies note
The module requires `golang.org/x/crypto` and `golang.org/x/sys`, pinned to v0.31.0 with `replace` lines to
`github.com/golang/*` because `golang.org` was unreachable where this was built. If your network allows
`proxy.golang.org`: remove the two `replace` lines and run `go mod tidy`. Otherwise build with
`GOPROXY=direct GOSUMDB=off`. `knownhosts.NewDB` is not available in this version, so `sshclient/hostkeys.go`
selects host-key algorithms from `known_hosts` itself.

## Build and test
`make worker-build` builds `worker/bin/netorchestra-worker`.
`cd worker && go vet ./... && go test -race ./...`
