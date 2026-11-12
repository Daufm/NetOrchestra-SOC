#!/bin/bash
# NetOrchestra container entrypoint.
# bash is required for `wait -n` (POSIX sh / dash does not support it).
# Runs as root (PID 2 under tini). Drops to neto for Rust/Go processes.
set -euo pipefail

NETO_UID="${NETO_UID:-10001}"
STARTUP_TIMEOUT="${NETO_STARTUP_TIMEOUT:-90}"

# ---------------------------------------------------------------------------
# 1. Dependency sanity check
# ---------------------------------------------------------------------------
required() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FATAL: required dependency missing from image: $1" >&2
    exit 1
  }
}

required /usr/local/bin/netorchestra-backend
required /usr/local/bin/netorchestra-worker
required nginx
required tshark
required curl
required setpriv

# ---------------------------------------------------------------------------
# 2. Mandatory env-var guard & user help
# ---------------------------------------------------------------------------
print_setup_help() {
  cat <<'EOF' >&2
================================================================================
                    NetOrchestra-SOC Setup Required
================================================================================
Mandatory environment variables or configuration are missing!

Quick Setup Steps:
  1. Prepare your .env file:
     POSTGRES_PASSWORD=$(openssl rand -hex 24)
     NETO_JWT_SECRET=$(openssl rand -base64 48)

  2. Ensure your docker-compose.yml or docker run specifies:
     - DATABASE_URL or POSTGRES_PASSWORD
     - NETO_JWT_SECRET (>= 32 bytes random string)

  3. Start with Docker Compose:
     docker compose up -d

Refer to README.md or .env.example for full details.
================================================================================
EOF
}

if [ -z "${DATABASE_URL:-}" ] || [ -z "${NETO_JWT_SECRET:-}" ]; then
  print_setup_help
  echo "FATAL: DATABASE_URL and NETO_JWT_SECRET must both be provided." >&2
  exit 1
fi

# [Fix #4] Reject well-known placeholder passwords at startup.
for _var in DATABASE_URL POSTGRES_PASSWORD; do
  _val="${!_var:-}"
  case "$_val" in
    *change-this-local-password*|*CHANGE_ME*)
      print_setup_help
      echo "FATAL: $_var contains a default/placeholder value. Configure a strong password." >&2
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# 3. Privilege-drop helper
# ---------------------------------------------------------------------------
# as_neto: run a command with the neto UID/GID so readability tests reflect
# the same permissions the backend will see at runtime.
as_neto() {
  setpriv --reuid=neto --regid=neto --init-groups "$@"
}

# ---------------------------------------------------------------------------
# 4. SSH credential validation — hard-fail on any unreadable key  [Fix #3]
#
# Only validate private keys when NETO_WORKER_BIN is set, because that is
# the flag that enables remote capture. If it is unset, the SSH directory
# is irrelevant and we must not fail on its contents (or emptiness).
# ---------------------------------------------------------------------------
if [ -n "${NETO_WORKER_BIN:-}" ]; then
  if [ ! -x "$NETO_WORKER_BIN" ]; then
    echo "FATAL: NETO_WORKER_BIN is not executable: $NETO_WORKER_BIN" >&2
    exit 1
  fi

  if [ -n "${NETO_WORKER_KNOWN_HOSTS:-}" ]; then
    if ! as_neto test -r "$NETO_WORKER_KNOWN_HOSTS"; then
      echo "FATAL: NETO_WORKER_KNOWN_HOSTS is not readable by user neto (uid $NETO_UID): $NETO_WORKER_KNOWN_HOSTS" >&2
      echo "  fix on host: sudo chown $NETO_UID:$NETO_UID secrets/known_hosts && chmod 644 secrets/known_hosts" >&2
      exit 1
    fi
  fi

  if [ -n "${NETO_WORKER_KEYS_DIR:-}" ]; then
    if [ ! -d "$NETO_WORKER_KEYS_DIR" ]; then
      echo "FATAL: NETO_WORKER_KEYS_DIR is not a directory: $NETO_WORKER_KEYS_DIR" >&2
      exit 1
    fi

    # Count and validate private key files. We skip:
    #   - .pub files  (public keys — not secret, not required to be 600)
    #   - dotfiles    (e.g. .gitkeep)
    #   - directories
    # This avoids false failures on repos with README or .gitkeep files.
    key_count=0
    while IFS= read -r -d '' key; do
      filename="$(basename "$key")"
      # Skip public keys and dot-files
      case "$filename" in
        *.pub|.*)  continue ;;
      esac
      [ -f "$key" ] || continue

      key_count=$((key_count + 1))

      if ! as_neto test -r "$key"; then
        echo "FATAL: SSH private key not readable by neto (uid $NETO_UID): $key" >&2
        echo "  fix: sudo chown $NETO_UID:$NETO_UID secrets/ssh/* && chmod 600 secrets/ssh/*" >&2
        exit 1
      fi

      perm="$(stat -c '%a' "$key")"
      case "$perm" in
        600|400) ;;  # acceptable for private keys
        *)
          echo "FATAL: SSH private key has insecure permissions ($perm): $key" >&2
          echo "  fix: chmod 600 secrets/ssh/$filename" >&2
          exit 1
          ;;
      esac
    done < <(find "$NETO_WORKER_KEYS_DIR" -maxdepth 1 -print0)

    if [ "$key_count" -eq 0 ]; then
      echo "FATAL: NETO_WORKER_BIN is set but no private key files found in NETO_WORKER_KEYS_DIR: $NETO_WORKER_KEYS_DIR" >&2
      echo "  Add at least one key (chmod 600) or unset NETO_WORKER_BIN to disable remote capture." >&2
      exit 1
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 5. Volume ownership — only chown the top-level dir when ownership is wrong,
#    keeping large-volume restarts fast.  [Fix #6]
# ---------------------------------------------------------------------------
mkdir -p "$NETO_EVIDENCE_DIR" "$NETO_WORKSPACE_DIR"
for d in "$NETO_EVIDENCE_DIR" "$NETO_WORKSPACE_DIR"; do
  owner="$(stat -c '%u' "$d")"
  if [ "$owner" != "$NETO_UID" ]; then
    echo "Volume $d owned by uid $owner; chowning to neto ($NETO_UID)..." >&2
    chown -R "neto:neto" "$d"
  fi
done

# ---------------------------------------------------------------------------
# 6. Process supervision  [Fix #1]
#    Uses bash's `wait -n` to block until any child exits, then identifies
#    the culprit with ps(1). `wait -n` is bash 4.3+ (bash 5 ships in
#    debian:bookworm). Zombie-safe: tini (PID 1) reaps all orphans, and
#    `wait <pid>` returns the child's real exit status.
# ---------------------------------------------------------------------------
export HOME=/var/lib/netorchestra

backend_pid=""
nginx_pid=""

stop_all() {
  trap - INT TERM EXIT
  [ -n "$nginx_pid" ]   && kill -QUIT "$nginx_pid"    2>/dev/null || true
  [ -n "$backend_pid" ] && kill -TERM "$backend_pid"  2>/dev/null || true
  wait 2>/dev/null || true
}

trap 'stop_all; exit 143' INT TERM
trap 'stop_all' EXIT

# Start Rust backend as neto
as_neto /usr/local/bin/netorchestra-backend &
backend_pid=$!

# Wait for backend health (bounded, zombie-safe via ps)
elapsed=0
until curl --fail --silent http://127.0.0.1:8080/api/health >/dev/null 2>&1; do
  if ! ps -p "$backend_pid" >/dev/null 2>&1; then
    wait "$backend_pid" 2>/dev/null; rc=$?
    echo "FATAL: backend exited during startup (status $rc)" >&2
    exit 1
  fi
  if [ "$elapsed" -ge "$STARTUP_TIMEOUT" ]; then
    echo "FATAL: backend did not become healthy within ${STARTUP_TIMEOUT}s" >&2
    exit 1
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done

# Start Nginx (nginx drops worker processes to www-data internally)
nginx -g 'daemon off;' &
nginx_pid=$!

# Block until one of our two children exits; `wait -n` returns that child's exit code.
wait -n "$backend_pid" "$nginx_pid" 2>/dev/null || true

# Identify which process exited and log its final status.
if ! ps -p "$backend_pid" >/dev/null 2>&1; then
  wait "$backend_pid" 2>/dev/null; rc=$? || true
  echo "FATAL: backend exited unexpectedly (status $rc)" >&2
else
  wait "$nginx_pid" 2>/dev/null; rc=$? || true
  echo "FATAL: nginx exited unexpectedly (status $rc)" >&2
fi
exit 1
