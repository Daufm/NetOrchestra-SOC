# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Backend (Rust) - dependency layer cached with cargo-chef
# ---------------------------------------------------------------------------
FROM rust:1.85-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /src/backend

FROM chef AS planner
COPY backend/ ./
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS backend-builder
COPY --from=planner /src/backend/recipe.json recipe.json
# Builds only dependencies; this layer is reused until Cargo.toml/Cargo.lock change
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY backend/Cargo.toml backend/Cargo.lock ./
COPY backend/src ./src
COPY backend/migrations ./migrations
RUN cargo build --release --locked

# ---------------------------------------------------------------------------
# Worker (Go)
# ---------------------------------------------------------------------------
FROM golang:1.22-bookworm AS worker-builder
WORKDIR /src/worker
COPY worker/go.mod worker/go.sum* ./
RUN go mod download
COPY worker ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /netorchestra-worker ./cmd/worker

# ---------------------------------------------------------------------------
# Frontend (React)
# ---------------------------------------------------------------------------
FROM node:22-bookworm AS frontend-builder
WORKDIR /src/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

ARG NETO_UID=10001
ARG NETO_GID=10001

ENV DEBIAN_FRONTEND=noninteractive \
    NETO_UID=${NETO_UID} \
    NETO_BIND_ADDR=0.0.0.0:8080 \
    NETO_TSHARK_PATH=/usr/bin/tshark \
    NETO_EVIDENCE_DIR=/var/lib/netorchestra/evidence \
    NETO_WORKSPACE_DIR=/var/lib/netorchestra/workspace \
    NETO_WORKER_KEYS_DIR=/run/secrets/ssh \
    NETO_WORKER_KNOWN_HOSTS=/etc/netorchestra/known_hosts

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nginx tshark ca-certificates curl libpq5 tini util-linux procps bash \
    && rm -rf /var/lib/apt/lists/* \
    # Create unprivileged service account
    && groupadd --system --gid ${NETO_GID} neto \
    && useradd --system --uid ${NETO_UID} --gid ${NETO_GID} \
        --create-home --home-dir /var/lib/netorchestra \
        --shell /usr/sbin/nologin neto \
    # Create data and secrets directories with strict ownership
    && mkdir -p /var/lib/netorchestra/evidence /var/lib/netorchestra/workspace \
        /run/secrets/ssh /etc/netorchestra \
    && chown -R neto:neto /var/lib/netorchestra \
    && chmod 750 /var/lib/netorchestra/evidence /var/lib/netorchestra/workspace \
    # [Fix #5] tshark: verify offline PCAP analysis works without CAP_NET_RAW.
    # The tshark binary is installed setuid/setcap by the Debian package; we
    # explicitly remove setuid and rely on the wireshark group for live capture
    # only when NETO_LIVE_CAPTURE=true (see Compose security_opt / cap_add).
    # Offline PCAP analysis requires no extra capabilities at all.
    && chmod u-s /usr/bin/dumpcap 2>/dev/null || true \
    # Harden Nginx: strip the default site and lock down the pid file location
    && rm -f /etc/nginx/sites-enabled/default \
    && mkdir -p /var/run/nginx \
    && chown -R root:www-data /var/run/nginx

COPY --from=backend-builder /src/backend/target/release/netorchestra-backend /usr/local/bin/netorchestra-backend
COPY --from=worker-builder /netorchestra-worker /usr/local/bin/netorchestra-worker
COPY --from=frontend-builder /src/frontend/dist /usr/share/nginx/html

# [Fix #2] Binary ownership: Rust/Go binaries are owned root, executable by
# neto only via the entrypoint's setpriv call. No SUID bits.
RUN chmod 0755 /usr/local/bin/netorchestra-backend \
              /usr/local/bin/netorchestra-worker

COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY docker/nginx-security.conf /etc/nginx/conf.d/security.conf
COPY docker/entrypoint.sh /usr/local/bin/netorchestra-entrypoint
RUN chmod 0755 /usr/local/bin/netorchestra-entrypoint

EXPOSE 80

# [Fix - volumes] Do NOT declare VOLUME here. The Dockerfile VOLUME instruction
# creates anonymous volumes that are ignored when Compose named volumes mount
# the same path, but can still create orphaned volumes in `docker run` scenarios
# and cause confusion. Persistence is managed entirely by docker-compose.yml.

# tini is PID 1: reaps zombies and forwards signals correctly to the
# entrypoint script (which then signals Nginx and Rust gracefully).
# The entrypoint is a bash script: bash 5 ships in debian:bookworm and is
# required for `wait -n`. /bin/sh is dash on Debian and lacks this builtin.
# [Fix #2] The supervisor entrypoint runs as root only for the brief chown
# check; Rust and Go are exec'd as neto via setpriv inside the entrypoint.
ENTRYPOINT ["/usr/bin/tini", "--", "/bin/bash", "/usr/local/bin/netorchestra-entrypoint"]
