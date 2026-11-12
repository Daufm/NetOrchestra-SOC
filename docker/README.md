# Docker deployment

The Compose deployment bundles PostgreSQL, the Rust API, the Go worker, React
static assets, Nginx, and TShark. No Rust, Go, Node.js, PostgreSQL, or TShark
installation is required on the host; Docker is the only host dependency.

## First run

From the repository root:

```sh
cp .env.example .env
mkdir -p secrets/ssh
touch secrets/known_hosts
```

Edit `.env`:

- Set a unique `POSTGRES_PASSWORD` (alphanumeric is safest, since it is embedded in `DATABASE_URL`).
- Set `NETO_JWT_SECRET` (`openssl rand -hex 32`). The container refuses to start without it.
- Replace any development/bootstrap secrets before exposing the service outside localhost.

The Compose defaults are intended only to make a local first run possible.

Build and start:

```sh
docker compose up --build -d
docker compose logs -f netorchestra
```

Open `http://localhost:8080`. Database migrations run automatically.

By default the port is bound to `127.0.0.1` only. To expose it on the network,
set `NETO_HTTP_HOST=0.0.0.0` in `.env`, put TLS in front, and set
`NETO_COOKIE_SECURE=true`.

## SSH keys

The application runs as an unprivileged user `neto` with the fixed UID/GID
`10001`. Because `secrets/ssh` is mounted read-only, the files must be readable
by that UID **on the host**:

```sh
sudo chown -R 10001:10001 secrets/ssh secrets/known_hosts
chmod 700 secrets/ssh
chmod 600 secrets/ssh/*
chmod 644 secrets/known_hosts
```

The dashboard lists the filenames in `secrets/ssh/` in the credential selector.
Add the target servers' host keys to `secrets/known_hosts`; host-key
verification remains mandatory.

If a key is unreadable, the entrypoint prints a warning with the exact fix
(`docker compose logs netorchestra`).

Password authentication is also available for live SSH capture, but passwords
are transient and are not stored.

## Stop and data

```sh
docker compose down
docker compose down -v   # permanently removes database/evidence volumes
```

PostgreSQL, evidence, and workspace data use named Docker volumes. Back them
up before deleting volumes.

`docker compose stop` gives the backend up to 30 seconds to shut down
gracefully (configurable via `stop_grace_period`).

## Dependency checks

The application entrypoint verifies that the bundled backend, worker, Nginx,
TShark, curl, and setpriv are present before startup. It also checks the
configured database/JWT settings and mounted SSH paths. Dependencies are
installed at image build time, not dynamically into a running production
container.

If the backend or Nginx exits, the container stops so Docker's restart policy
can recover it. Startup fails if the backend is not healthy within
`NETO_STARTUP_TIMEOUT` seconds (default 90).

## Notes

- `.dockerignore` keeps `.env` and `secrets/` out of the build context.
- Rust dependencies are cached with `cargo-chef`, so source-only changes no
  longer rebuild every crate.
- Live capture from local network interfaces (as opposed to remote SSH
  streams) additionally needs `cap_add: [NET_RAW, NET_ADMIN]` and capabilities
  on `dumpcap` for the `neto` user.