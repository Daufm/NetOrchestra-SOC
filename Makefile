# Rust >= 1.85 is required (current crates use edition 2024). If your default
# cargo is older, put a newer toolchain first on PATH, e.g.
#   export PATH=/usr/lib/rust-1.91/bin:$$PATH
.PHONY: check backend-check worker-check worker-build frontend-check docker-up docker-down fmt test-db sqlx-prepare sqlx-check db-backup

check: backend-check worker-check frontend-check

backend-check:
	cd backend && cargo fmt --check && cargo check && cargo test

worker-check:
	# In networks without proxy.golang.org: export GOPROXY=direct GOSUMDB=off (see docs/WORKER.md)
	cd worker && test -z "$$(gofmt -l .)" && go vet ./... && go test ./...

worker-build:
	cd worker && mkdir -p bin && go build -o bin/netorchestra-worker ./cmd/worker

frontend-check:
	cd frontend && npm run lint && npm test && npm run build

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

fmt:
	cd backend && cargo fmt
	cd worker && gofmt -w .

# Needs DATABASE_URL pointing at a PostgreSQL whose role has CREATEDB.
test-db:
	cd backend && cargo test --test db_schema --test auth_flow --test forensics_flow -- --ignored

# Regenerate committed SQLx offline metadata (needs sqlx-cli and a migrated DATABASE_URL).
# Only produces files once code uses sqlx::query!/query_as! macros.
sqlx-prepare:
	cd backend && cargo sqlx prepare -- --all-targets

# CI gate: fails if committed metadata is stale. Run with SQLX_OFFLINE unset and a live DB.
sqlx-check:
	cd backend && cargo sqlx prepare --check -- --all-targets

db-backup:
	scripts/db-backup.sh
