# Database (Phase 2)

Authoritative store: PostgreSQL 17+ (target). The schema uses nothing newer than PostgreSQL 13
(`gen_random_uuid()` is built in), and was tested on **PostgreSQL 16** during development.

## Tables (15)
| Group | Tables |
|---|---|
| Identity / RBAC | `users`, `roles`, `permissions`, `role_permissions`, `refresh_sessions` |
| Investigation | `investigations`, `capture_jobs`, `worker_sessions`, `detection_profiles` |
| Analysis | `packets`, `threat_findings` |
| Evidence / audit | `evidence_artifacts`, `evidence_hashes`, `chain_of_custody`, `audit_logs` |

Conventions: UUID primary keys for user-facing entities, `TIMESTAMPTZ` (UTC), `JSONB` for variable
protocol data and thresholds, `INET` for addresses, `BIGINT` identity keys for high-volume append tables.

## Integrity rules enforced by the database
- `users.password_hash` must be an Argon2id PHC string. Usernames/emails are unique case-insensitively.
- `refresh_sessions.token_hash` is a 32-byte SHA-256 digest, never the token. `family_id` groups a
  rotation chain so reuse of a revoked token can revoke the whole family (logic lands in Phase 3).
- Stream jobs must carry target/interface/duration; `remote_interface` is restricted to
  `[A-Za-z0-9_.:-]{1,32}` as defence in depth against command injection. Only a `credential_ref`
  is stored, never a key or password.
- `threat_findings` must reference at least one packet frame, with `confidence` in [0, 1].
  Redact credentials **before** inserting `supporting_evidence`.
- `evidence_artifacts` rows are immutable (UPDATE/DELETE rejected). `evidence_hashes`,
  `chain_of_custody` and `audit_logs` are append-only. A job that has evidence cannot be deleted.
- Original PCAP bytes live on the evidence volume; the DB keeps path, size and SHA-256 only.

Retention pruning of `audit_logs` needs a deliberate privileged procedure that disables the
`audit_logs_append_only` trigger; it is intentionally not automatic.

## Migrations
Files in `backend/migrations/` are embedded in the binary with `sqlx::migrate!` and applied at startup
when `NETO_RUN_MIGRATIONS=true` (default). Never edit an applied migration; add a new numbered file.
In multi-replica deployments run migrations from one place and set `NETO_RUN_MIGRATIONS=false` elsewhere.

## SQLx offline compilation
- Phase 2 uses the runtime `sqlx::query(...)` API and `sqlx::migrate!`, which need **no database at
  compile time**. Docker/CI builds therefore already compile without PostgreSQL, and `.sqlx/` is
  currently empty (nothing to prepare yet).
- Once code adopts compile-time-checked `sqlx::query!` / `query_as!` macros, commit metadata:
  ```
  cargo install sqlx-cli --no-default-features --features rustls,postgres
  export DATABASE_URL=postgres://...      # a migrated database
  make sqlx-prepare                       # writes backend/.sqlx/*.json; commit them
  ```
  Build with `SQLX_OFFLINE=true`. Re-run `make sqlx-prepare` after any query or migration change, and
  gate CI with `make sqlx-check`. Keep the `sqlx-cli` version in step with the `sqlx` crate (0.8.x).

## Tests
`make test-db` runs `backend/tests/db_schema.rs` (11 tests). `#[sqlx::test]` creates a throwaway
database per test, so the role in `DATABASE_URL` needs `CREATEDB`.

## Backup and restore
```
DATABASE_URL=postgres://user@host/netorchestra scripts/db-backup.sh            # dump + .sha256
INCLUDE_EVIDENCE=1 EVIDENCE_DIR=/var/lib/netorchestra/evidence scripts/db-backup.sh
TARGET_DATABASE_URL=postgres://user@host/restore_db scripts/db-restore.sh --yes backups/<file>.dump
```
Restore verifies the checksum, refuses without `--yes`, and reads `TARGET_DATABASE_URL` (not
`DATABASE_URL`) so it cannot hit the live database by accident. Back up the evidence directory together
with the database: the DB holds hashes, the files hold the evidence. Prefer `PGPASSFILE`/`PGPASSWORD`
over a password inside the URL so it stays out of the process list.
