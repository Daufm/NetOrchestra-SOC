# Security

## Implemented controls
* **AuthN/Z:** Argon2id; HS256 JWT with fixed algorithm and required claims; hashed rotating refresh tokens with reuse detection; CSRF
  double-submit + Origin check; lockout + rate limits; immediate revocation; RBAC enforced server-side from the database.
* **Injection:** parameterized SQL only (`QueryBuilder` binds; sort columns are whitelisted; LIKE wildcards escaped); no shell
  anywhere in the backend; remote command arguments allow-listed then quoted; TShark display filter built only from an integer.
* **SSRF/lateral movement:** remote targets must match `NETO_ALLOWED_TARGETS`; empty = deny all.
* **Evidence integrity:** write-once files, 0400, SHA-256, DB immutability triggers, verification before analysis and export, full custody trail.
* **Secrets:** none hardcoded; startup rejects weak/placeholder secrets; secrets redacted from `Debug`, findings, packets, audit logs; SSH keys by reference only.
* **Resource limits:** upload size, concurrency slots, duration, 512 MiB default cap per live capture, findings/groups caps, bounded channels, request body limits, per-job workspaces removed afterwards.
* **Web:** strict CORS allow-list, `nosniff`, `X-Frame-Options: DENY`, `no-referrer`, `no-store`, WebSocket origin check, token-in-first-message.
* **Audit:** append-only `audit_logs` with actor, IP, request id.

## Hardening checklist (Step 11)
- [ ] Run everything non-root; TShark not as root; drop all Linux capabilities in containers.
- [ ] PostgreSQL not published; TLS between app and DB where it crosses hosts; separate low-privilege app role.
- [ ] TLS terminated in front (HSTS); `NETO_COOKIE_SECURE=true`; CSP on the frontend.
- [ ] `NETO_TRUST_PROXY=true` only behind a proxy you control.
- [ ] Remove `NETO_BOOTSTRAP_TOKEN` after the first admin exists; keep `NETO_ALLOW_REGISTRATION=false`.
- [ ] Purge expired refresh sessions; rotate `NETO_JWT_SECRET` periodically (invalidates access tokens).
- [ ] Dependency audits in CI (`cargo audit`, `npm audit`, `govulncheck`).
- [ ] Backups of DB **and** evidence together; test restores.
- [ ] Review: upload handler, runner, worker command building, any new `format!` into commands.

## Threat notes
Uploaded PCAPs are untrusted input to a large C parser (TShark): keep it patched, unprivileged, resource-limited, and without name
resolution (already `-n`). Remote hosts are semi-trusted: their output is treated as hostile data. Findings can contain attacker-controlled
text (domain names): the frontend must render them as text, never HTML.
