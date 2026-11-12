# Authentication and RBAC (Phase 3)

First-party only: no OAuth, OIDC, SAML or external identity provider.

## Token model
| Token | Form | Lifetime | Where it lives |
|---|---|---|---|
| Access | JWT (HS256) | 15 min (`NETO_ACCESS_TTL_SECS`) | Response body; keep **in frontend memory only** |
| Refresh | 256-bit random opaque string | 7 days (`NETO_REFRESH_TTL_SECS`) | `neto_refresh` cookie: `HttpOnly; SameSite=Strict; Path=/api/auth`, `Secure` unless `NETO_COOKIE_SECURE=false` |

- **JWT validation** requires `exp`, `iss`, `aud`, `sub` with zero leeway. The accepted algorithm is
  fixed server-side to HS256; the token header's `alg` never selects the algorithm (`none` and other
  HMAC variants are rejected, covered by unit tests).
- **Refresh tokens are stored only as SHA-256 digests** (`refresh_sessions.token_hash`, 32 bytes).
- **Rotation + reuse detection:** every `/refresh` revokes the presented token (`rotated`) and issues a
  new one in the same *family*. Presenting an already-rotated token revokes the entire family
  (`reuse_detected`) and writes an audit record. Consequence: two tabs refreshing with the same token
  at the same instant look like reuse; the frontend must serialise refreshes (one in-flight request).
- **Immediate revocation:** each authenticated request re-reads the user, role, permissions and
  checks that the token's session family is still live, so logout, password change, deactivation and
  role changes take effect at once rather than after the 15-minute token expiry.
- **Passwords:** Argon2id (m=19456 KiB, t=2, p=1, the OWASP minimum), 12-128 characters, must not contain
  the username, small common-password denylist. Hashing runs on the blocking pool.
- **Login hardening:** identical `401 invalid credentials` for unknown user / wrong password / disabled
  account, equalised timing via a dummy hash, per-account lockout (5 failures -> 15 min, HTTP 429 with
  `Retry-After`), per-IP sliding-window limit (30/min), refresh and change-password throttles.

## CSRF and CORS
- CORS allow-list from `NETO_CORS_ORIGINS` (explicit origins, wildcards rejected at startup, credentials on).
- Cookie-authenticated endpoints (`/refresh`, `/logout`) require: `Origin` (if sent) in the allow-list,
  **and** double-submit token: `neto_csrf` cookie equals the `X-CSRF-Token` header (constant-time compare).
  `login` and `refresh` return the same value as `csrf_token` in the JSON body for cross-origin SPAs.
- Bearer-authenticated endpoints are not exposed to CSRF because the token is never a cookie.

## First-admin bootstrap and registration
1. Set `NETO_BOOTSTRAP_TOKEN` (>= 24 chars) in the environment.
2. With an empty `users` table: `POST /api/auth/register` with header `X-Bootstrap-Token: <token>` creates the
   **ADMIN**. Creation is serialised with a PostgreSQL advisory lock so concurrent requests cannot both win.
3. Once any user exists the bootstrap path is closed. Remove the token from the environment.
4. `NETO_ALLOW_REGISTRATION=false` (default) blocks all further public registration. If enabled, it can only
   create `VIEWER`. Elevated roles are never assignable through public registration.

```
curl -X POST http://localhost:8080/api/auth/register \
  -H 'Content-Type: application/json' -H "X-Bootstrap-Token: $NETO_BOOTSTRAP_TOKEN" \
  -d '{"username":"admin","password":"<12+ chars>"}'
```
Local plain-http development needs `NETO_COOKIE_SECURE=false`; the backend logs a warning when it is off.

## Endpoints
| Method / path | Auth | Notes |
|---|---|---|
| `POST /api/auth/register` | none | Bootstrap or (if enabled) VIEWER self-registration; 10/h per IP |
| `POST /api/auth/login` | none | Returns access token, sets refresh + CSRF cookies |
| `POST /api/auth/refresh` | refresh cookie + CSRF | Rotates; failure clears cookies |
| `POST /api/auth/logout` | refresh cookie + CSRF | Revokes this session family; 204 even with no cookie |
| `POST /api/auth/logout-all` | Bearer | Revokes all of the caller's sessions |
| `GET /api/auth/me` | Bearer | User, role, permission list, current `session_id` |
| `POST /api/auth/change-password` | Bearer | Verifies current password; revokes **all** sessions; client must log in again |
| `POST /api/auth/admin/reset-password` | Bearer + `users:manage` | Sets `must_change_password`, revokes the target's sessions |
| `GET /api/auth/sessions` | Bearer | Caller's active sessions; `session_id` is the stable family id |
| `DELETE /api/auth/sessions/:session_id` | Bearer | Own sessions; any user's with `sessions:manage_all` (ADMIN). Others get 404 |

`must_change_password`: after an admin reset, the user can only call `/api/auth/*` (others return 403
`password_change_required`) until they change their password.

## RBAC
Permissions live in `permissions` / `role_permissions` (seeded in migration 0006) and are loaded from the
database on every request. Handlers enforce with `AuthUser::require("<permission>")`, e.g.
`auth.require("jobs:create")?` in Phase 4. Role summary: ADMIN everything; ANALYST investigations, jobs,
findings triage, evidence read/export; VIEWER read-only investigations/jobs/findings.

## Operational notes
- Error envelope: `{"error":{"code","message"}}`; internal errors are logged, never returned.
- Every request gets an `x-request-id`; audit records (`audit_logs`) capture login success/failure, lockouts,
  reuse detection, logouts, password changes/resets, session revocations, registration and bootstrap
  attempts, with actor, IP and request id. The table is append-only.
- Security headers on all responses: `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `Cache-Control: no-store`. Auth bodies are limited to 64 KiB.
- Behind a reverse proxy set `NETO_TRUST_PROXY=true` so rate limits and audit use the real client IP.
  The per-IP limiter is in-process; the per-account lockout is in PostgreSQL and works across replicas.
- Not implemented (future hardening): JWT secret rotation / `kid`, expired-session purge job, MFA.
  Expired `refresh_sessions` rows are inert but not yet deleted.
