-- Phase 2 / 0005: evidence artifacts, hashes, chain of custody, audit log.
-- Original PCAP/PCAPNG bytes live on the evidence volume, never in PostgreSQL;
-- these tables hold only metadata, hashes and custody records.

CREATE TABLE evidence_artifacts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_id     TEXT NOT NULL UNIQUE CHECK (evidence_id ~ '^EV-[0-9]{8}-[0-9A-F]{12}$'),
    job_id          UUID NOT NULL REFERENCES capture_jobs(id) ON DELETE RESTRICT,
    kind            TEXT NOT NULL CHECK (kind IN ('pcap', 'pcapng', 'export', 'report')),
    original_filename TEXT,
    storage_path    TEXT NOT NULL UNIQUE,         -- relative to the evidence root
    size_bytes      BIGINT NOT NULL CHECK (size_bytes >= 0),
    sha256          BYTEA NOT NULL CHECK (octet_length(sha256) = 32),
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX evidence_artifacts_job_idx    ON evidence_artifacts (job_id);
CREATE INDEX evidence_artifacts_sha256_idx ON evidence_artifacts (sha256);

-- Evidence identity is immutable: the hash, path and size of a stored artifact never change.
CREATE FUNCTION protect_evidence_artifact() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'evidence artifacts cannot be deleted'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RAISE EXCEPTION 'evidence artifacts are immutable'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;
CREATE TRIGGER evidence_artifacts_immutable BEFORE UPDATE OR DELETE ON evidence_artifacts
    FOR EACH ROW EXECUTE FUNCTION protect_evidence_artifact();

-- Every hash computation, including re-verifications, is recorded (append-only).
CREATE TABLE evidence_hashes (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    artifact_id  UUID NOT NULL REFERENCES evidence_artifacts(id) ON DELETE RESTRICT,
    algorithm    TEXT NOT NULL DEFAULT 'sha256' CHECK (algorithm = 'sha256'),
    digest       BYTEA NOT NULL CHECK (octet_length(digest) = 32),
    matches_original BOOLEAN NOT NULL,
    computed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    computed_by  UUID REFERENCES users(id)
);
CREATE INDEX evidence_hashes_artifact_idx ON evidence_hashes (artifact_id, computed_at DESC);
CREATE TRIGGER evidence_hashes_append_only BEFORE UPDATE OR DELETE ON evidence_hashes
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

CREATE TABLE chain_of_custody (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    artifact_id  UUID NOT NULL REFERENCES evidence_artifacts(id) ON DELETE RESTRICT,
    action       custody_action NOT NULL,
    actor_id     UUID REFERENCES users(id),
    actor_label  TEXT NOT NULL,                  -- username snapshot, survives user deletion
    ip_address   INET,
    detail       JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object'),
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX chain_of_custody_artifact_idx ON chain_of_custody (artifact_id, occurred_at);
CREATE TRIGGER chain_of_custody_append_only BEFORE UPDATE OR DELETE ON chain_of_custody
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

CREATE TABLE audit_logs (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_label  TEXT,
    action       TEXT NOT NULL CHECK (char_length(action) BETWEEN 1 AND 100),
    resource_type TEXT,
    resource_id  TEXT,
    outcome      TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    ip_address   INET,
    request_id   TEXT,
    detail       JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object')
);
CREATE INDEX audit_logs_time_idx     ON audit_logs (occurred_at DESC);
CREATE INDEX audit_logs_actor_idx    ON audit_logs (actor_id, occurred_at DESC);
CREATE INDEX audit_logs_action_idx   ON audit_logs (action);
CREATE INDEX audit_logs_resource_idx ON audit_logs (resource_type, resource_id);
-- Updates are forbidden outright. Deletes are also blocked here; retention pruning
-- must be done by a privileged maintenance procedure that disables this trigger explicitly.
CREATE TRIGGER audit_logs_append_only BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
