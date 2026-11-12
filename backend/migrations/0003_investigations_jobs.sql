-- Phase 2 / 0003: detection profiles, investigations, capture jobs, worker sessions.

CREATE TABLE detection_profiles (
    id          TEXT PRIMARY KEY CHECK (id ~ '^[a-z][a-z0-9_]{2,63}$'),
    label       TEXT NOT NULL,
    description TEXT NOT NULL,
    thresholds  JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(thresholds) = 'object'),
    is_enabled  BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER detection_profiles_set_updated_at BEFORE UPDATE ON detection_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE investigations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title       TEXT NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    description TEXT,
    created_by  UUID NOT NULL REFERENCES users(id),
    is_closed   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at   TIMESTAMPTZ
);
CREATE INDEX investigations_created_by_idx ON investigations (created_by);
CREATE INDEX investigations_created_at_idx ON investigations (created_at DESC);
CREATE TRIGGER investigations_set_updated_at BEFORE UPDATE ON investigations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE capture_jobs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,
    created_by       UUID NOT NULL REFERENCES users(id),
    mode             job_mode NOT NULL,
    status           job_status NOT NULL DEFAULT 'queued',
    profile_id       TEXT NOT NULL REFERENCES detection_profiles(id),
    -- Stream-mode parameters. Credentials are never stored: only a reference.
    target_host      INET,
    ssh_port         INTEGER CHECK (ssh_port BETWEEN 1 AND 65535),
    ssh_username     TEXT,
    credential_ref   TEXT,
    remote_interface TEXT CHECK (remote_interface ~ '^[A-Za-z0-9_.:-]{1,32}$'),
    capture_filter   TEXT CHECK (char_length(capture_filter) <= 512),
    duration_secs    INTEGER CHECK (duration_secs BETWEEN 1 AND 86400),
    -- Upload-mode parameters.
    original_filename TEXT,
    -- Progress and outcome.
    progress_pct     SMALLINT NOT NULL DEFAULT 0 CHECK (progress_pct BETWEEN 0 AND 100),
    packet_count     BIGINT NOT NULL DEFAULT 0 CHECK (packet_count >= 0),
    bytes_captured   BIGINT NOT NULL DEFAULT 0 CHECK (bytes_captured >= 0),
    error_message    TEXT,
    workspace_path   TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ,
    CONSTRAINT stream_jobs_have_target CHECK (
        mode <> 'stream' OR (target_host IS NOT NULL AND ssh_port IS NOT NULL
                             AND ssh_username IS NOT NULL AND remote_interface IS NOT NULL
                             AND duration_secs IS NOT NULL)
    ),
    CONSTRAINT upload_jobs_have_filename CHECK (mode <> 'upload' OR original_filename IS NOT NULL)
);
CREATE INDEX capture_jobs_status_idx        ON capture_jobs (status);
CREATE INDEX capture_jobs_created_by_idx    ON capture_jobs (created_by, created_at DESC);
CREATE INDEX capture_jobs_investigation_idx ON capture_jobs (investigation_id);
CREATE TRIGGER capture_jobs_set_updated_at BEFORE UPDATE ON capture_jobs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE worker_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id          UUID NOT NULL REFERENCES capture_jobs(id) ON DELETE CASCADE,
    status          worker_status NOT NULL DEFAULT 'connecting',
    remote_host     INET NOT NULL,
    host_key_fingerprint TEXT,                -- SHA256 fingerprint verified against known_hosts
    remote_pid      INTEGER,
    cleanup_done    BOOLEAN NOT NULL DEFAULT FALSE,
    error_message   TEXT,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ
);
CREATE INDEX worker_sessions_job_idx ON worker_sessions (job_id);
CREATE INDEX worker_sessions_active_idx ON worker_sessions (status) WHERE status IN ('connecting', 'active', 'closing');
