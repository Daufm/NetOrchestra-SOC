-- Phase 2 / 0001: enum types and shared helper functions.
-- gen_random_uuid() is built into PostgreSQL 13+, so no extension is required.

CREATE TYPE job_mode      AS ENUM ('upload', 'stream');
CREATE TYPE job_status    AS ENUM ('queued', 'running', 'stopping', 'completed', 'failed', 'cancelled');
CREATE TYPE severity      AS ENUM ('info', 'low', 'medium', 'high', 'critical');
CREATE TYPE finding_status AS ENUM ('open', 'triaged', 'false_positive', 'confirmed');
CREATE TYPE custody_action AS ENUM ('ingested', 'analyzed', 'accessed', 'exported', 'verified', 'verification_failed');
CREATE TYPE worker_status AS ENUM ('connecting', 'active', 'closing', 'closed', 'failed');

-- Keeps updated_at current on mutable tables.
CREATE FUNCTION set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

-- Blocks UPDATE and DELETE on append-only tables (audit log, chain of custody, hashes).
CREATE FUNCTION forbid_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% on % is not permitted: table is append-only', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;
