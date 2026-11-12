-- Phase 2 / 0004: normalized packets and threat findings.

-- One row per dissected packet. Frame numbers reference the original PCAP so
-- every row can be traced back to evidence. Normalized columns support filtering;
-- the full TShark JSON dissection lives in `dissection` for the packet inspector.
CREATE TABLE packets (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id        UUID NOT NULL REFERENCES capture_jobs(id) ON DELETE CASCADE,
    frame_number  BIGINT NOT NULL CHECK (frame_number >= 1),
    captured_at   TIMESTAMPTZ NOT NULL,
    frame_length  INTEGER NOT NULL CHECK (frame_length >= 0),
    src_ip        INET,
    dst_ip        INET,
    ip_version    SMALLINT CHECK (ip_version IN (4, 6)),
    transport     TEXT CHECK (transport IN ('tcp', 'udp', 'icmp', 'icmpv6', 'other')),
    src_port      INTEGER CHECK (src_port BETWEEN 0 AND 65535),
    dst_port      INTEGER CHECK (dst_port BETWEEN 0 AND 65535),
    protocol_stack TEXT,                       -- e.g. eth:ethertype:ip:udp:dns
    top_protocol  TEXT,
    dns_query     TEXT,
    dns_qtype     INTEGER,
    http_method   TEXT,
    http_host     TEXT,
    http_uri      TEXT,
    tls_sni       TEXT,
    fields        JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(fields) = 'object'),   -- normalized `-T fields` output
    dissection    JSONB,                       -- `-T json` dissection (lazy-loaded by inspector)
    UNIQUE (job_id, frame_number)
);
CREATE INDEX packets_job_time_idx  ON packets (job_id, captured_at);
CREATE INDEX packets_src_ip_idx    ON packets (job_id, src_ip);
CREATE INDEX packets_dst_ip_idx    ON packets (job_id, dst_ip);
CREATE INDEX packets_dns_query_idx ON packets (job_id, dns_query) WHERE dns_query IS NOT NULL;
CREATE INDEX packets_fields_gin    ON packets USING GIN (fields jsonb_path_ops);

CREATE TABLE threat_findings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id        UUID NOT NULL REFERENCES capture_jobs(id) ON DELETE CASCADE,
    profile_id    TEXT NOT NULL REFERENCES detection_profiles(id),
    rule_id       TEXT NOT NULL,
    severity      severity NOT NULL,
    confidence    NUMERIC(4,3) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    status        finding_status NOT NULL DEFAULT 'open',
    title         TEXT NOT NULL,
    explanation   TEXT NOT NULL,
    src_ip        INET,
    dst_ip        INET,
    src_port      INTEGER CHECK (src_port BETWEEN 0 AND 65535),
    dst_port      INTEGER CHECK (dst_port BETWEEN 0 AND 65535),
    packet_frames BIGINT[] NOT NULL DEFAULT '{}',           -- frame numbers in the original PCAP
    supporting_evidence JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(supporting_evidence) = 'object'),  -- credentials MUST be redacted before insert
    detected_at   TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT findings_have_packet_refs CHECK (cardinality(packet_frames) >= 1)
);
CREATE INDEX threat_findings_job_idx      ON threat_findings (job_id, detected_at DESC);
CREATE INDEX threat_findings_severity_idx ON threat_findings (severity, detected_at DESC);
CREATE INDEX threat_findings_profile_idx  ON threat_findings (profile_id);
CREATE INDEX threat_findings_status_idx   ON threat_findings (status);
CREATE INDEX threat_findings_src_idx      ON threat_findings (src_ip);
CREATE TRIGGER threat_findings_set_updated_at BEFORE UPDATE ON threat_findings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
