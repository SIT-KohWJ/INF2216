-- ============================================================================
-- SITinform — PostgreSQL schema
-- Mounted by compose.yaml at /docker-entrypoint-initdb.d/init.sql, so it runs
-- automatically ONCE, the first time the postgres container initialises an
-- empty data directory.
-- ============================================================================

-- gen_random_uuid() is built into PostgreSQL 13+ (this project targets 16),
-- so no extension is required.

-- ---------------------------------------------------------------------------
-- Enumerated types — must be created BEFORE the tables that reference them.
-- ---------------------------------------------------------------------------
CREATE TYPE user_role              AS ENUM ('whistleblower', 'investigator', 'admin', 'system_admin');
CREATE TYPE report_status          AS ENUM ('received', 'triaged', 'investigating', 'resolved');
CREATE TYPE scan_status            AS ENUM ('pending', 'clean', 'infected');
CREATE TYPE recommendation_outcome AS ENUM ('action_taken', 'dismissed', 'referred', 'insufficient_evidence');

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               VARCHAR(255) NOT NULL UNIQUE,
    password_hash       TEXT         NOT NULL,                 -- bcrypt hash only, never plaintext
    role                user_role    NOT NULL DEFAULT 'whistleblower',
    is_active           BOOLEAN      NOT NULL DEFAULT TRUE,
    login_attempt_count INT          NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- reports
-- submitter_hash = HMAC-SHA256(user_id, server_secret). It is DELIBERATELY not
-- a foreign key to users — that irreversibility is the anonymity guarantee.
-- ---------------------------------------------------------------------------
CREATE TABLE reports (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_id             UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),  -- used in URLs; prevents enumeration
    submitter_hash        CHAR(64)      NOT NULL,            -- 64 hex chars = SHA-256 digest
    title_encrypted       BYTEA         NOT NULL,            -- AES-256-GCM ciphertext
    description_encrypted BYTEA         NOT NULL,
    category              VARCHAR(100)  NOT NULL,
    status                report_status NOT NULL DEFAULT 'received',
    created_at            TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT now()
);
CREATE INDEX idx_reports_submitter_hash ON reports (submitter_hash);
CREATE INDEX idx_reports_status         ON reports (status);

-- ---------------------------------------------------------------------------
-- report_status_history
-- ---------------------------------------------------------------------------
CREATE TABLE report_status_history (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id  UUID          NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    actor_role user_role     NOT NULL,
    old_status report_status,
    new_status report_status NOT NULL,
    changed_at TIMESTAMPTZ   NOT NULL DEFAULT now()
);
CREATE INDEX idx_rsh_report_id ON report_status_history (report_id);

-- ---------------------------------------------------------------------------
-- evidence
-- ---------------------------------------------------------------------------
CREATE TABLE evidence (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id          UUID         NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    filename_encrypted BYTEA        NOT NULL,
    file_hash          CHAR(64)     NOT NULL,
    mime_type          VARCHAR(100) NOT NULL,
    scan_status        scan_status  NOT NULL DEFAULT 'pending',
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_evidence_report_id ON evidence (report_id);

-- ---------------------------------------------------------------------------
-- investigation_notes
-- ---------------------------------------------------------------------------
CREATE TABLE investigation_notes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id       UUID NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    investigator_id UUID NOT NULL REFERENCES users (id),
    notes_encrypted BYTEA,
    recommendation  recommendation_outcome,
    assigned_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_notes_report_id       ON investigation_notes (report_id);
CREATE INDEX idx_notes_investigator_id ON investigation_notes (investigator_id);

-- ---------------------------------------------------------------------------
-- password_reset_tokens
-- ---------------------------------------------------------------------------
CREATE TABLE password_reset_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash CHAR(64)    NOT NULL UNIQUE,             -- store the hash of the token, never the token
    expires_at TIMESTAMPTZ NOT NULL,
    used       BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_prt_user_id ON password_reset_tokens (user_id);

-- ---------------------------------------------------------------------------
-- token_blocklist  (revoked / logged-out JWTs)
-- ---------------------------------------------------------------------------
CREATE TABLE token_blocklist (
    jti        VARCHAR(64) PRIMARY KEY,                 -- JWT "jti" claim
    token_hash CHAR(64)    NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_blocklist_expires_at ON token_blocklist (expires_at);

-- ---------------------------------------------------------------------------
-- audit_log  (append-only)
-- report_id is nullable: many events (logins, account changes) aren't tied to
-- a report. NEVER store report content or anything that re-identifies a
-- submitter here.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type      VARCHAR(100) NOT NULL,
    report_id       UUID REFERENCES reports (id) ON DELETE SET NULL,
    actor_role      VARCHAR(50),
    target_entity   VARCHAR(100),
    ip_address_hash CHAR(64),
    details         JSONB,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now()    -- renamed from "timestamp" to avoid a reserved word
);
CREATE INDEX idx_audit_occurred_at ON audit_log (occurred_at);
CREATE INDEX idx_audit_event_type  ON audit_log (event_type);

-- Enforce append-only at the DB layer: block UPDATE/DELETE so no role can
-- rewrite history (supports the "audit log is append-only" requirement).
CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

-- ---------------------------------------------------------------------------
-- Keep updated_at current automatically.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at   BEFORE UPDATE ON users               FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_reports_updated_at BEFORE UPDATE ON reports             FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_notes_updated_at   BEFORE UPDATE ON investigation_notes FOR EACH ROW EXECUTE FUNCTION set_updated_at();
