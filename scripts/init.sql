-- ============================================================================
-- SITinform — PostgreSQL schema (reconciled with the application ORM models)
--
-- Mounted by compose at /docker-entrypoint-initdb.d/init.sql, so it runs
-- automatically ONCE, the first time the postgres container initialises an
-- empty data directory.
--
-- IMPORTANT: the column types here mirror app/models.py exactly so the running
-- app (which uses SQLAlchemy and, for the SQLite dev fallback, db.create_all())
-- maps cleanly onto these tables:
--   * primary keys are VARCHAR(36) holding application-generated uuid4 strings
--     (the ORM sets them in Python), NOT native UUID columns;
--   * timestamps are TIMESTAMP (naive) because the models use datetime.utcnow;
--   * binary blobs (encrypted evidence) are BYTEA.
-- Keep this file and app/models.py in lock-step.
--
-- Security baseline carried over from the original design:
--   * report content is encrypted at rest (Report.encrypted_data / Evidence);
--   * the audit_logs table is append-only, enforced by a trigger so no role
--     can rewrite history;
--   * audit entries are additionally ECDSA-signed by the application.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                     VARCHAR(36)  PRIMARY KEY,
    email                  VARCHAR(120) NOT NULL UNIQUE,
    password_hash          VARCHAR(128) NOT NULL,           -- bcrypt hash only, never plaintext
    first_name             VARCHAR(64)  NOT NULL,
    last_name              VARCHAR(64)  NOT NULL,
    role                   VARCHAR(20)  NOT NULL DEFAULT 'whistleblower',
    is_active              BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at             TIMESTAMP    NOT NULL DEFAULT now(),
    updated_at             TIMESTAMP    NOT NULL DEFAULT now(),
    failed_login_attempts  INTEGER      NOT NULL DEFAULT 0,
    locked_until           TIMESTAMP
);

-- ---------------------------------------------------------------------------
-- reports
-- submitter_hash = HMAC-SHA256(user_id, server_secret) for the anonymity link.
--
-- NOTE: user_id is retained here (links a report to its submitter) to keep the
-- working whistleblower dashboard, notifications and ownership checks. This is
-- a known deviation from the stricter "hash-only / no user_id" anonymity design
-- and is tracked as a follow-up to harden later.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id               VARCHAR(36)  PRIMARY KEY,
    reference_number VARCHAR(16)  NOT NULL UNIQUE,
    submitter_hash   VARCHAR(64)  NOT NULL,
    title            VARCHAR(255) NOT NULL,
    description      TEXT         NOT NULL,
    category         VARCHAR(64)  NOT NULL,
    status           VARCHAR(32)  NOT NULL DEFAULT 'Received',
    severity         VARCHAR(32)  NOT NULL DEFAULT 'medium',
    outcome          VARCHAR(64),
    outcome_details  TEXT,
    encrypted_data   TEXT,                                  -- AES-256-GCM ciphertext (base64) of the report payload
    created_at       TIMESTAMP    NOT NULL DEFAULT now(),
    updated_at       TIMESTAMP    NOT NULL DEFAULT now(),
    user_id          VARCHAR(36)  REFERENCES users (id),
    investigator_id  VARCHAR(36)  REFERENCES users (id)
);
CREATE INDEX IF NOT EXISTS idx_reports_submitter_hash  ON reports (submitter_hash);
CREATE INDEX IF NOT EXISTS idx_reports_status          ON reports (status);
CREATE INDEX IF NOT EXISTS idx_reports_user_id         ON reports (user_id);
CREATE INDEX IF NOT EXISTS idx_reports_investigator_id ON reports (investigator_id);

-- ---------------------------------------------------------------------------
-- report_status_history
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS report_status_history (
    id              VARCHAR(36) PRIMARY KEY,
    report_id       VARCHAR(36) NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    old_status      VARCHAR(32) NOT NULL,
    new_status      VARCHAR(32) NOT NULL,
    changed_by_role VARCHAR(20) NOT NULL,
    changed_at      TIMESTAMP   NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rsh_report_id ON report_status_history (report_id);

-- ---------------------------------------------------------------------------
-- evidence  (uploaded files, encrypted at rest)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS evidence (
    id                  VARCHAR(36)  PRIMARY KEY,
    report_id           VARCHAR(36)  NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    original_filename   VARCHAR(255) NOT NULL,
    stored_filename     VARCHAR(255) NOT NULL,
    file_type           VARCHAR(32)  NOT NULL,
    file_size           INTEGER      NOT NULL,
    encrypted_file_data BYTEA,                              -- AES-256-GCM ciphertext of the file bytes
    uploaded_at         TIMESTAMP    NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_evidence_report_id ON evidence (report_id);

-- ---------------------------------------------------------------------------
-- investigation_notes
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS investigation_notes (
    id              VARCHAR(36) PRIMARY KEY,
    report_id       VARCHAR(36) NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    investigator_id VARCHAR(36) NOT NULL REFERENCES users (id),
    note            TEXT        NOT NULL,
    created_at      TIMESTAMP   NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notes_report_id       ON investigation_notes (report_id);
CREATE INDEX IF NOT EXISTS idx_notes_investigator_id ON investigation_notes (investigator_id);

-- ---------------------------------------------------------------------------
-- password_reset_tokens
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id         VARCHAR(36)  PRIMARY KEY,
    user_id    VARCHAR(36)  NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token      VARCHAR(128) NOT NULL UNIQUE,
    created_at TIMESTAMP    NOT NULL DEFAULT now(),
    expires_at TIMESTAMP    NOT NULL,
    used       BOOLEAN      NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_prt_user_id ON password_reset_tokens (user_id);

-- ---------------------------------------------------------------------------
-- revoked_tokens  (logged-out / revoked JWTs)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS revoked_tokens (
    id         VARCHAR(36) PRIMARY KEY,
    token_jti  VARCHAR(36) NOT NULL UNIQUE,
    revoked_at TIMESTAMP   NOT NULL DEFAULT now(),
    reason     VARCHAR(64)
);

-- ---------------------------------------------------------------------------
-- notifications  (in-app status/assignment notices to whistleblowers)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notifications (
    id                VARCHAR(36) PRIMARY KEY,
    user_id           VARCHAR(36) NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    message           TEXT        NOT NULL,
    notification_type VARCHAR(64) NOT NULL,
    related_report_id VARCHAR(36),
    read              BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMP   NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications (user_id);

-- ---------------------------------------------------------------------------
-- audit_logs  (append-only; entries are ECDSA-signed by the application)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id             VARCHAR(36)  PRIMARY KEY,
    timestamp      TIMESTAMP    NOT NULL DEFAULT now(),
    action         VARCHAR(128) NOT NULL,
    acting_user_id VARCHAR(36),
    acting_role    VARCHAR(20)  NOT NULL,
    target_type    VARCHAR(32),
    target_id      VARCHAR(36),
    details        TEXT,
    ip_address     VARCHAR(45),
    signature      TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action    ON audit_logs (action);

-- Enforce append-only at the DB layer: block UPDATE/DELETE so no role can
-- rewrite history (supports the "audit log is append-only" requirement).
CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_append_only ON audit_logs;
CREATE TRIGGER trg_audit_append_only
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

-- ---------------------------------------------------------------------------
-- Keep updated_at current automatically on the tables that have it.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_users_updated_at   ON users;
CREATE TRIGGER trg_users_updated_at   BEFORE UPDATE ON users   FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_reports_updated_at ON reports;
CREATE TRIGGER trg_reports_updated_at BEFORE UPDATE ON reports FOR EACH ROW EXECUTE FUNCTION set_updated_at();
