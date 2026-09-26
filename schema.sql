-- ============================================================================
-- UEBA (User & Entity Behavior Analytics) System - PostgreSQL Schema
-- ============================================================================
-- Convention: work_days uses Python's date.weekday() convention:
--   0 = Monday, 1 = Tuesday, 2 = Wednesday, 3 = Thursday,
--   4 = Friday, 5 = Saturday, 6 = Sunday
-- Default working days: Mon-Fri => ARRAY[0,1,2,3,4]
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------------------
-- Entities being monitored: users, hosts, service accounts, etc.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS entities (
    id             SERIAL PRIMARY KEY,
    entity_type    VARCHAR(50)  NOT NULL DEFAULT 'user',   -- user, host, service_account
    name           VARCHAR(255) NOT NULL UNIQUE,
    department     VARCHAR(100),
    email          VARCHAR(255),
    metadata       JSONB        NOT NULL DEFAULT '{}'::jsonb,
    is_active      BOOLEAN      NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ----------------------------------------------------------------------------
-- Raw activity events ingested from logs (auth, file access, network, VPN...)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id                 BIGSERIAL PRIMARY KEY,
    entity_id          INTEGER      NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    event_type         VARCHAR(50)  NOT NULL,                 -- login, logout, file_access, data_transfer, vpn_connect...
    event_time         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    status             VARCHAR(20)  NOT NULL DEFAULT 'success', -- success, fail
    source_ip          INET,
    geo_country        VARCHAR(100),
    geo_city           VARCHAR(100),
    geo_lat            DOUBLE PRECISION,
    geo_lon            DOUBLE PRECISION,
    resource           VARCHAR(255),
    bytes_transferred  BIGINT       NOT NULL DEFAULT 0,
    file_count         INTEGER,                                -- number of files involved, for data_transfer/file_access events
    raw                JSONB        NOT NULL DEFAULT '{}'::jsonb,
    processed          BOOLEAN      NOT NULL DEFAULT false,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_events_entity_time ON events(entity_id, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_type_time   ON events(event_type, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_unprocessed ON events(processed) WHERE processed = false;

-- ----------------------------------------------------------------------------
-- Configuration: exactly ONE default row (entity_id IS NULL) + optional
-- per-entity override rows. All thresholds / working hours live here and are
-- adjustable at runtime via the API.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS entity_config (
    id                              SERIAL PRIMARY KEY,
    entity_id                       INTEGER UNIQUE REFERENCES entities(id) ON DELETE CASCADE, -- NULL = global default

    timezone                        VARCHAR(64)  NOT NULL DEFAULT 'Africa/Accra',
    work_start                      TIME         NOT NULL DEFAULT '09:00',
    work_end                        TIME         NOT NULL DEFAULT '18:00',
    work_days                       INTEGER[]    NOT NULL DEFAULT ARRAY[0,1,2,3,4], -- Mon-Fri
    off_hours_enabled               BOOLEAN      NOT NULL DEFAULT true,
    -- Severity is graduated by how many hours outside the work window the
    -- login is (time-of-day distance from work_start/work_end, plus a fixed
    -- penalty added for non-work days). Below off_hours_low_hours, it's not
    -- flagged as an anomaly at all.
    off_hours_low_hours             NUMERIC      NOT NULL DEFAULT 0,
    off_hours_medium_hours          NUMERIC      NOT NULL DEFAULT 2,
    off_hours_high_hours            NUMERIC      NOT NULL DEFAULT 4,
    off_hours_critical_hours        NUMERIC      NOT NULL DEFAULT 8,

    -- Severity is graduated by the number of failed logins within the
    -- window. Below failed_login_low_threshold, no anomaly is raised.
    failed_login_low_threshold      INTEGER      NOT NULL DEFAULT 5,
    failed_login_medium_threshold   INTEGER      NOT NULL DEFAULT 8,
    failed_login_high_threshold     INTEGER      NOT NULL DEFAULT 12,
    failed_login_critical_threshold INTEGER      NOT NULL DEFAULT 20,
    failed_login_enabled            BOOLEAN      NOT NULL DEFAULT true,

    -- Severity is graduated by total MB moved within the window. Below
    -- data_transfer_low_mb, no anomaly is raised.
    data_transfer_low_mb            NUMERIC      NOT NULL DEFAULT 200,
    data_transfer_medium_mb         NUMERIC      NOT NULL DEFAULT 500,
    data_transfer_high_mb           NUMERIC      NOT NULL DEFAULT 1000,
    data_transfer_critical_mb       NUMERIC      NOT NULL DEFAULT 2000,
    data_transfer_window_minutes    INTEGER      NOT NULL DEFAULT 60,
    data_transfer_enabled           BOOLEAN      NOT NULL DEFAULT true,

    -- Blocks known social media domains via the hosts file on the
    -- employee's machine, but only while it's currently within this
    -- entity's configured work_start/work_end/work_days/timezone (the
    -- same fields off-hours detection already uses). Enforcement itself
    -- happens client-side (social_media_blocker.py); this flag and the
    -- work-hours fields are what /social-media-block-status computes
    -- "should this machine be blocking right now?" from.
    social_media_block_enabled      BOOLEAN      NOT NULL DEFAULT false,

    updated_at                      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by                      VARCHAR(100)
);

-- Seed the single global default configuration row.
INSERT INTO entity_config (entity_id)
SELECT NULL
WHERE NOT EXISTS (SELECT 1 FROM entity_config WHERE entity_id IS NULL);

-- ----------------------------------------------------------------------------
-- Rolling per-entity per-metric baseline statistics (Welford's online
-- algorithm) used for statistical (z-score) anomaly detection.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS entity_baselines (
    id             SERIAL PRIMARY KEY,
    entity_id      INTEGER      NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    metric_name    VARCHAR(100) NOT NULL,
    sample_count   INTEGER      NOT NULL DEFAULT 0,
    mean_value     NUMERIC      NOT NULL DEFAULT 0,
    m2             NUMERIC      NOT NULL DEFAULT 0, -- sum of squared differences from the mean
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE(entity_id, metric_name)
);

-- ----------------------------------------------------------------------------
-- Detected anomalies
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS anomalies (
    id             BIGSERIAL PRIMARY KEY,
    entity_id      INTEGER      NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    event_id       BIGINT       REFERENCES events(id) ON DELETE SET NULL,
    rule_name      VARCHAR(100) NOT NULL,
    severity       VARCHAR(20)  NOT NULL DEFAULT 'medium', -- low, medium, high, critical
    score          NUMERIC      NOT NULL DEFAULT 0,
    description    TEXT,
    details        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    status         VARCHAR(20)  NOT NULL DEFAULT 'open',   -- open, acknowledged, resolved, false_positive
    detected_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    resolved_at    TIMESTAMPTZ,
    resolved_by    VARCHAR(100)
);
CREATE INDEX IF NOT EXISTS idx_anomalies_entity  ON anomalies(entity_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomalies_status  ON anomalies(status);
CREATE INDEX IF NOT EXISTS idx_anomalies_rule    ON anomalies(rule_name, entity_id, detected_at DESC);

-- ----------------------------------------------------------------------------
-- Audit trail for every configuration change (who changed what, and when)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS config_audit_log (
    id           BIGSERIAL PRIMARY KEY,
    entity_id    INTEGER,       -- NULL means it was the global default
    changed_by   VARCHAR(100),
    field_name   VARCHAR(100)  NOT NULL,
    old_value    TEXT,
    new_value    TEXT,
    changed_at   TIMESTAMPTZ   NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON config_audit_log(entity_id, changed_at DESC);

-- ----------------------------------------------------------------------------
-- Admin login (dashboard authentication)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_users (
    id             SERIAL PRIMARY KEY,
    username       VARCHAR(100) NOT NULL UNIQUE,
    email          VARCHAR(255) UNIQUE,   -- required for self-service sign-up; nullable for CLI-created accounts
    password_hash  VARCHAR(128) NOT NULL,  -- hex-encoded PBKDF2-HMAC-SHA256 digest
    salt           VARCHAR(64)  NOT NULL,  -- hex-encoded random salt
    role           VARCHAR(20)  NOT NULL DEFAULT 'analyst', -- admin, analyst, employee
    entity_id      INTEGER REFERENCES entities(id) ON DELETE SET NULL, -- required for 'employee': which monitored entity they may view
    is_approved    BOOLEAN      NOT NULL DEFAULT true, -- self-registered analysts start false, pending admin approval
    must_change_password BOOLEAN NOT NULL DEFAULT false, -- true after a default-password reset; forces a password change on next login
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    token          VARCHAR(128) PRIMARY KEY,
    username       VARCHAR(100) NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ  NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON admin_sessions(expires_at);

-- ----------------------------------------------------------------------------
-- Entity aliases: lets a name that Windows sometimes reports differently for
-- the same physical machine/person (e.g. a Microsoft account email vs. the
-- local username) resolve to one canonical entity instead of silently
-- creating a duplicate. Populated automatically when two entities are merged.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS entity_aliases (
    id           SERIAL PRIMARY KEY,
    alias        VARCHAR(255) NOT NULL UNIQUE,
    entity_id    INTEGER      NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ----------------------------------------------------------------------------
-- Records exactly what moved during each entity merge, so it can be
-- reversed precisely later (which specific events/anomalies/logins were
-- reattributed, not just "everything currently on the kept entity").
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS entity_merges (
    id                       SERIAL PRIMARY KEY,
    kept_entity_id           INTEGER      NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    duplicate_entity_name    VARCHAR(255) NOT NULL,
    duplicate_entity_type    VARCHAR(50)  NOT NULL DEFAULT 'user',
    merged_event_ids         BIGINT[]     NOT NULL DEFAULT '{}',
    merged_anomaly_ids       BIGINT[]     NOT NULL DEFAULT '{}',
    affected_admin_user_ids  INTEGER[]    NOT NULL DEFAULT '{}',
    alias_created            VARCHAR(255),
    merged_by                VARCHAR(100),
    merged_at                TIMESTAMPTZ  NOT NULL DEFAULT now(),
    unmerged_at              TIMESTAMPTZ  -- NULL while still merged; set once reversed
);
CREATE INDEX IF NOT EXISTS idx_entity_merges_active ON entity_merges(kept_entity_id) WHERE unmerged_at IS NULL;
