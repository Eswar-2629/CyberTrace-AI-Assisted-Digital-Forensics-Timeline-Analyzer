CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(30) NOT NULL CHECK (role IN ('ADMIN', 'ANALYST', 'VIEWER')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cases (
    id BIGSERIAL PRIMARY KEY,
    case_number VARCHAR(100) NOT NULL UNIQUE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(30) NOT NULL DEFAULT 'OPEN'
        CHECK (status IN ('OPEN', 'CLOSED', 'ARCHIVED')),
    created_by BIGINT NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS evidence_files (
    id BIGSERIAL PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    original_name VARCHAR(255) NOT NULL,
    evidence_type VARCHAR(50) NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    size_bytes BIGINT NOT NULL,
    encrypted_payload BYTEA NOT NULL,
    uploaded_by BIGINT NOT NULL REFERENCES users(id),
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_file_id BIGINT REFERENCES evidence_files(id) ON DELETE SET NULL,
    event_time TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    source VARCHAR(100),
    host VARCHAR(255),
    username VARCHAR(255),
    source_ip INET,
    destination_ip INET,
    file_path TEXT,
    registry_path TEXT,
    message TEXT NOT NULL,
    normalized_text TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    classification VARCHAR(100),
    anomaly_score DOUBLE PRECISION,
    is_anomaly BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS timeline_relationships (
    id BIGSERIAL PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    from_event_id BIGINT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    to_event_id BIGINT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    relationship_type VARCHAR(100) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    UNIQUE(from_event_id, to_event_id, relationship_type)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(100),
    ip_address INET,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cases_status
    ON cases(status);

CREATE INDEX IF NOT EXISTS idx_events_case_time
    ON events(case_id, event_time);

CREATE INDEX IF NOT EXISTS idx_events_anomaly
    ON events(case_id, is_anomaly);

CREATE INDEX IF NOT EXISTS idx_events_type
    ON events(case_id, event_type);

CREATE INDEX IF NOT EXISTS idx_relationships_case
    ON timeline_relationships(case_id);

CREATE INDEX IF NOT EXISTS idx_audit_created
    ON audit_logs(created_at);
    