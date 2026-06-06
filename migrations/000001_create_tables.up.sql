CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS scans (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at TIMESTAMPTZ DEFAULT now(),
    ended_at   TIMESTAMPTZ,
    status     TEXT,
    config     JSONB
);

CREATE TABLE IF NOT EXISTS targets (
    id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type    TEXT NOT NULL,
    value   TEXT NOT NULL,
    org     TEXT,
    tags    TEXT[]
);

CREATE TABLE IF NOT EXISTS findings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_name   TEXT NOT NULL,
    target_id     UUID REFERENCES targets(id) ON DELETE CASCADE,
    severity      TEXT NOT NULL,
    title         TEXT NOT NULL,
    description   TEXT,
    evidence      JSONB,
    false_pos_prob FLOAT DEFAULT 0.0,
    confirmed     BOOLEAN DEFAULT NULL,
    created_at    TIMESTAMPTZ DEFAULT now(),
    scan_id       UUID REFERENCES scans(id) ON DELETE CASCADE
);
