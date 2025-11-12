-- Canonical schema for Spammy storage backends.
-- Ensure database/cluster uses UTF-8 (PostgreSQL UTF8, MariaDB utf8mb4, MSSQL UTF-8 collation).

CREATE TABLE messages (
    id BIGSERIAL PRIMARY KEY,
    message_uuid VARCHAR(64) NOT NULL UNIQUE,
    subject TEXT,
    sender TEXT,
    recipient TEXT,
    mailbox TEXT,
    category VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE analyses (
    id BIGSERIAL PRIMARY KEY,
    message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    origin_ip INET,
    rdap_network TEXT,
    severity VARCHAR(32),
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE abuse_contacts (
    id BIGSERIAL PRIMARY KEY,
    message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    role VARCHAR(32),
    confidence NUMERIC(4,2)
);

CREATE INDEX idx_analyses_message_id ON analyses(message_id);
CREATE INDEX idx_abuse_contacts_message_id ON abuse_contacts(message_id);
CREATE INDEX idx_messages_category_created ON messages(category, created_at DESC);
