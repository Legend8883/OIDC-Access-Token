-- Users table
CREATE TABLE IF NOT EXISTS users (
    id                BIGSERIAL PRIMARY KEY,
    username          VARCHAR(255) NOT NULL UNIQUE,
    password          VARCHAR(255),
    email             VARCHAR(255),
    provider          VARCHAR(50)  NOT NULL DEFAULT 'LOCAL',
    provider_id       VARCHAR(255)
);

-- OAuth2 authorized clients — tokens stored as TEXT, NOT bytea
-- This avoids the \x hex-prefix problem with bytea columns.
CREATE TABLE IF NOT EXISTS oauth2_authorized_client (
    client_registration_id  VARCHAR(100) NOT NULL,
    principal_name           VARCHAR(200) NOT NULL,
    access_token_type        VARCHAR(100) NOT NULL,
    access_token_value       TEXT         NOT NULL,
    access_token_issued_at   TIMESTAMP    NOT NULL,
    access_token_expires_at  TIMESTAMP    NOT NULL,
    access_token_scopes      VARCHAR(1000),
    refresh_token_value      TEXT,
    refresh_token_issued_at  TIMESTAMP,
    created_at               TIMESTAMP    DEFAULT NOW(),
    PRIMARY KEY (client_registration_id, principal_name)
);
