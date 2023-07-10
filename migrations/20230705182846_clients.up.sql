CREATE TABLE clients (
    id BIGINT NOT NULL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    client_name VARCHAR(32) NOT NULL,
    app_type VARCHAR(16) NOT NULL DEFAULT 'web',
    client_uri VARCHAR(256),
    logo_uri VARCHAR(256) NOT NULL,
    registration_token CHAR(32) NOT NULL,

    client_secret CHAR(32) UNIQUE
);

CREATE TABLE client_redirect_uris (
    client_id BIGINT REFERENCES clients(id),
    redirect_uri VARCHAR(256) NOT NULL
);

CREATE TABLE client_contacts (
    client_id BIGINT REFERENCES clients(id),
    email VARCHAR(64) NOT NULL
);