CREATE TABLE authorization_codes (
    id INTEGER PRIMARY KEY,
    uid VARCHAR(64) NOT NULL UNIQUE,

    user_id BIGINT NOT NULL REFERENCES users(id),
    client_id BIGINT NOT NULL REFERENCES clients(id),
    body TEXT NOT NULL,

    expires INTEGER NOT NULL
);