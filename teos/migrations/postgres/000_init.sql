-- INT is 4 bytes signed integer (i32) in PostgreSQL.
-- Many fields in here map to (u32)s in Rust, which has double the capacity of (i32)s on the positive side.
-- Some database calls might break because of this.
-- A solution for this could be either one of:
--   1- Find a one to one mapping between the Rust (u32)s and PostgreSQL's (i32)s since they are essentially the same size.
--   2- Use PostgreSQL's BIGINT which is equivalent to an i64.

CREATE TABLE IF NOT EXISTS users (
    user_id BYTEA PRIMARY KEY,
    available_slots BIGINT NOT NULL,
    subscription_start BIGINT NOT NULL,
    subscription_expiry BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS appointments (
    UUID BYTEA PRIMARY KEY,
    locator BYTEA NOT NULL,
    encrypted_blob BYTEA NOT NULL,
    to_self_delay BIGINT NOT NULL,
    user_signature TEXT NOT NULL,
    start_block BIGINT NOT NULL,
    user_id BYTEA NOT NULL,
    FOREIGN KEY(user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS trackers (
    UUID BYTEA PRIMARY KEY,
    dispute_tx BYTEA NOT NULL,
    penalty_tx BYTEA NOT NULL,
    height BIGINT NOT NULL,
    confirmed BIGINT NOT NULL,
    FOREIGN KEY(UUID)
        REFERENCES appointments(UUID)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS last_known_block (
    id INT PRIMARY KEY,
    block_hash BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
    id SERIAL PRIMARY KEY,
    secret_key TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS locators_index ON appointments (
    locator
);
