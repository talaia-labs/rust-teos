CREATE TABLE IF NOT EXISTS users (
    user_id INT PRIMARY KEY,
    available_slots INT NOT NULL,
    subscription_start INT NOT NULL,
    subscription_expiry INT NOT NULL
);

CREATE TABLE IF NOT EXISTS appointments (
    UUID INT PRIMARY KEY,
    locator INT NOT NULL,
    encrypted_blob BLOB NOT NULL,
    to_self_delay INT NOT NULL,
    user_signature BLOB NOT NULL,
    start_block INT NOT NULL,
    user_id INT NOT NULL,
    FOREIGN KEY(user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS trackers (
    UUID INT PRIMARY KEY,
    dispute_tx BLOB NOT NULL,
    penalty_tx BLOB NOT NULL,
    height INT NOT NULL,
    confirmed BOOL NOT NULL,
    FOREIGN KEY(UUID)
        REFERENCES appointments(UUID)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS last_known_block (
    id INT PRIMARY KEY,
    block_hash INT NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key INT NOT NULL
);
