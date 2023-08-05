-- Change `user_id` from INT to BLOB.
CREATE TABLE tmp_users (
    user_id BLOB PRIMARY KEY,
    available_slots INT NOT NULL,
    subscription_start INT NOT NULL,
    subscription_expiry INT NOT NULL
);
INSERT INTO tmp_users SELECT * FROM users;
-- We couldn't drop `users` before copying `appointments`, as the former will cascade delete the latter.
-- Same for `trackers` and `appointments`.
-- DROP TABLE users;

-- Change `UUID` & `locator` & `user_id` from INT to BLOB.
-- Change `user_signature` from BLOB to TEXT.
CREATE TABLE tmp_appointments (
    UUID BLOB PRIMARY KEY,
    locator BLOB NOT NULL,
    encrypted_blob BLOB NOT NULL,
    to_self_delay INT NOT NULL,
    user_signature TEXT NOT NULL,
    start_block INT NOT NULL,
    user_id BLOB NOT NULL,
    FOREIGN KEY(user_id)
        REFERENCES tmp_users(user_id)
        ON DELETE CASCADE
);
INSERT INTO tmp_appointments SELECT * FROM appointments;

-- Change `UUID` from INT to BLOB.
-- Change `confirmed` from BOOL to INT (due to https://github.com/launchbadge/sqlx/issues/2657).
CREATE TABLE tmp_trackers (
    UUID BLOB PRIMARY KEY,
    dispute_tx BLOB NOT NULL,
    penalty_tx BLOB NOT NULL,
    height INT NOT NULL,
    confirmed INT NOT NULL,
    FOREIGN KEY(UUID)
        REFERENCES tmp_appointments(UUID)
        ON DELETE CASCADE
);
INSERT INTO tmp_trackers SELECT * FROM trackers;

-- We can drop these now after all the data has been copied.
DROP TABLE users;
DROP TABLE appointments;
DROP TABLE trackers;

-- Foreign key references are automatically adjusted (tmp_* -> *).
ALTER TABLE tmp_users RENAME TO users;
ALTER TABLE tmp_appointments RENAME TO appointments;
ALTER TABLE tmp_trackers RENAME TO trackers;
