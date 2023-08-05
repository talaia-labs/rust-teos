-- Change `block_hash` from INT to BLOB.
CREATE TABLE tmp_last_known_block (
    id INT PRIMARY KEY,
    block_hash BLOB NOT NULL
);
INSERT INTO tmp_last_known_block SELECT * FROM last_known_block;
DROP TABLE last_known_block;
ALTER TABLE tmp_last_known_block RENAME TO last_known_block;

-- Change `key` from INT to TEXT.
CREATE TABLE tmp_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL
);
INSERT INTO tmp_keys SELECT * FROM keys;
DROP TABLE keys;
ALTER TABLE tmp_keys RENAME TO keys;
